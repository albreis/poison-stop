// Package netfilter instala no host as regras de iptables do modo
// transparente: o tráfego TCP 80/443 que sai das redes Docker escolhidas é
// desviado (DNAT) para o PoisonStop, sem precisar mexer nas stacks.
//
// Roda num container à parte, com network_mode: host e NET_ADMIN, e:
//   - só desvia destinos públicos (redes privadas, como outros containers, o
//     banco ou o host, seguem direto);
//   - preserva o IP de origem até o PoisonStop (sem MASQUERADE), para ele
//     saber qual container falou;
//   - libera, na chain DOCKER-USER, a passagem entre a rede do serviço e a
//     rede do PoisonStop;
//   - falha aberta: se o PoisonStop não responder, tira o desvio (as stacks
//     voltam a sair direto) e põe de volta quando ele voltar;
//   - remove tudo ao parar.
package netfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"
)

// Nomes das chains criadas pelo PoisonStop.
const (
	ChainPre  = "POISONSTOP-PRE"  // nat PREROUTING: DNAT
	ChainPost = "POISONSTOP-POST" // nat POSTROUTING: sem MASQUERADE até o PoisonStop
	ChainFwd  = "POISONSTOP-FWD"  // filter DOCKER-USER: libera a passagem
)

// Faixas que nunca são desviadas (tráfego interno).
var privateRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4",
}

// Config do sidecar.
type Config struct {
	Target     string   // IP do PoisonStop alcançável pelo host
	HTTPPort   int      // listener HTTP transparente
	TLSPort    int      // listener TLS transparente
	Networks   []string // nomes das redes Docker, ou "*" para todas
	Exclude    []string // redes que nunca são desviadas
	DockerHost string   // docker-socket-proxy (GET /networks)
	Iptables   string   // binário; vazio detecta (iptables-nft ou iptables-legacy)
	Interval   time.Duration
}

// Network é uma rede Docker do tipo bridge.
type Network struct {
	Name   string
	Bridge string
	Subnet string
}

// Rule é uma regra: tabela, chain e argumentos.
type Rule struct {
	Table, Chain string
	Args         []string
}

// Rules calcula as regras para as redes dadas.
func Rules(nets []Network, target string, httpPort, tlsPort int) []Rule {
	var r []Rule
	for _, p := range privateRanges {
		r = append(r, Rule{"nat", ChainPre, []string{"-d", p, "-j", "RETURN"}})
	}
	for _, n := range nets {
		r = append(r,
			Rule{"nat", ChainPre, []string{"-i", n.Bridge, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", target, httpPort)}},
			Rule{"nat", ChainPre, []string{"-i", n.Bridge, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", target, tlsPort)}},
			Rule{"nat", ChainPost, []string{"-s", n.Subnet, "-d", target, "-j", "ACCEPT"}},
			Rule{"filter", ChainFwd, []string{"-i", n.Bridge, "-d", target, "-p", "tcp", "-m", "multiport", "--dports", fmt.Sprintf("%d,%d", httpPort, tlsPort), "-j", "ACCEPT"}},
			Rule{"filter", ChainFwd, []string{"-o", n.Bridge, "-s", target, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		)
	}
	return r
}

// jumps liga as chains do PoisonStop às chains do sistema.
var jumps = []Rule{
	{"nat", "PREROUTING", []string{"-j", ChainPre}},
	{"nat", "POSTROUTING", []string{"-j", ChainPost}},
	{"filter", "DOCKER-USER", []string{"-j", ChainFwd}},
}

// Runner executa o iptables (trocável nos testes).
type Runner func(args ...string) error

func execRunner(bin string) Runner {
	return func(args ...string) error {
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// DetectIptables escolhe o iptables que o Docker do host está usando.
func DetectIptables() string {
	for _, bin := range []string{"iptables-nft", "iptables-legacy", "iptables"} {
		out, err := exec.Command(bin, "-t", "nat", "-S", "POSTROUTING").CombinedOutput()
		if err == nil && strings.Contains(string(out), "MASQUERADE") {
			return bin
		}
	}
	return "iptables"
}

// Manager aplica e remove as regras.
type Manager struct {
	run     Runner
	applied string // assinatura do que está aplicado
}

// NewManager cria o Manager com um Runner.
func NewManager(run Runner) *Manager { return &Manager{run: run} }

func (m *Manager) ensureChains() error {
	for _, c := range []Rule{{"nat", ChainPre, nil}, {"nat", ChainPost, nil}, {"filter", ChainFwd, nil}} {
		if m.run("-t", c.Table, "-L", c.Chain, "-n") != nil {
			if err := m.run("-t", c.Table, "-N", c.Chain); err != nil {
				return err
			}
		}
	}
	for _, j := range jumps {
		check := append([]string{"-t", j.Table, "-C", j.Chain}, j.Args...)
		if m.run(check...) != nil {
			ins := append([]string{"-t", j.Table, "-I", j.Chain, "1"}, j.Args...)
			if err := m.run(ins...); err != nil {
				return err
			}
		}
	}
	return nil
}

// Apply deixa as chains exatamente com estas regras (só mexe se mudou).
func (m *Manager) Apply(rules []Rule) error {
	sig := signature(rules)
	if sig == m.applied {
		return nil
	}
	if err := m.ensureChains(); err != nil {
		return err
	}
	for _, c := range []Rule{{"nat", ChainPre, nil}, {"nat", ChainPost, nil}, {"filter", ChainFwd, nil}} {
		if err := m.run("-t", c.Table, "-F", c.Chain); err != nil {
			return err
		}
	}
	for _, r := range rules {
		args := append([]string{"-t", r.Table, "-A", r.Chain}, r.Args...)
		if err := m.run(args...); err != nil {
			m.applied = ""
			return err
		}
	}
	m.applied = sig
	return nil
}

// Cleanup remove as ligações e as chains do PoisonStop.
func (m *Manager) Cleanup() {
	for _, j := range jumps {
		for m.run(append([]string{"-t", j.Table, "-D", j.Chain}, j.Args...)...) == nil {
		}
	}
	for _, c := range []Rule{{"nat", ChainPre, nil}, {"nat", ChainPost, nil}, {"filter", ChainFwd, nil}} {
		_ = m.run("-t", c.Table, "-F", c.Chain)
		_ = m.run("-t", c.Table, "-X", c.Chain)
	}
	m.applied = ""
}

func signature(rules []Rule) string {
	var b strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&b, "%s|%s|%s\n", r.Table, r.Chain, strings.Join(r.Args, " "))
	}
	return b.String()
}

type dockerNetwork struct {
	ID       string            `json:"Id"`
	Name     string            `json:"Name"`
	Driver   string            `json:"Driver"`
	Internal bool              `json:"Internal"`
	Options  map[string]string `json:"Options"`
	IPAM     struct {
		Config []struct {
			Subnet string `json:"Subnet"`
		} `json:"Config"`
	} `json:"IPAM"`
}

// FetchNetworks lista as redes bridge pela API do Docker.
func FetchNetworks(ctx context.Context, dockerHost string) ([]dockerNetwork, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(dockerHost, "/")+"/networks", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker respondeu %s", resp.Status)
	}
	var ns []dockerNetwork
	return ns, json.NewDecoder(resp.Body).Decode(&ns)
}

// Select escolhe as redes a desviar.
func Select(all []dockerNetwork, want, exclude []string, target string) []Network {
	tip := net.ParseIP(target)
	var out []Network
	for _, n := range all {
		if n.Driver != "bridge" || n.Internal || slices.Contains(exclude, n.Name) {
			continue
		}
		if !slices.Contains(want, "*") && !slices.Contains(want, n.Name) {
			continue
		}
		var subnet string
		for _, c := range n.IPAM.Config {
			if _, ipn, err := net.ParseCIDR(c.Subnet); err == nil && ipn.IP.To4() != nil {
				if tip != nil && ipn.Contains(tip) {
					subnet = "" // é a rede do próprio PoisonStop
					break
				}
				subnet = c.Subnet
			}
		}
		if subnet == "" {
			continue
		}
		br := n.Options["com.docker.network.bridge.name"]
		if br == "" {
			if len(n.ID) < 12 {
				continue
			}
			br = "br-" + n.ID[:12]
		}
		out = append(out, Network{Name: n.Name, Bridge: br, Subnet: subnet})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func healthy(target string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(target, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Run mantém as regras sincronizadas até o contexto acabar.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Iptables == "" {
		cfg.Iptables = DetectIptables()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 10 * time.Second
	}
	m := NewManager(execRunner(cfg.Iptables))
	defer func() {
		m.Cleanup()
		slog.Info("regras do modo transparente removidas")
	}()
	slog.Info("modo transparente", "iptables", cfg.Iptables, "target", cfg.Target, "networks", cfg.Networks, "exclude", cfg.Exclude)

	var lastNames string
	wasHealthy := true
	tick := time.NewTicker(cfg.Interval)
	defer tick.Stop()
	for {
		nets := []Network{}
		all, err := FetchNetworks(ctx, cfg.DockerHost)
		if err != nil {
			slog.Warn("listando redes do Docker", "err", err)
		} else {
			nets = Select(all, cfg.Networks, cfg.Exclude, cfg.Target)
		}
		ok := healthy(cfg.Target, cfg.TLSPort)
		// Sem o PoisonStop no ar, ou sem saber as redes, não desvia nada.
		var rules []Rule
		if ok && err == nil {
			rules = Rules(nets, cfg.Target, cfg.HTTPPort, cfg.TLSPort)
		}
		if !ok && wasHealthy {
			slog.Warn("PoisonStop não responde: desvio desligado (falha aberta)")
		}
		if ok && !wasHealthy {
			slog.Info("PoisonStop voltou: desvio religado")
		}
		wasHealthy = ok
		if err := m.Apply(rules); err != nil {
			slog.Error("aplicando regras", "err", err)
		}
		var names []string
		for _, n := range nets {
			names = append(names, n.Name+"("+n.Bridge+")")
		}
		if s := strings.Join(names, ","); s != lastNames && ok {
			slog.Info("redes desviadas para o PoisonStop", "networks", s)
			lastNames = s
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
