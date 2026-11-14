// Package dns é o resolver filtrado do PoisonStop.
//
// Ele atende na rede "apps", registra todas as consultas (inclusive as
// negadas) e, para serviços em enforce, só resolve nomes que aparecem na
// whitelist; o resto recebe NXDOMAIN. Como a rede é internal, os serviços não
// conseguem usar outro DNS (ex.: 8.8.8.8), o que fecha o caminho do DNS
// tunneling.
package dns

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

// Identifier mapeia IP de origem -> serviço.
type Identifier interface {
	Identify(ip string) string
}

// Recorder recebe as consultas.
type Recorder interface {
	RecordDNS(store.DNSEvent)
}

// Server é o resolver.
type Server struct {
	Policy   *policy.Engine
	Ident    Identifier
	Rec      Recorder
	Upstream string // host:porta do resolver de verdade
	udp, tcp *mdns.Client
}

// New cria o resolver. upstream vazio usa o primeiro nameserver de
// /etc/resolv.conf (no Docker, o DNS embutido 127.0.0.11).
func New(p *policy.Engine, id Identifier, rec Recorder, upstream string) *Server {
	if upstream == "" {
		upstream = SystemResolver("/etc/resolv.conf")
	}
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		upstream = net.JoinHostPort(upstream, "53")
	}
	return &Server{
		Policy: p, Ident: id, Rec: rec, Upstream: upstream,
		udp: &mdns.Client{Net: "udp", Timeout: 4 * time.Second},
		tcp: &mdns.Client{Net: "tcp", Timeout: 4 * time.Second},
	}
}

// SystemResolver lê o primeiro nameserver do resolv.conf.
func SystemResolver(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "127.0.0.11:53"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return net.JoinHostPort(fields[1], "53")
		}
	}
	return "127.0.0.11:53"
}

func remoteIP(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

// ServeDNS implementa mdns.Handler.
func (s *Server) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	if len(r.Question) != 1 || r.Opcode != mdns.OpcodeQuery {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	ip := remoteIP(w.RemoteAddr())
	svc := s.Ident.Identify(ip)
	d := s.Policy.DecideName(svc, name)
	ev := store.DNSEvent{Time: time.Now(), Service: svc, ClientIP: ip, Name: name, QType: mdns.TypeToString[q.Qtype], Denied: !d.Allowed}
	s.Rec.RecordDNS(ev)

	if !d.Allowed {
		slog.Info("DNS negado", "service", svc, "name", name, "type", ev.QType)
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeNameError)
		m.RecursionAvailable = true
		_ = w.WriteMsg(m)
		return
	}

	resp, err := s.forward(r, w.LocalAddr().Network())
	if err != nil {
		slog.Warn("DNS upstream", "name", name, "err", err)
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	resp.Id = r.Id
	_ = w.WriteMsg(resp)
}

func (s *Server) forward(r *mdns.Msg, network string) (*mdns.Msg, error) {
	c := s.udp
	if network == "tcp" {
		c = s.tcp
	}
	resp, _, err := c.Exchange(r, s.Upstream)
	if err == nil && resp.Truncated && c == s.udp {
		resp, _, err = s.tcp.Exchange(r, s.Upstream)
	}
	return resp, err
}

// ListenAndServe sobe o resolver em UDP e TCP até o contexto acabar.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	errc := make(chan error, 2)
	servers := []*mdns.Server{
		{Addr: addr, Net: "udp", Handler: s},
		{Addr: addr, Net: "tcp", Handler: s, ReadTimeout: 5 * time.Second},
	}
	for _, srv := range servers {
		go func() { errc <- srv.ListenAndServe() }()
	}
	select {
	case <-ctx.Done():
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
		return nil
	case err := <-errc:
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
		return err
	}
}
