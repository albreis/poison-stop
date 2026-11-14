// Package policy decide se uma conexão passa, conforme o modo e a whitelist
// de cada serviço.
package policy

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/albreis/poison-stop/internal/config"
)

// Modos de operação.
const (
	Learn   = "learn"
	Monitor = "monitor"
	Enforce = "enforce"
)

// Decision é o resultado da avaliação de uma conexão.
type Decision struct {
	Mode    string // modo efetivo do serviço
	Listed  bool   // destino está na whitelist
	Allowed bool   // conexão deve passar
	Reason  string
}

// Engine avalia conexões contra as regras. As regras podem ser trocadas a
// quente (painel) com SetRules.
type Engine struct {
	defaultMode string
	rules       atomic.Pointer[map[string]config.ServiceConfig]
}

// New cria um Engine com as regras do arquivo.
func New(cfg *config.Config) *Engine {
	e := &Engine{defaultMode: cfg.DefaultMode}
	e.SetRules(cfg.Services)
	return e
}

// SetRules troca as regras de todos os serviços.
func (e *Engine) SetRules(r map[string]config.ServiceConfig) {
	cp := make(map[string]config.ServiceConfig, len(r))
	for k, v := range r {
		cp[k] = config.ServiceConfig{Mode: v.Mode, Allow: append([]string(nil), v.Allow...)}
	}
	e.rules.Store(&cp)
}

// Rules devolve uma cópia das regras atuais.
func (e *Engine) Rules() map[string]config.ServiceConfig {
	r := *e.rules.Load()
	cp := make(map[string]config.ServiceConfig, len(r))
	for k, v := range r {
		cp[k] = config.ServiceConfig{Mode: v.Mode, Allow: append([]string(nil), v.Allow...)}
	}
	return cp
}

// DefaultMode é o modo de quem não tem regra.
func (e *Engine) DefaultMode() string { return e.defaultMode }

func (e *Engine) rule(service string) config.ServiceConfig {
	return (*e.rules.Load())[service]
}

// ModeOf devolve o modo efetivo de um serviço.
func (e *Engine) ModeOf(service string) string {
	if s := e.rule(service); s.Mode != "" {
		return s.Mode
	}
	return e.defaultMode
}

// Decide avalia service -> host:port.
func (e *Engine) Decide(service, host string, port int) Decision {
	mode := e.ModeOf(service)
	listed := Listed(e.rule(service).Allow, host, port)
	d := Decision{Mode: mode, Listed: listed, Allowed: true}
	switch {
	case mode == Learn:
		d.Reason = "learn"
	case listed:
		d.Reason = "na whitelist"
	case mode == Monitor:
		d.Reason = "fora da whitelist (monitor)"
	default:
		d.Allowed = false
		d.Reason = "fora da whitelist"
		if IsIP(host) {
			d.Reason = "IP direto sem nome"
		}
	}
	return d
}

// DecideName avalia uma consulta DNS: em enforce só resolve nomes que
// aparecem em alguma regra da whitelist (qualquer porta).
func (e *Engine) DecideName(service, name string) Decision {
	mode := e.ModeOf(service)
	listed := NameListed(e.rule(service).Allow, name)
	d := Decision{Mode: mode, Listed: listed, Allowed: true}
	switch {
	case mode == Learn:
		d.Reason = "learn"
	case listed:
		d.Reason = "na whitelist"
	case mode == Monitor:
		d.Reason = "fora da whitelist (monitor)"
	default:
		d.Allowed = false
		d.Reason = "fora da whitelist"
	}
	return d
}

// NameListed diz se o nome bate com o host de alguma regra, ignorando a porta.
func NameListed(allow []string, name string) bool {
	name = normalize(name)
	for _, rule := range allow {
		rh, _ := splitRule(rule)
		if strings.HasPrefix(rh, "*.") {
			if strings.HasSuffix(name, rh[1:]) && len(name) > len(rh)-1 {
				return true
			}
			continue
		}
		if rh == name {
			return true
		}
	}
	return false
}

// Listed diz se host:port bate com alguma regra da lista.
//
// Regras: "host:porta", "host" (porta 443) ou "*.dominio:porta".
// Wildcard só casa subdomínios ("*.x.com" não casa "x.com").
func Listed(allow []string, host string, port int) bool {
	host = normalize(host)
	for _, rule := range allow {
		rh, rp := splitRule(rule)
		if rp != port {
			continue
		}
		if strings.HasPrefix(rh, "*.") {
			if strings.HasSuffix(host, rh[1:]) && len(host) > len(rh)-1 {
				return true
			}
			continue
		}
		if rh == host {
			return true
		}
	}
	return false
}

func splitRule(rule string) (string, int) {
	rule = strings.TrimSpace(rule)
	h, p, err := net.SplitHostPort(rule)
	if err != nil {
		return normalize(rule), 443
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return normalize(h), -1
	}
	return normalize(h), n
}

func normalize(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// ValidRule confere o formato de uma regra de whitelist.
func ValidRule(rule string) bool {
	rule = strings.TrimSpace(rule)
	if rule == "" || strings.ContainsAny(rule, " /\\\t\"'<>") {
		return false
	}
	h, p := splitRule(rule)
	if p <= 0 || p > 65535 || h == "" || h == "*." {
		return false
	}
	if strings.Contains(h[1:], "*") || (strings.HasPrefix(h, "*") && !strings.HasPrefix(h, "*.")) {
		return false
	}
	return true
}

// IsIP diz se o host é um IP literal.
func IsIP(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

// destinos usados para exfiltrar dados: paste, upload, túneis, coletores.
var suspiciousSuffixes = []string{
	"pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co",
	"transfer.sh", "file.io", "0x0.st", "temp.sh", "gofile.io", "anonfiles.com",
	"webhook.site", "requestbin.com", "pipedream.net", "beeceptor.com", "requestcatcher.com",
	"ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net",
	"interact.sh", "oast.fun", "oast.pro", "burpcollaborator.net",
}

// Suspicious devolve os motivos para destacar um host na sugestão de
// whitelist (lista vazia se nada chamar atenção).
func Suspicious(host string) []string {
	host = normalize(host)
	var r []string
	if IsIP(host) {
		r = append(r, "IP direto, sem nome")
	}
	if strings.HasPrefix(host, "*.") {
		r = append(r, "wildcard: libera qualquer subdomínio")
	}
	for _, s := range suspiciousSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			r = append(r, "serviço de paste/upload/túnel")
			break
		}
	}
	return r
}
