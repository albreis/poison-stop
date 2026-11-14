// Package policy decide se uma conexão passa, conforme o modo e a whitelist
// de cada serviço.
package policy

import (
	"net"
	"strconv"
	"strings"

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

// Engine avalia conexões contra a configuração.
type Engine struct {
	cfg *config.Config
}

// New cria um Engine.
func New(cfg *config.Config) *Engine { return &Engine{cfg: cfg} }

// ModeOf devolve o modo efetivo de um serviço.
func (e *Engine) ModeOf(service string) string {
	if s, ok := e.cfg.Services[service]; ok && s.Mode != "" {
		return s.Mode
	}
	return e.cfg.DefaultMode
}

// Decide avalia service -> host:port.
func (e *Engine) Decide(service, host string, port int) Decision {
	mode := e.ModeOf(service)
	listed := Listed(e.cfg.Services[service].Allow, host, port)
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
