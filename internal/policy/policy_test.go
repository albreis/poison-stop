package policy

import (
	"testing"

	"github.com/albreis/poison-stop/internal/config"
)

func TestListed(t *testing.T) {
	allow := []string{"api.stripe.com:443", "maps.googleapis.com", "*.s3.sa-east-1.amazonaws.com:443", "vault.interno:8200"}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"api.stripe.com", 443, true},
		{"API.Stripe.com.", 443, true},
		{"api.stripe.com", 80, false},
		{"maps.googleapis.com", 443, true},
		{"storage.googleapis.com", 443, false},
		{"meu-bucket.s3.sa-east-1.amazonaws.com", 443, true},
		{"s3.sa-east-1.amazonaws.com", 443, false},
		{"vault.interno", 8200, true},
		{"evil.com", 443, false},
	}
	for _, c := range cases {
		if got := Listed(allow, c.host, c.port); got != c.want {
			t.Errorf("Listed(%s:%d) = %v, quer %v", c.host, c.port, got, c.want)
		}
	}
}

func TestDecide(t *testing.T) {
	cfg := config.Default()
	cfg.Services["app"] = config.ServiceConfig{Mode: "enforce", Allow: []string{"api.stripe.com:443"}}
	cfg.Services["worker"] = config.ServiceConfig{Mode: "monitor", Allow: []string{"api.telegram.org:443"}}
	e := New(cfg)

	if d := e.Decide("app", "api.stripe.com", 443); !d.Allowed || !d.Listed {
		t.Errorf("app -> stripe deveria passar: %+v", d)
	}
	if d := e.Decide("app", "evil.com", 443); d.Allowed {
		t.Errorf("app -> evil.com deveria ser bloqueado: %+v", d)
	}
	if d := e.Decide("app", "1.2.3.4", 443); d.Allowed || d.Reason != "IP direto sem nome" {
		t.Errorf("app -> IP deveria ser bloqueado como IP: %+v", d)
	}
	if d := e.Decide("worker", "evil.com", 443); !d.Allowed || d.Listed {
		t.Errorf("worker em monitor deveria passar mas fora da lista: %+v", d)
	}
	if d := e.Decide("desconhecido", "evil.com", 443); !d.Allowed || d.Mode != "learn" {
		t.Errorf("serviço sem regra usa default_mode learn: %+v", d)
	}
}

func TestDecideName(t *testing.T) {
	cfg := config.Default()
	cfg.Services["app"] = config.ServiceConfig{Mode: "enforce", Allow: []string{"api.stripe.com:443", "*.s3.amazonaws.com:443", "vault.interno:8200"}}
	e := New(cfg)
	for name, want := range map[string]bool{
		"api.stripe.com":          true,
		"API.STRIPE.COM.":         true,
		"vault.interno":           true,
		"bucket.s3.amazonaws.com": true,
		"s3.amazonaws.com":        false,
		"a8f3k2.evil.com":         false,
	} {
		if got := e.DecideName("app", name).Allowed; got != want {
			t.Errorf("DecideName(app, %s) = %v, quer %v", name, got, want)
		}
	}
	if !e.DecideName("outro", "qualquer.com").Allowed {
		t.Error("serviço em learn deveria resolver tudo")
	}
}

func TestSuspicious(t *testing.T) {
	if len(Suspicious("api.stripe.com")) != 0 {
		t.Error("stripe não é suspeito")
	}
	if len(Suspicious("abc.webhook.site")) == 0 {
		t.Error("webhook.site é suspeito")
	}
	if len(Suspicious("203.0.113.9")) == 0 {
		t.Error("IP direto é suspeito")
	}
}
