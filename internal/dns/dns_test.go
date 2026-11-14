package dns

import (
	"net"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/albreis/poison-stop/internal/config"
	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

type fixedIdent string

func (f fixedIdent) Identify(string) string { return string(f) }

type memRec struct {
	mu sync.Mutex
	ev []store.DNSEvent
}

func (m *memRec) RecordDNS(e store.DNSEvent) { m.mu.Lock(); m.ev = append(m.ev, e); m.mu.Unlock() }

// fakeUpstream responde 192.0.2.1 para qualquer A.
func fakeUpstream(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		rr, _ := mdns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func startResolver(t *testing.T, mode string, allow []string) (string, *memRec) {
	cfg := config.Default()
	cfg.Services["app"] = config.ServiceConfig{Mode: mode, Allow: allow}
	rec := &memRec{}
	s := New(policy.New(cfg), fixedIdent("app"), rec, fakeUpstream(t))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: s}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	time.Sleep(50 * time.Millisecond)
	return pc.LocalAddr().String(), rec
}

func query(t *testing.T, addr, name string) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	r, _, err := (&mdns.Client{Timeout: 2 * time.Second}).Exchange(m, addr)
	if err != nil {
		t.Fatalf("consulta %s: %v", name, err)
	}
	return r
}

func TestEnforce(t *testing.T) {
	addr, rec := startResolver(t, "enforce", []string{"api.stripe.com:443"})
	if r := query(t, addr, "api.stripe.com"); r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("stripe deveria resolver: %v", r)
	}
	if r := query(t, addr, "a8f3k2b9.evil.com"); r.Rcode != mdns.RcodeNameError {
		t.Errorf("evil.com deveria dar NXDOMAIN, veio %s", mdns.RcodeToString[r.Rcode])
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.ev) != 2 || rec.ev[0].Denied || !rec.ev[1].Denied {
		t.Errorf("eventos errados: %+v", rec.ev)
	}
}

func TestLearnResolvesAll(t *testing.T) {
	addr, _ := startResolver(t, "learn", nil)
	if r := query(t, addr, "qualquer.exemplo.com"); r.Rcode != mdns.RcodeSuccess {
		t.Errorf("learn deveria resolver tudo, veio %s", mdns.RcodeToString[r.Rcode])
	}
}
