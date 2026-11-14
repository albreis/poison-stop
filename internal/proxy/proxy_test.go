package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/albreis/poison-stop/internal/config"
	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

type fixedIdent string

func (f fixedIdent) Identify(string) string { return string(f) }

type memRec struct {
	mu sync.Mutex
	ev []store.Event
}

func (m *memRec) Record(e store.Event) { m.mu.Lock(); m.ev = append(m.ev, e); m.mu.Unlock() }
func (m *memRec) all() []store.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.Event(nil), m.ev...)
}

func newProxy(t *testing.T, cfg *config.Config) (*httptest.Server, *memRec) {
	rec := &memRec{}
	p := New(policy.New(cfg), fixedIdent("app"), rec)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv, rec
}

func clientVia(proxyURL string) *http.Client {
	u, _ := url.Parse(proxyURL)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func TestLearnHTTPAndHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ola") }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "seguro") }))
	defer secure.Close()

	px, rec := newProxy(t, config.Default())
	c := clientVia(px.URL)

	for _, u := range []string{plain.URL, secure.URL} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || len(b) == 0 {
			t.Fatalf("GET %s: %d %q", u, resp.StatusCode, b)
		}
	}
	c.CloseIdleConnections() // encerra o túnel CONNECT para o evento ser gravado

	waitFor(t, func() bool { return len(rec.all()) >= 2 })
	evs := rec.all()
	var sawHTTP, sawHTTPS bool
	for _, e := range evs {
		if e.Blocked {
			t.Errorf("learn não deveria bloquear: %+v", e)
		}
		switch e.Proto {
		case "http":
			sawHTTP = e.BytesIn > 0
		case "https":
			sawHTTPS = e.BytesIn > 0 && e.BytesOut > 0
		}
	}
	if !sawHTTP || !sawHTTPS {
		t.Errorf("esperava eventos http e https com bytes: %+v", evs)
	}
}

func TestEnforceBlocks(t *testing.T) {
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer secure.Close()
	cfg := config.Default()
	cfg.Services["app"] = config.ServiceConfig{Mode: "enforce", Allow: []string{"api.stripe.com:443"}}
	px, rec := newProxy(t, cfg)

	_, err := clientVia(px.URL).Get(secure.URL)
	if err == nil {
		t.Fatal("esperava erro: CONNECT deveria ser recusado")
	}
	resp, err := clientVia(px.URL).Get("http://exemplo.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("HTTP bloqueado deveria dar 403, veio %d", resp.StatusCode)
	}
	waitFor(t, func() bool { return len(rec.all()) >= 2 })
	for _, e := range rec.all() {
		if !e.Blocked {
			t.Errorf("evento deveria estar bloqueado: %+v", e)
		}
	}
}

func TestPeekClientHello(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: "api.stripe.com", InsecureSkipVerify: true}).Handshake()
	}()
	sni, isTLS, consumed := PeekClientHello(b)
	a.Close()
	if !isTLS || sni != "api.stripe.com" || len(consumed) == 0 {
		t.Errorf("sni=%q tls=%v consumidos=%d", sni, isTLS, len(consumed))
	}
}

func TestTransparentTLS(t *testing.T) {
	cfg := config.Default()
	cfg.Services["app"] = config.ServiceConfig{Mode: "enforce", Allow: []string{"api.stripe.com:443"}}
	rec := &memRec{}
	p := New(policy.New(cfg), fixedIdent("app"), rec)

	// SNI fora da lista: recusado e registrado como bloqueio
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { p.ServeTransparentTLS(b); close(done) }()
	go func() { _ = tls.Client(a, &tls.Config{ServerName: "evil.com", InsecureSkipVerify: true}).Handshake() }()
	<-done
	a.Close()

	// conexão vazia (checagem de saúde): não registra nada
	c, d := net.Pipe()
	c.Close()
	p.ServeTransparentTLS(d)

	evs := rec.all()
	if len(evs) != 1 || evs[0].Host != "evil.com" || !evs[0].Blocked || evs[0].Proto != "tls" {
		t.Errorf("eventos inesperados: %+v", evs)
	}
}
