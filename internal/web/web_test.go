package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albreis/poison-stop/internal/config"
	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

func TestPanel(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Record(store.Event{Service: "app", ClientIP: "172.30.0.5", Host: "api.github.com", Port: 443, Proto: "https"})
	st.Record(store.Event{Service: "app", ClientIP: "172.30.0.5", Host: "abc.webhook.site", Port: 443, Proto: "https"})

	srv, err := New(st, policy.New(config.Default()), []string{"172.30.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	var body string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.65.1:5555"
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("painel: %d", rr.Code)
		}
		body = rr.Body.String()
		if strings.Contains(body, "api.github.com") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, want := range []string{"api.github.com:443", "abc.webhook.site:443", "serviço de paste/upload/túnel", "learn"} {
		if !strings.Contains(body, want) {
			t.Errorf("painel não mostra %q", want)
		}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.30.0.7:4444"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("acesso da rede apps deveria ser recusado, veio %d", rr.Code)
	}
}
