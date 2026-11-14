package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albreis/poison-stop/internal/config"
	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

type memChannel struct {
	mu  sync.Mutex
	got []Alert
}

func (*memChannel) Name() string { return "mem" }
func (m *memChannel) Send(_ context.Context, a Alert) error {
	m.mu.Lock()
	m.got = append(m.got, a)
	m.mu.Unlock()
	return nil
}
func (m *memChannel) kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var k []string
	for _, a := range m.got {
		k = append(k, a.Kind+":"+a.Host)
	}
	return k
}

func TestDebounce(t *testing.T) {
	ch := &memChannel{}
	n := NewWithChannels(time.Minute, ch)
	clock := time.Unix(1_800_000_000, 0)
	n.now = func() time.Time { return clock }
	for i := 0; i < 5; i++ {
		n.Notify(Alert{Kind: KindBlocked, Service: "app", Host: "evil.com"})
	}
	n.Notify(Alert{Kind: KindBlocked, Service: "app", Host: "outro.com"})
	clock = clock.Add(2 * time.Minute)
	n.Notify(Alert{Kind: KindBlocked, Service: "app", Host: "evil.com"})
	n.Close()
	if len(ch.got) != 3 {
		t.Fatalf("esperava 3 alertas, veio %d: %v", len(ch.got), ch.kinds())
	}
	if ch.got[2].Suppressed != 4 {
		t.Errorf("o terceiro alerta deveria contar 4 agrupados, veio %d", ch.got[2].Suppressed)
	}
}

func TestWebhookSigned(t *testing.T) {
	var body []byte
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		sig = r.Header.Get("X-PoisonStop-Signature")
	}))
	defer srv.Close()
	wh := &Webhook{URL: srv.URL, Secret: "segredo"}
	if err := wh.Send(context.Background(), Alert{Kind: KindBlocked, Service: "app", Host: "evil.com", Port: 443, Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, []byte("segredo"))
	m.Write(body)
	if sig != "sha256="+hex.EncodeToString(m.Sum(nil)) {
		t.Errorf("assinatura errada: %s", sig)
	}
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if p["event"] != "blocked" || p["service"] != "app" || !strings.Contains(p["text"].(string), "evil.com:443") {
		t.Errorf("payload inesperado: %s", body)
	}
}

func TestTelegram(t *testing.T) {
	var path string
	var p map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&p)
	}))
	defer srv.Close()
	tg := &Telegram{Token: "123:abc", ChatID: "42", BaseURL: srv.URL}
	if err := tg.Send(context.Background(), Alert{Kind: KindDNSDenied, Service: "worker", Host: "x.evil.com", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123:abc/sendMessage" || p["chat_id"] != "42" || !strings.Contains(p["text"].(string), "x.evil.com") {
		t.Errorf("chamada errada: %s %v", path, p)
	}
}

func TestWatcher(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	cfg.Services["mon"] = config.ServiceConfig{Mode: "monitor", Allow: []string{"ok.com:443"}}
	pol := policy.New(cfg)
	ch := &memChannel{}
	n := NewWithChannels(time.Minute, ch)
	w, err := NewWatcher(context.Background(), st, n, pol, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	w.now = func() time.Time { return clock }

	// learn, dentro do período: nada
	w.Record(store.Event{Service: "app", Host: "a.com", Port: 443, Mode: "learn"})
	// learn, depois do período: destino novo alerta, repetido não
	clock = clock.Add(2 * time.Hour)
	w.Record(store.Event{Service: "app", Host: "a.com", Port: 443, Mode: "learn"})
	w.Record(store.Event{Service: "app", Host: "b.com", Port: 443, Mode: "learn"})
	// monitor: fora da lista alerta, na lista não
	w.Record(store.Event{Service: "mon", Host: "ok.com", Port: 443, Mode: "monitor"})
	w.Record(store.Event{Service: "mon", Host: "fora.com", Port: 443, Mode: "monitor"})
	// bloqueio e DNS negado
	w.Record(store.Event{Service: "app", Host: "evil.com", Port: 443, Mode: "enforce", Blocked: true})
	w.RecordDNS(store.DNSEvent{Service: "app", Name: "tunel.evil.com", QType: "A", Denied: true})
	n.Close()

	got := strings.Join(ch.kinds(), ",")
	want := "new_host:b.com,off_list:fora.com,blocked:evil.com,dns_denied:tunel.evil.com"
	if got != want {
		t.Errorf("alertas:\n got %s\nwant %s", got, want)
	}
}
