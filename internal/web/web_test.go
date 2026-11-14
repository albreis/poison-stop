package web

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albreis/poison-stop/internal/config"
	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

type env struct {
	st  *store.Store
	pol *policy.Engine
	srv *httptest.Server
	c   *http.Client
}

func setup(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := EnsureAdmin(ctx, st, "admin", "senha-forte"); err != nil {
		t.Fatal(err)
	}
	pol := policy.New(config.Default())
	ws, err := New(st, pol, []string{"10.89.0.0/24"}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ws.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &env{st: st, pol: pol, srv: srv, c: &http.Client{Jar: jar}}
}

func (e *env) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := e.c.Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) post(t *testing.T, path string, form url.Values) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func waitBody(t *testing.T, e *env, path, want string) string {
	t.Helper()
	var body string
	for i := 0; i < 60; i++ {
		_, body = e.get(t, path)
		if strings.Contains(body, want) {
			return body
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s não mostrou %q", path, want)
	return body
}

func TestLoginRequired(t *testing.T) {
	e := setup(t)
	_, body := e.get(t, "/")
	if !strings.Contains(body, `name="password"`) {
		t.Fatal("sem login deveria cair na tela de login")
	}
	if code := e.post(t, "/login", url.Values{"username": {"admin"}, "password": {"errada"}}); code != 200 {
		t.Fatalf("login errado: %d", code)
	}
	if _, body = e.get(t, "/"); !strings.Contains(body, `name="password"`) {
		t.Fatal("senha errada não pode entrar")
	}
	e.post(t, "/login", url.Values{"username": {"admin"}, "password": {"senha-forte"}})
	if _, body = e.get(t, "/"); !strings.Contains(body, "Visão geral") {
		t.Fatal("login certo deveria mostrar a visão geral")
	}
}

func TestSuggestApproveAndBlocks(t *testing.T) {
	e := setup(t)
	e.st.Record(store.Event{Service: "app", ClientIP: "10.89.0.130", Host: "api.github.com", Port: 443, Proto: "https"})
	e.st.Record(store.Event{Service: "app", ClientIP: "10.89.0.130", Host: "abc.webhook.site", Port: 443, Proto: "https"})
	e.st.Record(store.Event{Service: "app", ClientIP: "10.89.0.130", Host: "evil.com", Port: 443, Proto: "https", Blocked: true})
	e.post(t, "/login", url.Values{"username": {"admin"}, "password": {"senha-forte"}})

	body := waitBody(t, e, "/service/app", "api.github.com:443")
	if !strings.Contains(body, `value="api.github.com:443" checked`) {
		t.Error("github deveria vir marcado na sugestão")
	}
	if strings.Contains(body, `value="abc.webhook.site:443" checked`) {
		t.Error("webhook.site não deveria vir marcado")
	}

	if code := e.post(t, "/service/app/allow", url.Values{"rule": {"api.github.com:443"}}); code != 200 {
		t.Fatalf("aprovar: %d", code)
	}
	e.post(t, "/service/app/mode", url.Values{"mode": {"enforce"}})
	if d := e.pol.Decide("app", "api.github.com", 443); !d.Allowed || d.Mode != "enforce" {
		t.Errorf("regra aprovada deveria valer na hora: %+v", d)
	}
	if d := e.pol.Decide("app", "abc.webhook.site", 443); d.Allowed {
		t.Errorf("fora da lista deveria bloquear: %+v", d)
	}

	if _, body = e.get(t, "/blocks"); !strings.Contains(body, "liberar evil.com:443") {
		t.Error("bloqueios deveria listar evil.com com botão de liberar")
	}
	e.post(t, "/service/app/allow", url.Values{"rule": {"evil.com:443"}, "from": {"blocks"}})
	if !e.pol.Decide("app", "evil.com", 443).Allowed {
		t.Error("liberar pelo painel deveria valer na hora")
	}
	if code := e.post(t, "/service/app/allow", url.Values{"new": {"bad rule/x"}}); code != http.StatusBadRequest {
		t.Errorf("regra inválida deveria dar 400, veio %d", code)
	}

	// export / import
	_, y := e.get(t, "/whitelist.yaml")
	if !strings.Contains(y, "api.github.com:443") || !strings.Contains(y, "enforce") {
		t.Errorf("export sem as regras: %s", y)
	}
	e.post(t, "/whitelist/import", url.Values{"yaml": {"services:\n  app:\n    mode: monitor\n    allow: [api.stripe.com:443]\n"}})
	if e.pol.ModeOf("app") != "monitor" || e.pol.Decide("app", "api.github.com", 443).Listed {
		t.Error("import deveria substituir as regras")
	}
	rules, _ := e.st.LoadRules(context.Background())
	if len(rules["app"].Allow) != 1 {
		t.Errorf("import deveria persistir no banco: %+v", rules)
	}
}

func TestCrossOriginPostRefused(t *testing.T) {
	e := setup(t)
	e.post(t, "/login", url.Values{"username": {"admin"}, "password": {"senha-forte"}})
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/service/app/mode", strings.NewReader("mode=learn"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://atacante.example")
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST de outra origem deveria dar 403, veio %d", resp.StatusCode)
	}
}

func TestDenyAppsNetwork(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "d.db"))
	defer st.Close()
	ws, _ := New(st, policy.New(config.Default()), []string{"10.89.0.0/24"}, 0)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "10.89.0.7:4444"
	ws.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("acesso da rede apps deveria ser recusado, veio %d", rr.Code)
	}
}

func TestServiceNameWithSlash(t *testing.T) {
	e := setup(t)
	e.st.Record(store.Event{Service: "meuchefe/worker", ClientIP: "172.19.0.7", Host: "api.deepseek.com", Port: 443, Proto: "tls"})
	e.post(t, "/login", url.Values{"username": {"admin"}, "password": {"senha-forte"}})
	body := waitBody(t, e, "/", "meuchefe/worker")
	if !strings.Contains(body, `href="/service/meuchefe%2fworker"`) && !strings.Contains(body, `href="/service/meuchefe%2Fworker"`) {
		t.Fatalf("link do serviço com barra errado")
	}
	if _, b := e.get(t, "/service/meuchefe%2Fworker"); !strings.Contains(b, "api.deepseek.com:443") {
		t.Fatal("página do serviço com barra não abriu")
	}
	e.post(t, "/service/meuchefe%2Fworker/allow", url.Values{"rule": {"api.deepseek.com:443"}})
	if !e.pol.Decide("meuchefe/worker", "api.deepseek.com", 443).Listed {
		t.Error("aprovar regra em serviço com barra não funcionou")
	}
}
