// Package web serve o painel do PoisonStop.
//
// O painel exige login (bcrypt + cookie de sessão) e recusa acessos vindos
// das redes listadas em panel.deny_cidrs (a rede dos serviços monitorados).
// As regras (modo e whitelist de cada serviço) ficam no SQLite e são
// editadas aqui; o poisonstop.yml só semeia as regras na primeira subida.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/albreis/poison-stop/internal/config"
	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

const sessionCookie = "ps_session"
const sessionTTL = 12 * time.Hour

// Server é o painel.
type Server struct {
	Store       *store.Store
	Policy      *policy.Engine
	Deny        []*net.IPNet
	LearnPeriod time.Duration
	pages       map[string]*template.Template
}

// New cria o painel.
func New(st *store.Store, pol *policy.Engine, denyCIDRs []string, learn time.Duration) (*Server, error) {
	s := &Server{Store: st, Policy: pol, LearnPeriod: learn, pages: map[string]*template.Template{}}
	for _, c := range denyCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		s.Deny = append(s.Deny, n)
	}
	funcs := template.FuncMap{
		"bytes": humanBytes,
		"ago":   ago,
		"when":  func(t time.Time) string { return t.Local().Format("02/01 15:04") },
		"hour":  func(t time.Time) string { return t.Local().Format("15h") },
		"pct": func(v, max int64) int64 {
			if max == 0 {
				return 0
			}
			return v * 100 / max
		},
		"path": url.PathEscape,
	}
	for _, page := range []string{"login.html", "index.html", "service.html", "blocks.html", "whitelist.html"} {
		t, err := template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/layout.html", "templates/"+page)
		if err != nil {
			return nil, err
		}
		s.pages[page] = t
	}
	return s, nil
}

// Handler devolve as rotas do painel.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)

	auth := http.NewServeMux()
	auth.HandleFunc("POST /logout", s.logout)
	auth.HandleFunc("GET /{$}", s.index)
	auth.HandleFunc("GET /service/{name}", s.service)
	auth.HandleFunc("POST /service/{name}/mode", s.setMode)
	auth.HandleFunc("POST /service/{name}/allow", s.addAllow)
	auth.HandleFunc("POST /service/{name}/remove", s.removeAllow)
	auth.HandleFunc("POST /service/{name}/forget", s.forget)
	auth.HandleFunc("GET /blocks", s.blocks)
	auth.HandleFunc("GET /whitelist", s.whitelist)
	auth.HandleFunc("GET /whitelist.yaml", s.exportYAML)
	auth.HandleFunc("POST /whitelist/import", s.importYAML)
	auth.HandleFunc("GET /api/destinations", s.apiDestinations)
	mux.Handle("/", s.requireAuth(auth))

	return s.guard(securityHeaders(sameOrigin(mux)))
}

// --- middlewares ---

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range s.Deny {
				if n.Contains(ip) {
					slog.Warn("acesso ao painel vindo da rede dos serviços recusado", "ip", host)
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// sameOrigin recusa POST de outra origem (CSRF), além do SameSite=Strict.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			src := r.Header.Get("Origin")
			if src == "" || src == "null" {
				src = r.Header.Get("Referer")
			}
			if src != "" {
				u, err := url.Parse(src)
				if err != nil || u.Host != r.Host {
					http.Error(w, "origem inválida", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err == nil {
			if u, err := s.Store.SessionUser(r.Context(), c.Value); err == nil && u != "" {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
				return
			}
		}
		if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "login necessário", http.StatusUnauthorized)
	})
}

func userOf(r *http.Request) string {
	u, _ := r.Context().Value(ctxKey{}).(string)
	return u
}

// --- render ---

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["User"] = userOf(r)
	data["Path"] = r.URL.Path
	data["Flash"] = r.URL.Query().Get("ok")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages[page].ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("template", "page", page, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	slog.Error("painel", "err", err)
	http.Error(w, "erro interno", http.StatusInternalServerError)
}

func back(w http.ResponseWriter, r *http.Request, to, msg string) {
	if msg != "" {
		to += "?ok=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// reload aplica no proxy/DNS as regras gravadas no banco.
func (s *Server) reload(ctx context.Context) error {
	rules, err := s.Store.LoadRules(ctx)
	if err != nil {
		return err
	}
	s.Policy.SetRules(rules)
	return nil
}

// --- login ---

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login.html", map[string]any{"Error": r.URL.Query().Get("erro") != ""})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.FormValue("username"))
	if !CheckPassword(r.Context(), s.Store, user, r.FormValue("password")) {
		slog.Warn("login falhou", "user", user, "ip", r.RemoteAddr)
		time.Sleep(700 * time.Millisecond) // freia tentativa e erro
		http.Redirect(w, r, "/login?erro=1", http.StatusSeeOther)
		return
	}
	tok, err := s.Store.NewSession(r.Context(), user, sessionTTL)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int(sessionTTL.Seconds()),
	})
	slog.Info("login", "user", user)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.Store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- visão geral ---

type serviceRow struct {
	store.Service
	Short      string // nome sem o prefixo "stack/"
	Mode       string
	Blocked24h int64
	Allowed    int
	LearnLeft  string
}

type stackGroup struct {
	Name       string // "" = sem stack
	Rows       []serviceRow
	Hits       int64
	Blocked24h int64
	Modes      map[string]int
}

// groupByStack agrupa os serviços pelo projeto do Compose. Stacks em ordem
// alfabética; serviços sem stack conhecida ficam por último.
func groupByStack(rows []serviceRow) []stackGroup {
	idx := map[string]int{}
	var groups []stackGroup
	for _, r := range rows {
		i, ok := idx[r.Stack]
		if !ok {
			i = len(groups)
			idx[r.Stack] = i
			groups = append(groups, stackGroup{Name: r.Stack, Modes: map[string]int{}})
		}
		g := &groups[i]
		g.Rows = append(g.Rows, r)
		g.Hits += r.Hits
		g.Blocked24h += r.Blocked24h
		g.Modes[r.Mode]++
	}
	sort.SliceStable(groups, func(a, b int) bool {
		if (groups[a].Name == "") != (groups[b].Name == "") {
			return groups[b].Name == ""
		}
		return groups[a].Name < groups[b].Name
	})
	return groups
}

func (s *Server) learnLeft(svc store.Service, mode string) string {
	if mode != policy.Learn || s.LearnPeriod <= 0 {
		return ""
	}
	left := time.Until(svc.FirstSeen.Add(s.LearnPeriod))
	if left <= 0 {
		return "aprendizado concluído: revise a whitelist sugerida"
	}
	if left > 48*time.Hour {
		return fmt.Sprintf("aprendendo, faltam %d dias", int(left.Hours()/24))
	}
	return fmt.Sprintf("aprendendo, faltam %dh", int(left.Hours())+1)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	svcs, err := s.Store.Services(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	blocked, err := s.Store.BlockedSince(r.Context(), time.Now().Add(-24*time.Hour))
	if err != nil {
		s.fail(w, err)
		return
	}
	rules := s.Policy.Rules()
	rows := make([]serviceRow, 0, len(svcs))
	var total int64
	for _, sv := range svcs {
		mode := s.Policy.ModeOf(sv.Name)
		short := strings.TrimPrefix(sv.Name, sv.Stack+"/")
		if sv.Stack == "" {
			short = sv.Name
		}
		rows = append(rows, serviceRow{Service: sv, Short: short, Mode: mode, Blocked24h: blocked[sv.Name],
			Allowed: len(rules[sv.Name].Allow), LearnLeft: s.learnLeft(sv, mode)})
		total += blocked[sv.Name]
	}
	s.render(w, r, "index.html", map[string]any{"Services": rows, "Groups": groupByStack(rows), "Blocked24h": total, "DefaultMode": s.Policy.DefaultMode()})
}

// --- serviço ---

type destRow struct {
	store.Destination
	Rule       string
	Listed     bool
	Suspicious []string
	Suggest    bool
}

func ruleFor(host string, port int) string { return fmt.Sprintf("%s:%d", host, port) }

func (s *Server) service(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := r.Context()
	dests, err := s.Store.Destinations(ctx, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	queries, err := s.Store.DNSQueries(ctx, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	hours, err := s.Store.Hourly(ctx, name, 24)
	if err != nil {
		s.fail(w, err)
		return
	}
	var maxHits int64
	for _, h := range hours {
		if h.Hits > maxHits {
			maxHits = h.Hits
		}
	}
	var info store.Service
	svcs, _ := s.Store.Services(ctx)
	for _, sv := range svcs {
		if sv.Name == name {
			info = sv
		}
	}

	// junta http e https do mesmo host:porta numa linha só
	byRule := map[string]*destRow{}
	var order []string
	for _, d := range dests {
		rule := ruleFor(d.Host, d.Port)
		if row, ok := byRule[rule]; ok {
			row.Hits += d.Hits
			row.Blocked += d.Blocked
			row.BytesIn += d.BytesIn
			row.BytesOut += d.BytesOut
			row.SNIMismatch += d.SNIMismatch
			if d.LastSeen.After(row.LastSeen) {
				row.LastSeen = d.LastSeen
			}
			if d.FirstSeen.Before(row.FirstSeen) {
				row.FirstSeen = d.FirstSeen
			}
			continue
		}
		dec := s.Policy.Decide(name, d.Host, d.Port)
		row := &destRow{Destination: d, Rule: rule, Listed: dec.Listed, Suspicious: policy.Suspicious(d.Host)}
		byRule[rule] = row
		order = append(order, rule)
	}
	var rows []destRow
	for _, k := range order {
		row := byRule[k]
		// sugestão: o que foi usado, não é suspeito e não teve SNI estranho
		row.Suggest = !row.Listed && len(row.Suspicious) == 0 && row.SNIMismatch == 0
		rows = append(rows, *row)
	}
	mode := s.Policy.ModeOf(name)
	rule := s.Policy.Rules()[name]
	s.render(w, r, "service.html", map[string]any{
		"Name": name, "Info": info, "Mode": mode, "ExplicitMode": rule.Mode, "DefaultMode": s.Policy.DefaultMode(),
		"Allow": rule.Allow, "Dests": rows, "DNS": queries, "Hours": hours, "MaxHits": maxHits,
		"LearnLeft": s.learnLeft(info, mode),
	})
}

func (s *Server) setMode(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	mode := r.FormValue("mode")
	if mode != "" && !config.ValidMode(mode) {
		http.Error(w, "modo inválido", http.StatusBadRequest)
		return
	}
	if err := s.Store.SetMode(r.Context(), name, mode); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.reload(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	slog.Info("modo alterado pelo painel", "user", userOf(r), "service", name, "mode", mode)
	back(w, r, "/service/"+url.PathEscape(name), "Modo atualizado.")
}

func (s *Server) addAllow(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "formulário inválido", http.StatusBadRequest)
		return
	}
	var rules []string
	for _, v := range append(r.PostForm["rule"], strings.Fields(r.PostForm.Get("new"))...) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if !policy.ValidRule(v) {
			http.Error(w, "regra inválida: "+v, http.StatusBadRequest)
			return
		}
		rules = append(rules, v)
	}
	if len(rules) > 0 {
		if err := s.Store.AddAllow(r.Context(), name, rules...); err != nil {
			s.fail(w, err)
			return
		}
		if err := s.reload(r.Context()); err != nil {
			s.fail(w, err)
			return
		}
		slog.Info("whitelist ampliada pelo painel", "user", userOf(r), "service", name, "rules", rules)
	}
	to := "/service/" + url.PathEscape(name)
	if r.PostForm.Get("from") == "blocks" {
		to = "/blocks"
	}
	back(w, r, to, fmt.Sprintf("%d regra(s) adicionada(s).", len(rules)))
}

func (s *Server) removeAllow(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rule := r.FormValue("rule")
	if err := s.Store.RemoveAllow(r.Context(), name, rule); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.reload(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	slog.Info("regra removida pelo painel", "user", userOf(r), "service", name, "rule", rule)
	back(w, r, "/service/"+url.PathEscape(name), "Regra removida.")
}

func (s *Server) forget(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Store.DeleteServiceHistory(r.Context(), name); err != nil {
		s.fail(w, err)
		return
	}
	slog.Info("histórico apagado pelo painel", "user", userOf(r), "service", name)
	back(w, r, "/", "Histórico de "+name+" apagado.")
}

// --- bloqueios ---

type blockRow struct {
	Service, Host, Rule, Kind string
	Port                      int
	Count                     int64
	LastSeen                  time.Time
}

func (s *Server) blocks(w http.ResponseWriter, r *http.Request) {
	dests, err := s.Store.Destinations(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	queries, err := s.Store.DNSQueries(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	var rows []blockRow
	for _, d := range dests {
		if d.Blocked > 0 {
			rows = append(rows, blockRow{Service: d.Service, Host: d.Host, Port: d.Port, Rule: ruleFor(d.Host, d.Port),
				Kind: d.Proto, Count: d.Blocked, LastSeen: d.LastSeen})
		}
	}
	for _, q := range queries {
		if q.Denied > 0 {
			rows = append(rows, blockRow{Service: q.Service, Host: q.Name, Rule: q.Name + ":443",
				Kind: "dns " + q.QType, Count: q.Denied, LastSeen: q.LastSeen})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].LastSeen.After(rows[j].LastSeen) })
	s.render(w, r, "blocks.html", map[string]any{"Rows": rows})
}

// --- whitelist (YAML) ---

type yamlRules struct {
	Services map[string]config.ServiceConfig `yaml:"services"`
}

func (s *Server) rulesYAML() ([]byte, error) {
	return yaml.Marshal(yamlRules{Services: s.Policy.Rules()})
}

func (s *Server) whitelist(w http.ResponseWriter, r *http.Request) {
	b, err := s.rulesYAML()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "whitelist.html", map[string]any{"YAML": string(b)})
}

func (s *Server) exportYAML(w http.ResponseWriter, r *http.Request) {
	b, err := s.rulesYAML()
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="poisonstop-whitelist.yml"`)
	w.Write(b)
}

func (s *Server) importYAML(w http.ResponseWriter, r *http.Request) {
	var in yamlRules
	if err := yaml.Unmarshal([]byte(r.FormValue("yaml")), &in); err != nil {
		http.Error(w, "YAML inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	for name, sc := range in.Services {
		if sc.Mode != "" && !config.ValidMode(sc.Mode) {
			http.Error(w, fmt.Sprintf("serviço %s: modo inválido %q", name, sc.Mode), http.StatusBadRequest)
			return
		}
		for _, a := range sc.Allow {
			if !policy.ValidRule(a) {
				http.Error(w, fmt.Sprintf("serviço %s: regra inválida %q", name, a), http.StatusBadRequest)
				return
			}
		}
	}
	if err := s.Store.ReplaceRules(r.Context(), in.Services); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.reload(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	slog.Info("whitelist importada pelo painel", "user", userOf(r), "services", len(in.Services))
	back(w, r, "/whitelist", "Whitelist importada.")
}

func (s *Server) apiDestinations(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Store.Destinations(r.Context(), r.URL.Query().Get("service"))
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ds)
}

// --- formatação ---

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds atrás", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min atrás", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh atrás", int(d.Hours()))
	}
	return fmt.Sprintf("%d dias atrás", int(d.Hours()/24))
}
