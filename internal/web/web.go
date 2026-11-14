// Package web serve o painel do PoisonStop.
//
// Nesta primeira entrega o painel mostra, por serviço, os hosts para onde
// ele mandou requisições. O painel recusa acessos vindos das redes listadas
// em panel.deny_cidrs (a rede dos serviços monitorados).
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Server é o painel.
type Server struct {
	Store  *store.Store
	Policy *policy.Engine
	Deny   []*net.IPNet
	tmpl   *template.Template
}

// New cria o painel.
func New(st *store.Store, pol *policy.Engine, denyCIDRs []string) (*Server, error) {
	s := &Server{Store: st, Policy: pol}
	for _, c := range denyCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		s.Deny = append(s.Deny, n)
	}
	t, err := template.New("").Funcs(template.FuncMap{
		"bytes": humanBytes,
		"ago":   ago,
		"when":  func(t time.Time) string { return t.Local().Format("02/01 15:04:05") },
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.tmpl = t
	return s, nil
}

// Handler devolve as rotas do painel.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /api/destinations", s.apiDestinations)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return s.guard(securityHeaders(mux))
}

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
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type destView struct {
	store.Destination
	Listed     bool
	Suspicious []string
}

type serviceView struct {
	store.Service
	Mode  string
	Dests []destView
}

func (s *Server) load(r *http.Request) ([]serviceView, error) {
	svcs, err := s.Store.Services(r.Context())
	if err != nil {
		return nil, err
	}
	dests, err := s.Store.Destinations(r.Context(), "")
	if err != nil {
		return nil, err
	}
	by := map[string][]destView{}
	for _, d := range dests {
		by[d.Service] = append(by[d.Service], destView{
			Destination: d,
			Listed:      s.Policy.Decide(d.Service, d.Host, d.Port).Listed,
			Suspicious:  policy.Suspicious(d.Host),
		})
	}
	out := make([]serviceView, 0, len(svcs))
	for _, sv := range svcs {
		out = append(out, serviceView{Service: sv, Mode: s.Policy.ModeOf(sv.Name), Dests: by[sv.Name]})
	}
	return out, nil
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	views, err := s.load(r)
	if err != nil {
		slog.Error("painel", "err", err)
		http.Error(w, "erro lendo o banco", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", map[string]any{"Services": views, "Now": time.Now()}); err != nil {
		slog.Error("template", "err", err)
	}
}

func (s *Server) apiDestinations(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Store.Destinations(r.Context(), r.URL.Query().Get("service"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ds)
}

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
