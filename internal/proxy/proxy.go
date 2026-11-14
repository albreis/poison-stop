// Package proxy implementa o proxy explícito HTTP/HTTPS (CONNECT).
//
// HTTP: decide pelo host da URL. HTTPS: decide pelo host do CONNECT e, sem
// abrir o TLS, lê o SNI do ClientHello para conferir se bate com o host
// pedido.
package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

// Identifier mapeia IP de origem -> serviço.
type Identifier interface {
	Identify(ip string) string
}

// Recorder recebe os eventos de conexão.
type Recorder interface {
	Record(store.Event)
}

// Proxy é o handler HTTP do proxy.
type Proxy struct {
	Policy   *policy.Engine
	Ident    Identifier
	Rec      Recorder
	Dialer   *net.Dialer
	Transprt *http.Transport
}

// New cria um Proxy com timeouts razoáveis.
func New(p *policy.Engine, id Identifier, rec Recorder) *Proxy {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &Proxy{
		Policy: p, Ident: id, Rec: rec, Dialer: d,
		Transprt: &http.Transport{
			Proxy:                 nil, // nunca encadear em outro proxy
			DialContext:           d.DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
	}
}

// ServeHTTP despacha CONNECT e requisições HTTP com URL absoluta.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "PoisonStop: isto é um proxy; use HTTP_PROXY/HTTPS_PROXY", http.StatusBadRequest)
		return
	}
	p.handleHTTP(w, r)
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func splitHostPort(hostport string, defPort int) (string, int) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(strings.Trim(hostport, "[]")), defPort
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return strings.ToLower(h), defPort
	}
	return strings.ToLower(h), n
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, k := range strings.Split(f, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

type countingReader struct {
	r io.ReadCloser
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}
func (c *countingReader) Close() error { return c.r.Close() }

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	svc := p.Ident.Identify(ip)
	if r.URL.Scheme != "http" {
		http.Error(w, "PoisonStop: esquema não suportado: "+r.URL.Scheme, http.StatusBadRequest)
		return
	}
	host, port := splitHostPort(r.URL.Host, 80)
	d := p.Policy.Decide(svc, host, port)
	ev := store.Event{Time: time.Now(), Service: svc, ClientIP: ip, Host: host, Port: port, Proto: "http", Mode: d.Mode}
	if !d.Allowed {
		ev.Blocked = true
		p.Rec.Record(ev)
		slog.Info("bloqueado", "service", svc, "host", host, "port", port, "proto", "http", "reason", d.Reason)
		http.Error(w, "PoisonStop: destino bloqueado ("+d.Reason+")", http.StatusForbidden)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHop(out.Header)
	var body *countingReader
	if r.Body != nil && r.Body != http.NoBody {
		body = &countingReader{r: r.Body}
		out.Body = body
	}
	resp, err := p.Transprt.RoundTrip(out)
	if body != nil {
		ev.BytesOut = body.n.Load()
	}
	if err != nil {
		p.Rec.Record(ev)
		slog.Warn("erro no destino", "service", svc, "host", host, "err", err)
		http.Error(w, "PoisonStop: erro ao falar com o destino", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	if body != nil {
		ev.BytesOut = body.n.Load()
	}
	ev.BytesIn = n
	p.Rec.Record(ev)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	svc := p.Ident.Identify(ip)
	host, port := splitHostPort(r.Host, 443)
	d := p.Policy.Decide(svc, host, port)
	ev := store.Event{Time: time.Now(), Service: svc, ClientIP: ip, Host: host, Port: port, Proto: "https", Mode: d.Mode}
	if !d.Allowed {
		ev.Blocked = true
		p.Rec.Record(ev)
		slog.Info("bloqueado", "service", svc, "host", host, "port", port, "proto", "connect", "reason", d.Reason)
		http.Error(w, "PoisonStop: destino bloqueado ("+d.Reason+")", http.StatusForbidden)
		return
	}

	upstream, err := p.Dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		p.Rec.Record(ev)
		slog.Warn("erro no destino", "service", svc, "host", host, "err", err)
		http.Error(w, "PoisonStop: erro ao falar com o destino", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack não suportado", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Lê o ClientHello (com prazo, caso o protocolo seja "servidor fala primeiro").
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	sni, isTLS, consumed := PeekClientHello(brw.Reader)
	_ = client.SetReadDeadline(time.Time{})
	if !isTLS {
		ev.Proto = "tcp"
	}
	ev.SNI = sni
	if isTLS && sni != "" && !strings.EqualFold(strings.TrimSuffix(sni, "."), host) {
		ev.SNIMismatch = true
		if d.Mode == policy.Enforce || d.Mode == policy.Monitor {
			slog.Warn("SNI diferente do CONNECT", "service", svc, "connect", host, "sni", sni)
		}
		if d.Mode == policy.Enforce {
			ev.Blocked = true
			p.Rec.Record(ev)
			return // fecha a conexão
		}
	}

	if len(consumed) > 0 {
		if _, err := upstream.Write(consumed); err != nil {
			p.Rec.Record(ev)
			return
		}
	}
	out, in := pipe(client, brw.Reader, upstream)
	ev.BytesOut = out + int64(len(consumed))
	ev.BytesIn = in
	p.Rec.Record(ev)
}

// pipe copia nos dois sentidos até um dos lados fechar.
func pipe(client net.Conn, clientR io.Reader, upstream net.Conn) (out, in int64) {
	done := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(upstream, clientR)
		closeWrite(upstream)
		done <- n
	}()
	in, _ = io.Copy(client, upstream)
	closeWrite(client)
	out = <-done
	return out, in
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// ListenAndServe sobe o proxy até o contexto acabar.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
