package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/albreis/poison-stop/internal/store"
)

// Modo transparente: o firewall do host desvia (DNAT) o tráfego 80/443 dos
// containers para estes listeners. Não há CONNECT nem HTTP_PROXY: o destino
// sai do cabeçalho Host (HTTP) ou do SNI do ClientHello (TLS). Como o DNAT
// acontece em outro namespace de rede, o IP original não é conhecido; TLS sem
// SNI (IP direto) não tem como ser repassado e é recusado.

// TransparentHTTP devolve o handler HTTP do modo transparente.
func (p *Proxy) TransparentHTTP() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" {
			http.Error(w, "PoisonStop: requisição sem Host", http.StatusBadRequest)
			return
		}
		r.URL.Scheme = "http"
		r.URL.Host = r.Host
		p.handleHTTP(w, r)
	})
}

// ServeTransparentTLS atende uma conexão TLS desviada para cá.
func (p *Proxy) ServeTransparentTLS(client net.Conn) {
	defer client.Close()
	ip := remoteHost(client.RemoteAddr())
	svc := p.Ident.Identify(ip)

	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	sni, isTLS, consumed := PeekClientHello(client)
	_ = client.SetReadDeadline(time.Time{})

	if len(consumed) == 0 {
		return // conexão aberta e fechada sem dados (ex.: checagem de saúde)
	}
	host := strings.ToLower(strings.TrimSuffix(sni, "."))
	if !isTLS || host == "" {
		// Sem nome não dá para saber o destino original.
		mode := p.Policy.ModeOf(svc)
		p.Rec.Record(store.Event{Time: time.Now(), Service: svc, ClientIP: ip, Host: "(tls sem SNI)", Port: 443,
			Proto: "tls", Mode: mode, Blocked: true})
		slog.Info("TLS sem SNI recusado no modo transparente", "service", svc, "tls", isTLS)
		return
	}
	d := p.Policy.Decide(svc, host, 443)
	ev := store.Event{Time: time.Now(), Service: svc, ClientIP: ip, Host: host, Port: 443, Proto: "tls", Mode: d.Mode, SNI: sni}
	if !d.Allowed {
		ev.Blocked = true
		p.Rec.Record(ev)
		slog.Info("bloqueado", "service", svc, "host", host, "port", 443, "proto", "tls", "reason", d.Reason)
		return
	}
	upstream, err := p.Dialer.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		p.Rec.Record(ev)
		slog.Warn("erro no destino", "service", svc, "host", host, "err", err)
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(consumed); err != nil {
		p.Rec.Record(ev)
		return
	}
	out, in := pipe(client, client, upstream)
	ev.BytesOut = out + int64(len(consumed))
	ev.BytesIn = in
	p.Rec.Record(ev)
}

func remoteHost(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

// ListenTransparent sobe os listeners HTTP e TLS do modo transparente.
func (p *Proxy) ListenTransparent(ctx context.Context, httpAddr, tlsAddr string) error {
	errc := make(chan error, 2)
	hs := &http.Server{Addr: httpAddr, Handler: p.TransparentHTTP(), ReadHeaderTimeout: 15 * time.Second}
	go func() {
		err := hs.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()
	ln, err := net.Listen("tcp", tlsAddr)
	if err != nil {
		_ = hs.Close()
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					errc <- nil
				} else {
					errc <- err
				}
				return
			}
			go p.ServeTransparentTLS(c)
		}
	}()
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	_ = ln.Close()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
	return err
}
