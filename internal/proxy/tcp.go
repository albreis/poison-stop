package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/albreis/poison-stop/internal/store"
)

// TCP genérico: conexões fora de 80/443 (SSH, SCP, FTP, SMTP...) chegam do
// relay do sidecar netfilter com uma linha do PROXY protocol v1 na frente,
// que diz a origem (o container) e o destino original (IP:porta). Não há
// nome de host: a regra é por IP:porta.

// PortName é o protocolo provável de uma porta.
var PortName = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 110: "pop3",
	143: "imap", 389: "ldap", 465: "smtps", 587: "smtp", 636: "ldaps", 873: "rsync",
	989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1883: "mqtt",
	3306: "mysql", 3389: "rdp", 5432: "postgres", 5672: "amqp", 6379: "redis", 6667: "irc",
	8080: "http-alt", 8443: "https-alt", 9418: "git", 11211: "memcached", 27017: "mongodb",
}

// ProtoFor devolve "tcp/<nome>" ou "tcp".
func ProtoFor(port int) string {
	if n, ok := PortName[port]; ok {
		return "tcp/" + n
	}
	return "tcp"
}

// ParseProxyV1 lê "PROXY TCP4 src dst sport dport".
func ParseProxyV1(line string) (src, dst string, dport int, err error) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return "", "", 0, fmt.Errorf("cabeçalho PROXY inválido")
	}
	if net.ParseIP(f[2]) == nil || net.ParseIP(f[3]) == nil {
		return "", "", 0, fmt.Errorf("IP inválido no cabeçalho PROXY")
	}
	dport, err = strconv.Atoi(f[5])
	if err != nil || dport <= 0 || dport > 65535 {
		return "", "", 0, fmt.Errorf("porta inválida no cabeçalho PROXY")
	}
	return f[2], f[3], dport, nil
}

// ServeRelayedTCP atende uma conexão vinda do relay.
func (p *Proxy) ServeRelayedTCP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReaderSize(conn, 256)
	line, err := br.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || len(line) > 120 {
		return
	}
	ip, host, port, err := ParseProxyV1(line)
	if err != nil {
		slog.Warn("relay TCP", "err", err)
		return
	}
	svc := p.Ident.Identify(ip)
	d := p.Policy.Decide(svc, host, port)
	ev := store.Event{Time: time.Now(), Service: svc, ClientIP: ip, Host: host, Port: port, Proto: ProtoFor(port), Mode: d.Mode}
	if !d.Allowed {
		ev.Blocked = true
		p.Rec.Record(ev)
		slog.Info("bloqueado", "service", svc, "host", host, "port", port, "proto", ev.Proto, "reason", d.Reason)
		return
	}
	up, err := p.Dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		p.Rec.Record(ev)
		slog.Warn("erro no destino", "service", svc, "host", host, "port", port, "err", err)
		return
	}
	defer up.Close()
	out, in := pipe(conn, br, up)
	ev.BytesOut, ev.BytesIn = out, in
	p.Rec.Record(ev)
}

// ListenRelayedTCP aceita só conexões vindas das redes em trusted (o relay
// do sidecar), para ninguém forjar o cabeçalho PROXY.
func (p *Proxy) ListenRelayedTCP(ctx context.Context, addr string, trusted []*net.IPNet) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		h, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		ok := false
		for _, n := range trusted {
			if n.Contains(net.ParseIP(h)) {
				ok = true
				break
			}
		}
		if !ok {
			slog.Warn("relay TCP: origem não confiável recusada", "ip", h)
			c.Close()
			continue
		}
		go p.ServeRelayedTCP(c)
	}
}
