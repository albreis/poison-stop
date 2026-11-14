package netfilter

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"syscall"
	"time"
)

// O relay cobre o TCP que não é 80/443 (SSH, SCP, FTP, SMTP, bancos...).
// Ele roda aqui, no namespace de rede do host, porque é só aqui que o
// conntrack sabe o destino original de uma conexão desviada por REDIRECT
// (SO_ORIGINAL_DST). O relay abre uma conexão até o PoisonStop, manda na
// frente uma linha do PROXY protocol v1 com origem e destino originais e
// depois só copia os bytes. Quem decide (learn/monitor/enforce) e registra é
// o PoisonStop.

const soOriginalDst = 80 // SO_ORIGINAL_DST (linux/netfilter_ipv4.h)

// OriginalDst devolve o destino original de uma conexão desviada por
// REDIRECT. Só funciona no Linux.
func OriginalDst(c *net.TCPConn) (*net.TCPAddr, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var addr *net.TCPAddr
	var serr error
	err = raw.Control(func(fd uintptr) {
		// sockaddr_in cabe nos 16 bytes de um IPv6Mreq.
		mreq, e := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if e != nil {
			serr = e
			return
		}
		b := mreq.Multiaddr
		addr = &net.TCPAddr{IP: net.IPv4(b[4], b[5], b[6], b[7]), Port: int(binary.BigEndian.Uint16(b[2:4]))}
	})
	if err != nil {
		return nil, err
	}
	return addr, serr
}

// ProxyHeader monta a linha do PROXY protocol v1.
func ProxyHeader(src, dst *net.TCPAddr) string {
	return fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src.IP.String(), dst.IP.String(), src.Port, dst.Port)
}

// Relay escuta as conexões desviadas e as entrega ao PoisonStop.
type Relay struct {
	Listen string // ex.: ":15001"
	Target string // ex.: "10.89.1.2:3400"
}

// Run aceita conexões até o contexto acabar.
func (r *Relay) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp4", r.Listen)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	_, selfPort, _ := net.SplitHostPort(r.Listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go r.handle(c.(*net.TCPConn), selfPort)
	}
}

func (r *Relay) handle(c *net.TCPConn, selfPort string) {
	defer c.Close()
	dst, err := OriginalDst(c)
	if err != nil || strconv.Itoa(dst.Port) == selfPort {
		return // conexão direta ao relay, não desviada
	}
	src := c.RemoteAddr().(*net.TCPAddr)
	up, err := net.DialTimeout("tcp", r.Target, 5*time.Second)
	if err != nil {
		slog.Warn("relay: PoisonStop não respondeu", "err", err, "src", src, "dst", dst)
		return
	}
	defer up.Close()
	if _, err := io.WriteString(up, ProxyHeader(src, dst)); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, c)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(c, up)
	_ = c.CloseWrite()
	<-done
}
