package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

var errStop = errors.New("parar depois do ClientHello")

// readOnlyConn deixa o crypto/tls ler o ClientHello sem conseguir responder.
type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return nil }
func (readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// PeekClientHello lê do cliente o suficiente para achar o SNI do TLS, sem
// abrir o TLS. Devolve os bytes consumidos, que precisam ser reenviados ao
// destino. isTLS é falso se o tráfego não parece TLS.
func PeekClientHello(r io.Reader) (sni string, isTLS bool, consumed []byte) {
	var buf bytes.Buffer
	var hello *tls.ClientHelloInfo
	_ = tls.Server(readOnlyConn{r: io.TeeReader(r, &buf)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = h
			return nil, errStop
		},
	}).Handshake()
	if hello == nil {
		return "", false, buf.Bytes()
	}
	return hello.ServerName, true, buf.Bytes()
}
