// Package alerts envia alertas (Telegram e webhook genérico) com
// agrupamento (debounce) por serviço+evento+host.
package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/albreis/poison-stop/internal/config"
)

// Tipos de evento.
const (
	KindBlocked     = "blocked"      // conexão bloqueada
	KindDNSDenied   = "dns_denied"   // consulta DNS negada
	KindNewHost     = "new_host"     // destino visto pela primeira vez
	KindOffList     = "off_list"     // monitor: destino fora da whitelist
	KindSNIMismatch = "sni_mismatch" // SNI diferente do CONNECT
)

// Alert é um evento a notificar.
type Alert struct {
	Kind    string    `json:"event"`
	Service string    `json:"service"`
	Host    string    `json:"host"`
	Port    int       `json:"port,omitempty"`
	Proto   string    `json:"proto,omitempty"`
	Mode    string    `json:"mode"`
	Detail  string    `json:"detail,omitempty"`
	Time    time.Time `json:"time"`
	// Suppressed é quantos alertas iguais foram agrupados desde o último envio.
	Suppressed int `json:"suppressed,omitempty"`
}

// Text é a mensagem legível do alerta.
func (a Alert) Text() string {
	dest := a.Host
	if a.Port != 0 {
		dest = fmt.Sprintf("%s:%d", a.Host, a.Port)
	}
	var title string
	switch a.Kind {
	case KindBlocked:
		title = "🚫 Conexão bloqueada"
	case KindDNSDenied:
		title = "🚫 Consulta DNS negada"
	case KindNewHost:
		title = "🆕 Destino novo"
	case KindOffList:
		title = "⚠️ Destino fora da whitelist"
	case KindSNIMismatch:
		title = "⚠️ SNI diferente do CONNECT"
	default:
		title = a.Kind
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PoisonStop · %s\nServiço: %s (%s)\nDestino: %s", title, a.Service, a.Mode, dest)
	if a.Proto != "" {
		fmt.Fprintf(&b, " [%s]", a.Proto)
	}
	if a.Detail != "" {
		fmt.Fprintf(&b, "\n%s", a.Detail)
	}
	if a.Suppressed > 0 {
		fmt.Fprintf(&b, "\n(+%d ocorrência(s) agrupada(s) desde o último alerta)", a.Suppressed)
	}
	return b.String()
}

// Channel é um destino de alertas.
type Channel interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// Notifier agrupa e despacha alertas sem bloquear quem chama.
type Notifier struct {
	channels []Channel
	debounce time.Duration
	queue    chan Alert
	now      func() time.Time

	mu         sync.Mutex
	closed     bool
	last       map[string]time.Time
	suppressed map[string]int
	done       chan struct{}
}

// New cria um Notifier a partir da configuração. Sem canais configurados,
// devolve um Notifier que descarta tudo.
func New(cfg config.AlertsConfig) (*Notifier, error) {
	var chs []Channel
	if t := cfg.Telegram; t != nil && t.ChatID != "" {
		token := os.Getenv(t.BotTokenEnv)
		if token == "" {
			return nil, fmt.Errorf("alerts.telegram: variável %q vazia", t.BotTokenEnv)
		}
		chs = append(chs, &Telegram{Token: token, ChatID: t.ChatID})
	}
	if w := cfg.Webhook; w != nil && w.URL != "" {
		wh := &Webhook{URL: w.URL}
		if w.SecretEnv != "" {
			wh.Secret = os.Getenv(w.SecretEnv)
			if wh.Secret == "" {
				return nil, fmt.Errorf("alerts.webhook: variável %q vazia", w.SecretEnv)
			}
		}
		chs = append(chs, wh)
	}
	return NewWithChannels(time.Duration(cfg.Debounce), chs...), nil
}

// NewWithChannels cria um Notifier com canais explícitos.
func NewWithChannels(debounce time.Duration, chs ...Channel) *Notifier {
	n := &Notifier{
		channels: chs, debounce: debounce, queue: make(chan Alert, 256), now: time.Now,
		last: map[string]time.Time{}, suppressed: map[string]int{}, done: make(chan struct{}),
	}
	go n.loop()
	return n
}

// Channels diz quais canais estão ativos.
func (n *Notifier) Channels() []string {
	var out []string
	for _, c := range n.channels {
		out = append(out, c.Name())
	}
	return out
}

// Notify enfileira um alerta, respeitando o debounce.
func (n *Notifier) Notify(a Alert) {
	if len(n.channels) == 0 {
		return
	}
	if a.Time.IsZero() {
		a.Time = n.now()
	}
	key := a.Service + "|" + a.Kind + "|" + a.Host
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	if t, ok := n.last[key]; ok && n.now().Sub(t) < n.debounce {
		n.suppressed[key]++
		return
	}
	n.last[key] = n.now()
	a.Suppressed = n.suppressed[key]
	delete(n.suppressed, key)
	select {
	case n.queue <- a:
	default:
		slog.Warn("fila de alertas cheia, descartando", "event", a.Kind, "service", a.Service)
	}
}

// Close espera os alertas na fila serem enviados.
func (n *Notifier) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	close(n.queue)
	n.mu.Unlock()
	<-n.done
}

func (n *Notifier) loop() {
	defer close(n.done)
	for a := range n.queue {
		for _, c := range n.channels {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := c.Send(ctx, a); err != nil {
				slog.Warn("enviando alerta", "channel", c.Name(), "err", err)
			}
			cancel()
		}
	}
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Telegram envia pela Bot API.
type Telegram struct {
	Token  string
	ChatID string
	// BaseURL permite testes; padrão https://api.telegram.org.
	BaseURL string
}

// Name implementa Channel.
func (*Telegram) Name() string { return "telegram" }

// Send implementa Channel.
func (t *Telegram) Send(ctx context.Context, a Alert) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	body, _ := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": a.Text(), "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+t.Token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		// a URL tem o token: não deixar ele ir para o log
		return fmt.Errorf("telegram: %s", strings.ReplaceAll(err.Error(), t.Token, "***"))
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram respondeu %s", resp.Status)
	}
	return nil
}

// Webhook faz POST de um JSON com o alerta.
type Webhook struct {
	URL    string
	Secret string
}

// Name implementa Channel.
func (*Webhook) Name() string { return "webhook" }

// Send implementa Channel.
func (w *Webhook) Send(ctx context.Context, a Alert) error {
	payload := struct {
		Alert
		Text string `json:"text"`
	}{a, a.Text()}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PoisonStop")
	if w.Secret != "" {
		m := hmac.New(sha256.New, []byte(w.Secret))
		m.Write(body)
		req.Header.Set("X-PoisonStop-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook respondeu %s", resp.Status)
	}
	return nil
}
