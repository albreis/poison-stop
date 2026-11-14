package alerts

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/store"
)

// Sink é quem grava os eventos (o store).
type Sink interface {
	Record(store.Event)
	RecordDNS(store.DNSEvent)
}

// Watcher fica entre o proxy/DNS e o store: grava tudo e decide o que vira
// alerta.
//
//   - conexão bloqueada ou SNI diferente do CONNECT: sempre alerta;
//   - consulta DNS negada: sempre alerta;
//   - monitor: destino fora da whitelist alerta;
//   - learn: depois do learn_period do serviço, um destino nunca visto alerta
//     como "destino novo" (o melhor sinal de comprometimento que existe).
type Watcher struct {
	Next        Sink
	Notifier    *Notifier
	Policy      *policy.Engine
	LearnPeriod time.Duration
	now         func() time.Time

	mu       sync.Mutex
	known    map[string]bool
	svcFirst map[string]time.Time
}

// NewWatcher cria o Watcher já conhecendo o que está no banco.
func NewWatcher(ctx context.Context, st *store.Store, n *Notifier, p *policy.Engine, learn time.Duration) (*Watcher, error) {
	w := &Watcher{Next: st, Notifier: n, Policy: p, LearnPeriod: learn, now: time.Now,
		known: map[string]bool{}, svcFirst: map[string]time.Time{}}
	ds, err := st.Destinations(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		w.known[destKey(d.Service, d.Host, d.Port)] = true
	}
	svcs, err := st.Services(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range svcs {
		w.svcFirst[s.Name] = s.FirstSeen
	}
	return w, nil
}

func destKey(svc, host string, port int) string { return fmt.Sprintf("%s|%s|%d", svc, host, port) }

// Record implementa proxy.Recorder.
func (w *Watcher) Record(e store.Event) {
	w.Next.Record(e)

	now := w.now()
	w.mu.Lock()
	key := destKey(e.Service, e.Host, e.Port)
	isNew := !w.known[key]
	w.known[key] = true
	first, ok := w.svcFirst[e.Service]
	if !ok {
		first = now
		w.svcFirst[e.Service] = now
	}
	w.mu.Unlock()

	a := Alert{Service: e.Service, Host: e.Host, Port: e.Port, Proto: e.Proto, Mode: e.Mode, Time: e.Time}
	switch {
	case e.Blocked:
		a.Kind = KindBlocked
		if e.SNIMismatch {
			a.Detail = "SNI do TLS (" + e.SNI + ") diferente do host pedido"
		}
	case e.SNIMismatch:
		a.Kind = KindSNIMismatch
		a.Detail = "SNI do TLS: " + e.SNI
	case e.Mode == policy.Monitor && !w.Policy.Decide(e.Service, e.Host, e.Port).Listed:
		a.Kind = KindOffList
	case e.Mode == policy.Learn && isNew && now.Sub(first) >= w.LearnPeriod:
		a.Kind = KindNewHost
		a.Detail = "Primeira vez que este serviço fala com este destino, depois do período de aprendizado."
	default:
		return
	}
	if r := policy.Suspicious(e.Host); len(r) > 0 {
		if a.Detail != "" {
			a.Detail += "\n"
		}
		a.Detail += "Atenção: " + r[0]
	}
	w.Notifier.Notify(a)
}

// RecordDNS implementa dns.Recorder.
func (w *Watcher) RecordDNS(e store.DNSEvent) {
	w.Next.RecordDNS(e)
	if !e.Denied {
		return
	}
	w.Notifier.Notify(Alert{
		Kind: KindDNSDenied, Service: e.Service, Host: e.Name, Proto: "dns/" + e.QType,
		Mode: w.Policy.ModeOf(e.Service), Time: e.Time,
	})
}
