// Package store grava as conexões observadas num SQLite (modo WAL).
//
// As gravações passam por um único goroutine que agrupa os eventos em
// transações, para o proxy nunca esperar o disco.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite" // driver SQLite em Go puro (sem CGO)
)

// Event é uma conexão (ou tentativa) que passou pelo proxy.
type Event struct {
	Time        time.Time
	Service     string
	ClientIP    string
	Host        string
	Port        int
	Proto       string // http | https | tcp
	Mode        string
	BytesOut    int64 // do serviço para fora
	BytesIn     int64 // de fora para o serviço
	Blocked     bool
	SNI         string
	SNIMismatch bool
}

// Destination é o agregado de um serviço -> host:porta.
type Destination struct {
	Service     string
	Host        string
	Port        int
	Proto       string
	FirstSeen   time.Time
	LastSeen    time.Time
	Hits        int64
	Blocked     int64
	BytesOut    int64
	BytesIn     int64
	SNIMismatch int64
}

// Service é o resumo de um serviço.
type Service struct {
	Name      string
	LastIP    string
	FirstSeen time.Time
	LastSeen  time.Time
	Hosts     int
	Hits      int64
	Blocked   int64
}

// Store é o banco.
type Store struct {
	db     *sql.DB
	events chan any // Event ou DNSEvent
	done   chan struct{}

	closeMu sync.RWMutex
	closed  bool
}

const schema = `
CREATE TABLE IF NOT EXISTS services (
	name       TEXT PRIMARY KEY,
	last_ip    TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS destinations (
	service      TEXT NOT NULL,
	host         TEXT NOT NULL,
	port         INTEGER NOT NULL,
	proto        TEXT NOT NULL,
	first_seen   INTEGER NOT NULL,
	last_seen    INTEGER NOT NULL,
	hits         INTEGER NOT NULL DEFAULT 0,
	blocked      INTEGER NOT NULL DEFAULT 0,
	bytes_out    INTEGER NOT NULL DEFAULT 0,
	bytes_in     INTEGER NOT NULL DEFAULT 0,
	sni_mismatch INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (service, host, port, proto)
);
CREATE TABLE IF NOT EXISTS hourly (
	service   TEXT NOT NULL,
	host      TEXT NOT NULL,
	port      INTEGER NOT NULL,
	hour      INTEGER NOT NULL,
	hits      INTEGER NOT NULL DEFAULT 0,
	blocked   INTEGER NOT NULL DEFAULT 0,
	bytes_out INTEGER NOT NULL DEFAULT 0,
	bytes_in  INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (service, host, port, hour)
);
CREATE TABLE IF NOT EXISTS dns_queries (
	service    TEXT NOT NULL,
	name       TEXT NOT NULL,
	qtype      TEXT NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	hits       INTEGER NOT NULL DEFAULT 0,
	denied     INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (service, name, qtype)
);
`

// Open abre (ou cria) o banco em path.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema + rulesSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("criando schema: %w", err)
	}
	s := &Store{db: db, events: make(chan any, 4096), done: make(chan struct{})}
	go s.writer()
	return s, nil
}

// Record enfileira um evento. Nunca bloqueia: se a fila estiver cheia, o
// evento é descartado e logado.
func (s *Store) Record(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if !s.enqueue(e) {
		slog.Warn("fila de eventos cheia, descartando", "service", e.Service, "host", e.Host)
	}
}

// enqueue devolve false se a fila estiver cheia. Depois do Close, descarta
// em silêncio (conexões ainda abertas durante o desligamento).
func (s *Store) enqueue(e any) bool {
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return true
	}
	select {
	case s.events <- e:
		return true
	default:
		return false
	}
}

// Close grava o que estiver na fila e fecha o banco.
func (s *Store) Close() error {
	s.closeMu.Lock()
	s.closed = true
	close(s.events)
	s.closeMu.Unlock()
	<-s.done
	return s.db.Close()
}

func (s *Store) writer() {
	defer close(s.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var batch []any
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.write(batch); err != nil {
			slog.Error("gravando eventos", "err", err, "n", len(batch))
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-s.events:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= 256 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) write(batch []any) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range batch {
		if q, ok := item.(DNSEvent); ok {
			if err := writeDNS(tx, q); err != nil {
				return err
			}
			continue
		}
		e := item.(Event)
		ts := e.Time.Unix()
		if _, err := tx.Exec(`INSERT INTO services(name, last_ip, first_seen, last_seen) VALUES(?,?,?,?)
			ON CONFLICT(name) DO UPDATE SET last_ip=excluded.last_ip, last_seen=MAX(last_seen, excluded.last_seen)`,
			e.Service, e.ClientIP, ts, ts); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO destinations(service, host, port, proto, first_seen, last_seen, hits, blocked, bytes_out, bytes_in, sni_mismatch)
			VALUES(?,?,?,?,?,?,1,?,?,?,?)
			ON CONFLICT(service, host, port, proto) DO UPDATE SET
				last_seen=MAX(last_seen, excluded.last_seen),
				hits=hits+1,
				blocked=blocked+excluded.blocked,
				bytes_out=bytes_out+excluded.bytes_out,
				bytes_in=bytes_in+excluded.bytes_in,
				sni_mismatch=sni_mismatch+excluded.sni_mismatch`,
			e.Service, e.Host, e.Port, e.Proto, ts, ts, b2i(e.Blocked), e.BytesOut, e.BytesIn, b2i(e.SNIMismatch)); err != nil {
			return err
		}
		hour := e.Time.Truncate(time.Hour).Unix()
		if _, err := tx.Exec(`INSERT INTO hourly(service, host, port, hour, hits, blocked, bytes_out, bytes_in)
			VALUES(?,?,?,?,1,?,?,?)
			ON CONFLICT(service, host, port, hour) DO UPDATE SET
				hits=hits+1, blocked=blocked+excluded.blocked,
				bytes_out=bytes_out+excluded.bytes_out, bytes_in=bytes_in+excluded.bytes_in`,
			e.Service, e.Host, e.Port, hour, b2i(e.Blocked), e.BytesOut, e.BytesIn); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DNSEvent é uma consulta DNS recebida pelo resolver.
type DNSEvent struct {
	Time     time.Time
	Service  string
	ClientIP string
	Name     string
	QType    string
	Denied   bool
}

// DNSQuery é o agregado de consultas de um serviço a um nome.
type DNSQuery struct {
	Service   string
	Name      string
	QType     string
	FirstSeen time.Time
	LastSeen  time.Time
	Hits      int64
	Denied    int64
}

// RecordDNS enfileira uma consulta DNS (nunca bloqueia).
func (s *Store) RecordDNS(e DNSEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if !s.enqueue(e) {
		slog.Warn("fila de eventos cheia, descartando consulta DNS", "service", e.Service, "name", e.Name)
	}
}

func writeDNS(tx *sql.Tx, e DNSEvent) error {
	ts := e.Time.Unix()
	if _, err := tx.Exec(`INSERT INTO services(name, last_ip, first_seen, last_seen) VALUES(?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET last_ip=excluded.last_ip, last_seen=MAX(last_seen, excluded.last_seen)`,
		e.Service, e.ClientIP, ts, ts); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO dns_queries(service, name, qtype, first_seen, last_seen, hits, denied)
		VALUES(?,?,?,?,?,1,?)
		ON CONFLICT(service, name, qtype) DO UPDATE SET
			last_seen=MAX(last_seen, excluded.last_seen), hits=hits+1, denied=denied+excluded.denied`,
		e.Service, e.Name, e.QType, ts, ts, b2i(e.Denied))
	return err
}

// DNSQueries lista as consultas DNS agregadas (todas se service == "").
func (s *Store) DNSQueries(ctx context.Context, service string) ([]DNSQuery, error) {
	q := `SELECT service, name, qtype, first_seen, last_seen, hits, denied FROM dns_queries`
	var args []any
	if service != "" {
		q += ` WHERE service = ?`
		args = append(args, service)
	}
	q += ` ORDER BY service, hits DESC, name`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSQuery
	for rows.Next() {
		var d DNSQuery
		var fs, ls int64
		if err := rows.Scan(&d.Service, &d.Name, &d.QType, &fs, &ls, &d.Hits, &d.Denied); err != nil {
			return nil, err
		}
		d.FirstSeen, d.LastSeen = time.Unix(fs, 0), time.Unix(ls, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Services lista os serviços vistos, mais recentes primeiro.
func (s *Store) Services(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.name, s.last_ip, s.first_seen, s.last_seen,
		       COUNT(DISTINCT d.host || ':' || d.port), COALESCE(SUM(d.hits),0), COALESCE(SUM(d.blocked),0)
		FROM services s LEFT JOIN destinations d ON d.service = s.name
		GROUP BY s.name ORDER BY s.last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var v Service
		var fs, ls int64
		if err := rows.Scan(&v.Name, &v.LastIP, &fs, &ls, &v.Hosts, &v.Hits, &v.Blocked); err != nil {
			return nil, err
		}
		v.FirstSeen, v.LastSeen = time.Unix(fs, 0), time.Unix(ls, 0)
		out = append(out, v)
	}
	return out, rows.Err()
}

// Destinations lista os destinos de um serviço (todos se service == "").
func (s *Store) Destinations(ctx context.Context, service string) ([]Destination, error) {
	q := `SELECT service, host, port, proto, first_seen, last_seen, hits, blocked, bytes_out, bytes_in, sni_mismatch
		FROM destinations`
	var args []any
	if service != "" {
		q += ` WHERE service = ?`
		args = append(args, service)
	}
	q += ` ORDER BY service, hits DESC, host`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Destination
	for rows.Next() {
		var d Destination
		var fs, ls int64
		if err := rows.Scan(&d.Service, &d.Host, &d.Port, &d.Proto, &fs, &ls, &d.Hits, &d.Blocked, &d.BytesOut, &d.BytesIn, &d.SNIMismatch); err != nil {
			return nil, err
		}
		d.FirstSeen, d.LastSeen = time.Unix(fs, 0), time.Unix(ls, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}
