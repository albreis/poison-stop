package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/albreis/poison-stop/internal/config"
)

const rulesSchema = `
CREATE TABLE IF NOT EXISTS service_rules (
	service TEXT PRIMARY KEY,
	mode    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS allow_rules (
	service    TEXT NOT NULL,
	rule       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (service, rule)
);
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
	username TEXT PRIMARY KEY,
	hash     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token    TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	expires  INTEGER NOT NULL
);
`

// RulesSeeded diz se as regras já foram importadas alguma vez do arquivo.
func (s *Store) RulesSeeded(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='rules_seeded'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// LoadRules lê as regras por serviço.
func (s *Store) LoadRules(ctx context.Context) (map[string]config.ServiceConfig, error) {
	out := map[string]config.ServiceConfig{}
	rows, err := s.db.QueryContext(ctx, `SELECT service, mode FROM service_rules`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var svc, mode string
		if err := rows.Scan(&svc, &mode); err != nil {
			rows.Close()
			return nil, err
		}
		out[svc] = config.ServiceConfig{Mode: mode}
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT service, rule FROM allow_rules ORDER BY service, rule`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var svc, rule string
		if err := rows.Scan(&svc, &rule); err != nil {
			return nil, err
		}
		sc := out[svc]
		sc.Allow = append(sc.Allow, rule)
		out[svc] = sc
	}
	return out, rows.Err()
}

// ReplaceRules troca todas as regras (usado na semeadura e no import YAML).
func (s *Store) ReplaceRules(ctx context.Context, rules map[string]config.ServiceConfig) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM service_rules; DELETE FROM allow_rules;`); err != nil {
		return err
	}
	now := time.Now().Unix()
	names := make([]string, 0, len(rules))
	for n := range rules {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, svc := range names {
		r := rules[svc]
		if _, err := tx.Exec(`INSERT INTO service_rules(service, mode) VALUES(?,?)`, svc, r.Mode); err != nil {
			return err
		}
		for _, a := range r.Allow {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO allow_rules(service, rule, created_at) VALUES(?,?,?)`, svc, a, now); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`INSERT INTO meta(key, value) VALUES('rules_seeded', '1') ON CONFLICT(key) DO NOTHING`); err != nil {
		return err
	}
	return tx.Commit()
}

// SetMode muda o modo de um serviço ("" volta ao default_mode).
func (s *Store) SetMode(ctx context.Context, service, mode string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO service_rules(service, mode) VALUES(?,?)
		ON CONFLICT(service) DO UPDATE SET mode=excluded.mode`, service, mode)
	return err
}

// AddAllow inclui regras na whitelist de um serviço.
func (s *Store) AddAllow(ctx context.Context, service string, rules ...string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO service_rules(service, mode) VALUES(?, '') ON CONFLICT(service) DO NOTHING`, service); err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, r := range rules {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO allow_rules(service, rule, created_at) VALUES(?,?,?)`, service, r, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RemoveAllow tira uma regra da whitelist.
func (s *Store) RemoveAllow(ctx context.Context, service, rule string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM allow_rules WHERE service=? AND rule=?`, service, rule)
	return err
}

// --- usuários e sessões ---

// UserCount devolve quantos usuários existem.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetUser cria ou troca a senha (hash bcrypt) de um usuário.
func (s *Store) SetUser(ctx context.Context, username, hash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(username, hash) VALUES(?,?)
		ON CONFLICT(username) DO UPDATE SET hash=excluded.hash`, username, hash)
	return err
}

// UserHash devolve o hash da senha ("" se o usuário não existe).
func (s *Store) UserHash(ctx context.Context, username string) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM users WHERE username=?`, username).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return h, err
}

// NewSession cria uma sessão e devolve o token.
func (s *Store) NewSession(ctx context.Context, username string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token, username, expires) VALUES(?,?,?)`,
		tok, username, time.Now().Add(ttl).Unix())
	return tok, err
}

// SessionUser devolve o usuário de uma sessão válida ("" se inválida).
func (s *Store) SessionUser(ctx context.Context, token string) (string, error) {
	var u string
	err := s.db.QueryRowContext(ctx, `SELECT username FROM sessions WHERE token=? AND expires > ?`,
		token, time.Now().Unix()).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return u, err
}

// DeleteSession encerra uma sessão (e limpa as expiradas).
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token=? OR expires <= ?`, token, time.Now().Unix())
	return err
}

// --- consultas do painel ---

// HourPoint é o total de uma hora.
type HourPoint struct {
	Hour    time.Time
	Hits    int64
	Blocked int64
}

// Hourly devolve as últimas n horas de um serviço (horas sem tráfego vêm zeradas).
func (s *Store) Hourly(ctx context.Context, service string, n int) ([]HourPoint, error) {
	end := time.Now().Truncate(time.Hour)
	start := end.Add(-time.Duration(n-1) * time.Hour)
	rows, err := s.db.QueryContext(ctx, `SELECT hour, SUM(hits), SUM(blocked) FROM hourly
		WHERE service=? AND hour >= ? GROUP BY hour`, service, start.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[int64]HourPoint{}
	for rows.Next() {
		var h int64
		var p HourPoint
		if err := rows.Scan(&h, &p.Hits, &p.Blocked); err != nil {
			return nil, err
		}
		by[h] = p
	}
	out := make([]HourPoint, 0, n)
	for t := start; !t.After(end); t = t.Add(time.Hour) {
		p := by[t.Unix()]
		p.Hour = t
		out = append(out, p)
	}
	return out, rows.Err()
}

// BlockedSince soma os bloqueios por serviço desde t (conexões e DNS não
// entram juntos: DNS negado vem de dns_queries, sem série por hora).
func (s *Store) BlockedSince(ctx context.Context, t time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service, SUM(blocked) FROM hourly WHERE hour >= ? GROUP BY service`,
		t.Truncate(time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var svc string
		var n int64
		if err := rows.Scan(&svc, &n); err != nil {
			return nil, err
		}
		out[svc] = n
	}
	return out, rows.Err()
}

// DeleteServiceHistory apaga o histórico de um serviço (destinos, horas,
// DNS). As regras dele ficam.
func (s *Store) DeleteServiceHistory(ctx context.Context, service string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM destinations WHERE service=?`,
		`DELETE FROM hourly WHERE service=?`,
		`DELETE FROM dns_queries WHERE service=?`,
		`DELETE FROM services WHERE name=?`,
	} {
		if _, err := tx.Exec(q, service); err != nil {
			return err
		}
	}
	return tx.Commit()
}
