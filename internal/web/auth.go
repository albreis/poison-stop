package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"

	"golang.org/x/crypto/bcrypt"

	"github.com/albreis/poison-stop/internal/store"
)

// hash usado quando o usuário não existe, para o tempo de resposta não
// revelar quais usuários existem.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("poisonstop"), bcrypt.DefaultCost)

// CheckPassword confere usuário e senha.
func CheckPassword(ctx context.Context, st *store.Store, user, pass string) bool {
	h, err := st.UserHash(ctx, user)
	if err != nil || h == "" {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pass))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(pass)) == nil
}

// SetPassword grava a senha (bcrypt) de um usuário.
func SetPassword(ctx context.Context, st *store.Store, user, pass string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return st.SetUser(ctx, user, string(h))
}

// EnsureAdmin cria o primeiro usuário se não houver nenhum. A senha vem de
// POISONSTOP_ADMIN_PASSWORD; sem ela, uma senha aleatória é gerada e
// mostrada uma única vez no log.
func EnsureAdmin(ctx context.Context, st *store.Store, user, pass string) error {
	n, err := st.UserCount(ctx)
	if err != nil || n > 0 {
		return err
	}
	if user == "" {
		user = "admin"
	}
	generated := pass == ""
	if generated {
		b := make([]byte, 15)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		pass = base64.RawURLEncoding.EncodeToString(b)
	}
	if err := SetPassword(ctx, st, user, pass); err != nil {
		return err
	}
	if generated {
		slog.Warn("usuário do painel criado com senha gerada; anote, ela não aparece de novo",
			"user", user, "password", pass)
	} else {
		slog.Info("usuário do painel criado", "user", user)
	}
	return nil
}
