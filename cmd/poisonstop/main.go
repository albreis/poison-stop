// Comando poisonstop: proxy de saída (egress) com painel para Docker.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/albreis/poison-stop/internal/config"
	"github.com/albreis/poison-stop/internal/dns"
	"github.com/albreis/poison-stop/internal/identify"
	"github.com/albreis/poison-stop/internal/policy"
	"github.com/albreis/poison-stop/internal/proxy"
	"github.com/albreis/poison-stop/internal/store"
	"github.com/albreis/poison-stop/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		slog.Error("encerrando", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run() error {
	cfgPath := flag.String("config", envOr("POISONSTOP_CONFIG", "/etc/poisonstop.yml"), "arquivo de configuração")
	showVersion := flag.Bool("version", false, "mostra a versão")
	flag.Parse()
	if *showVersion {
		fmt.Println("poisonstop", version)
		return nil
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	slog.Info("iniciando PoisonStop", "version", version, "config", *cfgPath,
		"default_mode", cfg.DefaultMode, "services", len(cfg.Services), "docker", cfg.Identify.DockerHost)

	st, err := store.Open(cfg.Data.Path)
	if err != nil {
		return fmt.Errorf("abrindo banco %s: %w", cfg.Data.Path, err)
	}
	defer st.Close()

	pol := policy.New(cfg)
	id := identify.New(cfg.Identify.DockerHost, cfg.Identify.StaticIPs)
	px := proxy.New(pol, id, st)

	panel, err := web.New(st, pol, cfg.Panel.DenyCIDRs)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 3)
	go func() {
		slog.Info("proxy ouvindo", "addr", cfg.Proxy.Listen)
		errc <- px.ListenAndServe(ctx, cfg.Proxy.Listen)
	}()
	if cfg.DNS.Listen != "" {
		resolver := dns.New(pol, id, st, cfg.DNS.Upstream)
		go func() {
			slog.Info("DNS ouvindo", "addr", cfg.DNS.Listen, "upstream", resolver.Upstream)
			if err := resolver.ListenAndServe(ctx, cfg.DNS.Listen); err != nil {
				errc <- fmt.Errorf("DNS: %w", err)
			}
		}()
	}
	go func() {
		srv := &http.Server{Addr: cfg.Panel.Listen, Handler: panel.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		}()
		slog.Info("painel ouvindo", "addr", cfg.Panel.Listen)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case <-ctx.Done():
		slog.Info("sinal recebido, encerrando")
		return nil
	case err := <-errc:
		return err
	}
}

// healthcheck é usado pelo HEALTHCHECK do container (a imagem não tem shell).
func healthcheck() int {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(envOr("POISONSTOP_HEALTH_URL", "http://127.0.0.1:8080/healthz"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
