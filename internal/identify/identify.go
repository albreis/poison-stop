// Package identify descobre qual serviço é dono de um IP de origem.
//
// A fonte principal é a API do Docker, acessada só para leitura através de
// um docker-socket-proxy (nunca o /var/run/docker.sock direto). Como
// alternativa, IPs fixos podem ser mapeados no poisonstop.yml.
package identify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Identifier mapeia IP -> nome do serviço.
type Identifier struct {
	static     map[string]string
	dockerHost string
	client     *http.Client

	refreshMu   sync.Mutex // serializa consultas ao Docker
	mu          sync.RWMutex
	cache       map[string]string
	lastRefresh time.Time
}

// MaxAge é quanto tempo o mapa vindo do Docker vale antes de ser renovado.
const MaxAge = 30 * time.Second

// minRetry evita martelar o Docker quando aparece um IP desconhecido.
const minRetry = 3 * time.Second

// New cria um Identifier. dockerHost pode ser vazio.
func New(dockerHost string, static map[string]string) *Identifier {
	return &Identifier{
		static:     static,
		dockerHost: strings.TrimRight(dockerHost, "/"),
		client:     &http.Client{Timeout: 3 * time.Second},
		cache:      map[string]string{},
	}
}

// Identify devolve o nome do serviço dono do IP, ou "ip:<IP>" se não souber.
func (i *Identifier) Identify(ip string) string {
	if n, ok := i.static[ip]; ok {
		return n
	}
	if i.dockerHost == "" {
		return "ip:" + ip
	}
	i.mu.RLock()
	n, ok := i.cache[ip]
	age := time.Since(i.lastRefresh)
	i.mu.RUnlock()
	if ok && age < MaxAge {
		return n
	}
	if !ok && age < minRetry {
		return "ip:" + ip
	}
	i.refresh()
	i.mu.RLock()
	n, ok = i.cache[ip]
	i.mu.RUnlock()
	if ok {
		return n
	}
	return "ip:" + ip
}

type container struct {
	Names           []string          `json:"Names"`
	Labels          map[string]string `json:"Labels"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// ServiceName escolhe o nome exibido: label poisonstop.service, senão
// "projeto/serviço" do Compose (para "worker" de duas stacks não se
// misturarem), senão o nome do container.
func ServiceName(labels map[string]string, names []string) string {
	if v := labels["poisonstop.service"]; v != "" {
		return v
	}
	if v := labels["com.docker.compose.service"]; v != "" {
		if p := labels["com.docker.compose.project"]; p != "" {
			return p + "/" + v
		}
		return v
	}
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	return ""
}

func (i *Identifier) refresh() {
	i.refreshMu.Lock()
	defer i.refreshMu.Unlock()
	i.mu.RLock()
	fresh := time.Since(i.lastRefresh) < minRetry
	i.mu.RUnlock()
	if fresh {
		return // outro goroutine acabou de atualizar
	}
	m, err := i.fetch()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.lastRefresh = time.Now()
	if err != nil {
		slog.Warn("consultando a API do Docker", "err", err)
		return
	}
	i.cache = m
}

func (i *Identifier) fetch() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, i.dockerHost+"/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker respondeu %s", resp.Status)
	}
	var cs []container
	if err := json.NewDecoder(resp.Body).Decode(&cs); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, c := range cs {
		name := ServiceName(c.Labels, c.Names)
		for _, n := range c.NetworkSettings.Networks {
			if n.IPAddress != "" {
				m[n.IPAddress] = name
			}
		}
	}
	return m, nil
}
