// Package config carrega o arquivo poisonstop.yml.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config é a configuração completa do PoisonStop.
type Config struct {
	DefaultMode string                    `yaml:"default_mode"`
	LearnPeriod Duration                  `yaml:"learn_period"`
	Services    map[string]ServiceConfig  `yaml:"services"`
	Proxy       ProxyConfig               `yaml:"proxy"`
	Panel       PanelConfig               `yaml:"panel"`
	Identify    IdentifyConfig            `yaml:"identify"`
	Data        DataConfig                `yaml:"data"`
	Alerts      map[string]map[string]any `yaml:"alerts"` // lido, mas usado só na próxima etapa
}

// ServiceConfig é a regra de um serviço.
type ServiceConfig struct {
	Mode  string   `yaml:"mode"`
	Allow []string `yaml:"allow"`
}

// ProxyConfig configura o proxy explícito.
type ProxyConfig struct {
	Listen string `yaml:"listen"`
}

// PanelConfig configura o painel.
type PanelConfig struct {
	Listen string `yaml:"listen"`
	// DenyCIDRs são redes de onde o painel recusa acesso (a rede "apps").
	DenyCIDRs []string `yaml:"deny_cidrs"`
}

// IdentifyConfig diz como descobrir qual serviço é dono de um IP.
type IdentifyConfig struct {
	// DockerHost é a URL de um docker-socket-proxy somente leitura,
	// ex.: http://docker-proxy:2375. Vazio desliga a consulta ao Docker.
	DockerHost string `yaml:"docker_host"`
	// StaticIPs mapeia IP -> nome do serviço (alternativa sem Docker).
	StaticIPs map[string]string `yaml:"static_ips"`
}

// DataConfig configura o armazenamento.
type DataConfig struct {
	Path string `yaml:"path"`
}

// Duration aceita "7d", "12h", "30m".
type Duration time.Duration

// UnmarshalYAML implementa yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ParseDuration é time.ParseDuration com suporte a sufixo "d" (dias).
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("duração inválida %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Default devolve a configuração padrão.
func Default() *Config {
	return &Config{
		DefaultMode: "learn",
		LearnPeriod: Duration(7 * 24 * time.Hour),
		Services:    map[string]ServiceConfig{},
		Proxy:       ProxyConfig{Listen: ":3128"},
		Panel:       PanelConfig{Listen: ":8080"},
		Data:        DataConfig{Path: "/data/poisonstop.db"},
	}
}

// Load lê o arquivo; se ele não existir, usa os padrões.
func Load(path string) (*Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("lendo %s: %w", path, err)
	}
	if cfg.Services == nil {
		cfg.Services = map[string]ServiceConfig{}
	}
	return cfg, cfg.Validate()
}

// Validate confere modos e CIDRs.
func (c *Config) Validate() error {
	if !ValidMode(c.DefaultMode) {
		return fmt.Errorf("default_mode inválido: %q (use learn, monitor ou enforce)", c.DefaultMode)
	}
	for name, s := range c.Services {
		if s.Mode != "" && !ValidMode(s.Mode) {
			return fmt.Errorf("serviço %s: modo inválido %q", name, s.Mode)
		}
	}
	for _, cidr := range c.Panel.DenyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("panel.deny_cidrs: %w", err)
		}
	}
	return nil
}

// ValidMode diz se o modo é conhecido.
func ValidMode(m string) bool {
	switch m {
	case "learn", "monitor", "enforce":
		return true
	}
	return false
}
