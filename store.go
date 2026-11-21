package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RosConf guarda como falar com a REST API da RouterBoard.
type RosConf struct {
	HTTPS     bool   `json:"https"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	Password  string `json:"password"`
	VerifyTLS bool   `json:"verifyTLS"`
}

// WgConf guarda os parâmetros do servidor WireGuard e os padrões dos clientes.
type WgConf struct {
	Iface      string `json:"iface"`
	ListenPort int    `json:"listenPort"`
	Subnet     string `json:"subnet"`
	ServerIP   string `json:"serverIP"`
	Endpoint   string `json:"endpoint"`
	DNS        string `json:"dns"`
	AllowedIPs string `json:"allowedIPs"`
}

// Config é o conteúdo de /data/config.json. Chaves privadas de peers nunca entram aqui.
type Config struct {
	PasswordHash string   `json:"passwordHash"`
	Ros          *RosConf `json:"ros,omitempty"`
	Wg           *WgConf  `json:"wg,omitempty"`
	SetupDone    bool     `json:"setupDone"`
}

func (c *Config) clone() Config {
	d := *c
	if c.Ros != nil {
		r := *c.Ros
		d.Ros = &r
	}
	if c.Wg != nil {
		w := *c.Wg
		d.Wg = &w
	}
	return d
}

type Store struct {
	mu   sync.RWMutex
	path string
	cfg  *Config // nil enquanto não existir config.json
}

func LoadStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "config.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// primeiro acesso: o wizard assume
	case err != nil:
		return nil, err
	default:
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("config.json inválido: %w", err)
		}
		s.cfg = &c
		_ = os.Chmod(s.path, 0o600)
	}
	// falha cedo se o volume não for gravável
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("sem permissão de escrita: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return s, nil
}

// Snapshot devolve uma cópia da configuração; ok=false se ainda não existe.
func (s *Store) Snapshot() (Config, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil {
		return Config{}, false
	}
	return s.cfg.clone(), true
}

// Mutate aplica fn sobre uma cópia e grava em disco só se fn retornar nil.
func (s *Store) Mutate(fn func(c *Config, exists bool) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var c Config
	exists := s.cfg != nil
	if exists {
		c = s.cfg.clone()
	}
	if err := fn(&c, exists); err != nil {
		return err
	}
	if err := s.write(&c); err != nil {
		return err
	}
	s.cfg = &c
	return nil
}

func (s *Store) write(c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
