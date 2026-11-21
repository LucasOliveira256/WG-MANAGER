package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Endpoints usados (todos na REST API /rest do RouterOS v7):
//   GET/PUT          /rest/interface/wireguard
//   DELETE           /rest/interface/wireguard/<id>
//   GET/PUT          /rest/interface/wireguard/peers
//   GET/PATCH/DELETE /rest/interface/wireguard/peers/<id>
//   GET/PUT          /rest/ip/address

var idRe = regexp.MustCompile(`^\*[0-9A-Fa-f]+$`)

var errBadID = errors.New("ID inválido")

// RosError representa uma resposta de erro da RouterBoard.
type RosError struct {
	Status int
	Msg    string
}

func (e *RosError) Error() string { return fmt.Sprintf("RouterOS (%d): %s", e.Status, e.Msg) }

// Obj é um objeto JSON do RouterOS (os valores costumam vir como string).
type Obj map[string]any

func (o Obj) S(k string) string {
	switch v := o[k].(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

type Ros struct {
	base string
	user string
	pass string
	hc   *http.Client
}

func NewRos(c RosConf) (*Ros, error) {
	if c.Host == "" || c.Port < 1 || c.Port > 65535 {
		return nil, errors.New("host ou porta inválidos")
	}
	scheme := "http"
	if c.HTTPS {
		scheme = "https"
	}
	tr := &http.Transport{
		// Com "verificar TLS" desligado aceitamos o certificado autoassinado da RB.
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !c.VerifyTLS}, //nolint:gosec
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Ros{
		base: scheme + "://" + net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		user: c.User,
		pass: c.Password,
		hc: &http.Client{
			Transport: tr,
			Timeout:   15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (r *Ros) do(method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.base+"/rest/"+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.user, r.pass)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return fmt.Errorf("falha ao falar com a RouterBoard: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Detail
		if msg == "" {
			msg = e.Message
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			msg = "usuário ou senha inválidos"
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			msg = "redirecionamento inesperado (confira se HTTPS/porta correspondem ao serviço www ou www-ssl)"
		case msg == "":
			msg = http.StatusText(resp.StatusCode)
		}
		return &RosError{Status: resp.StatusCode, Msg: msg}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("resposta inesperada da RouterBoard: %w", err)
		}
	}
	return nil
}

func (r *Ros) list(path string) ([]Obj, error) {
	var out []Obj
	err := r.do(http.MethodGet, path, nil, &out)
	return out, err
}

func (r *Ros) Interfaces() ([]Obj, error) { return r.list("interface/wireguard") }
func (r *Ros) Peers() ([]Obj, error)      { return r.list("interface/wireguard/peers") }
func (r *Ros) Addresses() ([]Obj, error)  { return r.list("ip/address") }

func (r *Ros) Peer(id string) (Obj, error) {
	if !idRe.MatchString(id) {
		return nil, errBadID
	}
	var o Obj
	err := r.do(http.MethodGet, "interface/wireguard/peers/"+id, nil, &o)
	return o, err
}

func (r *Ros) CreateInterface(name string, port int) error {
	return r.do(http.MethodPut, "interface/wireguard", Obj{"name": name, "listen-port": strconv.Itoa(port)}, nil)
}

func (r *Ros) DeleteInterface(id string) error {
	if !idRe.MatchString(id) {
		return errBadID
	}
	return r.do(http.MethodDelete, "interface/wireguard/"+id, nil, nil)
}

func (r *Ros) CreateAddress(addr, iface string) error {
	return r.do(http.MethodPut, "ip/address", Obj{"address": addr, "interface": iface}, nil)
}

func (r *Ros) CreatePeer(body Obj) error {
	return r.do(http.MethodPut, "interface/wireguard/peers", body, nil)
}

func (r *Ros) SetPeerDisabled(id string, disabled bool) error {
	if !idRe.MatchString(id) {
		return errBadID
	}
	v := "false"
	if disabled {
		v = "true"
	}
	return r.do(http.MethodPatch, "interface/wireguard/peers/"+id, Obj{"disabled": v}, nil)
}

func (r *Ros) DeletePeer(id string) error {
	if !idRe.MatchString(id) {
		return errBadID
	}
	return r.do(http.MethodDelete, "interface/wireguard/peers/"+id, nil, nil)
}
