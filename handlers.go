package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type M map[string]any

var errAlreadySetup = errors.New("já configurado")

type App struct {
	store  *Store
	sess   *Sessions
	lim    *Limiter
	peerMu sync.Mutex // serializa criação de peers (alocação de IP)

	rosMu sync.Mutex
	ros   *Ros // cliente reutilizado depois que o wizard termina
}

func NewApp(s *Store) *App {
	return &App{store: s, sess: NewSessions(), lim: NewLimiter()}
}

type handler func(w http.ResponseWriter, r *http.Request, s session)

func (a *App) Routes(static fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", a.handleState)
	mux.HandleFunc("POST /api/setup/password", a.guard(false, a.handleSetupPassword))
	mux.HandleFunc("POST /api/login", a.guard(false, a.handleLogin))
	mux.HandleFunc("POST /api/logout", a.guard(true, a.handleLogout))
	mux.HandleFunc("POST /api/setup/ros/test", a.guard(true, a.handleRosTest))
	mux.HandleFunc("POST /api/setup/ros", a.guard(true, a.handleRosSave))
	mux.HandleFunc("GET /api/setup/interfaces", a.guard(true, a.handleSetupInterfaces))
	mux.HandleFunc("POST /api/setup/wg", a.guard(true, a.handleWgSetup))
	mux.HandleFunc("GET /api/peers", a.guard(true, a.handlePeers))
	mux.HandleFunc("POST /api/peers", a.guard(true, a.handlePeerCreate))
	mux.HandleFunc("POST /api/peers/{id}/toggle", a.guard(true, a.handlePeerToggle))
	mux.HandleFunc("POST /api/peers/{id}/delete", a.guard(true, a.handlePeerDelete))
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	return mux
}

// ---------- utilitários ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, M{"error": msg})
}

func writeRosErr(w http.ResponseWriter, err error) {
	log.Printf("routeros: %v", err)
	var re *RosError
	if errors.As(err, &re) && re.Status == http.StatusNotFound {
		writeErr(w, http.StatusNotFound, "Não encontrado na RouterBoard.")
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "not allowed") {
		msg += " (confira as policies do grupo do usuário: read, write, rest-api e sensitive)"
	}
	writeErr(w, http.StatusBadGateway, msg)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "Requisição inválida.")
		return false
	}
	return true
}

func (a *App) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return session{}, false
	}
	return a.sess.Get(c.Value)
}

// guard exige sessão válida, token CSRF em todo POST e, opcionalmente, login.
func (a *App) guard(needAuth bool, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.currentSession(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, M{"error": "Sessão expirada. Recarregue a página.", "code": "session"})
			return
		}
		if r.Method == http.MethodPost && !csrfOK(r, s) {
			writeErr(w, http.StatusForbidden, "Token CSRF inválido. Recarregue a página.")
			return
		}
		if needAuth && !s.authed {
			writeJSON(w, http.StatusUnauthorized, M{"error": "Faça login para continuar.", "code": "session"})
			return
		}
		h(w, r, s)
	}
}

// setupConfig devolve a config durante o wizard (senha já definida, setup incompleto).
func (a *App) setupConfig(w http.ResponseWriter) (Config, bool) {
	cfg, ok := a.store.Snapshot()
	if !ok {
		writeErr(w, http.StatusConflict, "Defina a senha da página primeiro.")
		return cfg, false
	}
	if cfg.SetupDone {
		writeErr(w, http.StatusConflict, "A configuração inicial já foi concluída.")
		return cfg, false
	}
	return cfg, true
}

// readyConfig devolve a config e o cliente RouterOS depois que o wizard terminou.
func (a *App) readyConfig(w http.ResponseWriter) (Config, *Ros, bool) {
	cfg, ok := a.store.Snapshot()
	if !ok || !cfg.SetupDone || cfg.Ros == nil || cfg.Wg == nil {
		writeErr(w, http.StatusConflict, "A configuração inicial ainda não foi concluída.")
		return Config{}, nil, false
	}
	a.rosMu.Lock()
	defer a.rosMu.Unlock()
	if a.ros == nil {
		c, err := NewRos(*cfg.Ros)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return Config{}, nil, false
		}
		a.ros = c
	}
	return cfg, a.ros, true
}

// ---------- estado, login, logout ----------

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	s, ok := a.currentSession(r)
	if !ok {
		s = a.sess.Create(false)
		setSessionCookie(w, r, s)
	}
	state, hasRos := "no-config", false
	if cfg, exists := a.store.Snapshot(); exists {
		state = "setup"
		if cfg.SetupDone {
			state = "ready"
		}
		hasRos = cfg.Ros != nil
	}
	writeJSON(w, http.StatusOK, M{"state": state, "authenticated": s.authed, "csrf": s.csrf, "hasRos": hasRos})
}

func (a *App) handleSetupPassword(w http.ResponseWriter, r *http.Request, s session) {
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "A senha deve ter pelo menos 8 caracteres.")
		return
	}
	if len(in.Password) > 72 {
		writeErr(w, http.StatusBadRequest, "A senha deve ter no máximo 72 bytes (limite do bcrypt).")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Não foi possível gerar o hash da senha.")
		return
	}
	err = a.store.Mutate(func(c *Config, exists bool) error {
		if exists {
			return errAlreadySetup
		}
		c.PasswordHash = string(hash)
		return nil
	})
	if errors.Is(err, errAlreadySetup) {
		writeErr(w, http.StatusConflict, "A senha já foi definida. Faça login.")
		return
	}
	if err != nil {
		log.Printf("gravar config: %v", err)
		writeErr(w, http.StatusInternalServerError, "Não foi possível gravar a configuração em /data.")
		return
	}
	a.sess.Delete(s.token)
	ns := a.sess.Create(true)
	setSessionCookie(w, r, ns)
	writeJSON(w, http.StatusOK, M{"csrf": ns.csrf})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request, s session) {
	ip := clientIP(r)
	if ok, wait := a.lim.Check(ip); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("Muitas tentativas. Tente novamente em %d min.", int(wait.Minutes())+1))
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	cfg, ok := a.store.Snapshot()
	if !ok {
		writeErr(w, http.StatusConflict, "Nenhuma senha definida ainda.")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(in.Password)) != nil {
		a.lim.Fail(ip)
		writeErr(w, http.StatusUnauthorized, "Senha incorreta.")
		return
	}
	a.lim.Reset(ip)
	a.sess.Delete(s.token) // nova sessão após o login (evita fixação de sessão)
	ns := a.sess.Create(true)
	setSessionCookie(w, r, ns)
	writeJSON(w, http.StatusOK, M{"csrf": ns.csrf})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request, s session) {
	a.sess.Delete(s.token)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, M{"ok": true})
}

// ---------- wizard: RouterBoard ----------

type rosInput struct {
	HTTPS     bool   `json:"https"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	Password  string `json:"password"`
	VerifyTLS bool   `json:"verifyTLS"`
}

func (in rosInput) conf() (RosConf, error) {
	c := RosConf{
		HTTPS:     in.HTTPS,
		Host:      strings.TrimSpace(in.Host),
		Port:      in.Port,
		User:      strings.TrimSpace(in.User),
		Password:  in.Password,
		VerifyTLS: in.VerifyTLS,
	}
	switch {
	case !validHost(c.Host):
		return c, errors.New("Host inválido. Informe um IP ou nome, sem porta nem http://.")
	case c.Port < 1 || c.Port > 65535:
		return c, errors.New("Porta inválida.")
	case c.User == "" || len(c.User) > 64:
		return c, errors.New("Informe o usuário da RouterBoard.")
	case c.Password == "":
		return c, errors.New("Informe a senha do usuário da RouterBoard.")
	}
	return c, nil
}

// probe confirma que o usuário consegue ler os três recursos que o sistema usa.
func probe(c *Ros) ([]Obj, error) {
	ifs, err := c.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("/interface/wireguard: %w", err)
	}
	if _, err := c.Peers(); err != nil {
		return nil, fmt.Errorf("/interface/wireguard/peers: %w", err)
	}
	if _, err := c.Addresses(); err != nil {
		return nil, fmt.Errorf("/ip/address: %w", err)
	}
	return ifs, nil
}

func ifaceViews(ifs []Obj) []M {
	out := []M{}
	for _, o := range ifs {
		out = append(out, M{"name": o.S("name"), "listenPort": o.S("listen-port"), "publicKey": o.S("public-key")})
	}
	return out
}

func (a *App) handleRosTest(w http.ResponseWriter, r *http.Request, _ session) {
	if _, ok := a.setupConfig(w); !ok {
		return
	}
	var in rosInput
	if !decode(w, r, &in) {
		return
	}
	rc, err := in.conf()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := NewRos(rc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ifs, err := probe(c)
	if err != nil {
		writeRosErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, M{"ok": true, "interfaces": ifaceViews(ifs)})
}

func (a *App) handleRosSave(w http.ResponseWriter, r *http.Request, _ session) {
	if _, ok := a.setupConfig(w); !ok {
		return
	}
	var in rosInput
	if !decode(w, r, &in) {
		return
	}
	rc, err := in.conf()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := NewRos(rc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := probe(c); err != nil { // só grava se a conexão realmente funciona
		writeRosErr(w, err)
		return
	}
	err = a.store.Mutate(func(cfg *Config, exists bool) error {
		if !exists || cfg.SetupDone {
			return errors.New("estado inválido")
		}
		cfg.Ros = &rc
		return nil
	})
	if err != nil {
		log.Printf("gravar config: %v", err)
		writeErr(w, http.StatusInternalServerError, "Não foi possível gravar a configuração em /data.")
		return
	}
	writeJSON(w, http.StatusOK, M{"ok": true})
}

func (a *App) handleSetupInterfaces(w http.ResponseWriter, r *http.Request, _ session) {
	cfg, ok := a.setupConfig(w)
	if !ok {
		return
	}
	if cfg.Ros == nil {
		writeErr(w, http.StatusConflict, "Configure a conexão com a RouterBoard primeiro.")
		return
	}
	c, err := NewRos(*cfg.Ros)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ifs, err := c.Interfaces()
	if err != nil {
		writeRosErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, M{"interfaces": ifaceViews(ifs)})
}

// ---------- wizard: servidor WireGuard ----------

type wgInput struct {
	Adopt      bool   `json:"adopt"`
	Iface      string `json:"iface"`
	ListenPort int    `json:"listenPort"`
	Subnet     string `json:"subnet"`
	ServerIP   string `json:"serverIP"`
	Endpoint   string `json:"endpoint"`
	DNS        string `json:"dns"`
	AllowedIPs string `json:"allowedIPs"`
}

func (a *App) handleWgSetup(w http.ResponseWriter, r *http.Request, _ session) {
	cfg, ok := a.setupConfig(w)
	if !ok {
		return
	}
	if cfg.Ros == nil {
		writeErr(w, http.StatusConflict, "Configure a conexão com a RouterBoard primeiro.")
		return
	}
	var in wgInput
	if !decode(w, r, &in) {
		return
	}
	in.Iface = strings.TrimSpace(in.Iface)
	if !ifaceRe.MatchString(in.Iface) {
		writeErr(w, http.StatusBadRequest, "Nome de interface inválido (até 15 caracteres: letras, números, _ . -).")
		return
	}
	sub, err := parseSubnet(in.Subnet)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sip, err := netip.ParseAddr(strings.TrimSpace(in.ServerIP))
	if err != nil || !sip.Is4() || !sub.Contains(sip) || sip == sub.Addr() || sip == broadcast(sub) {
		writeErr(w, http.StatusBadRequest, "O IP do servidor deve estar dentro da sub-rede e não pode ser o endereço de rede nem o de broadcast.")
		return
	}
	endpoint := strings.TrimSpace(in.Endpoint)
	if !validHost(endpoint) {
		writeErr(w, http.StatusBadRequest, "Endpoint público inválido. Informe um IP ou nome DDNS, sem porta.")
		return
	}
	dns, err := normAddrList(in.DNS, false)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	allowed, err := normPrefixList(in.AllowedIPs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ros, err := NewRos(*cfg.Ros)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ifs, err := ros.Interfaces()
	if err != nil {
		writeRosErr(w, err)
		return
	}
	addrs, err := ros.Addresses()
	if err != nil {
		writeRosErr(w, err)
		return
	}

	var found Obj
	for _, o := range ifs {
		if o.S("name") == in.Iface {
			found = o
		}
	}
	port := in.ListenPort
	if in.Adopt {
		if found == nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("A interface %q não existe na RouterBoard.", in.Iface))
			return
		}
		p, _ := strconv.Atoi(found.S("listen-port"))
		if p < 1 {
			writeErr(w, http.StatusBadGateway, "Não foi possível ler a listen-port da interface escolhida.")
			return
		}
		port = p
	} else {
		if found != nil {
			writeErr(w, http.StatusConflict, "Já existe uma interface com esse nome. Use a opção de adotar interface existente.")
			return
		}
		if port < 1 || port > 65535 {
			writeErr(w, http.StatusBadRequest, "Listen-port inválida.")
			return
		}
		for _, o := range ifs {
			if o.S("listen-port") == strconv.Itoa(port) {
				writeErr(w, http.StatusConflict, fmt.Sprintf("A porta %d já é usada pela interface %s.", port, o.S("name")))
				return
			}
		}
	}

	hasIP := false
	for _, o := range addrs {
		p, err := netip.ParsePrefix(o.S("address"))
		if err != nil || p.Addr() != sip {
			continue
		}
		if in.Adopt && o.S("interface") == in.Iface {
			hasIP = true
		} else {
			writeErr(w, http.StatusConflict, fmt.Sprintf("O IP %s já está em uso na interface %s.", sip, o.S("interface")))
			return
		}
	}

	if !in.Adopt {
		if err := ros.CreateInterface(in.Iface, port); err != nil {
			writeRosErr(w, err)
			return
		}
	}
	if !hasIP {
		if err := ros.CreateAddress(fmt.Sprintf("%s/%d", sip, sub.Bits()), in.Iface); err != nil {
			if !in.Adopt { // desfaz a interface recém-criada
				if now, e := ros.Interfaces(); e == nil {
					for _, o := range now {
						if o.S("name") == in.Iface {
							_ = ros.DeleteInterface(o.S(".id"))
						}
					}
				}
			}
			writeRosErr(w, err)
			return
		}
	}

	pub := ""
	if now, e := ros.Interfaces(); e == nil {
		for _, o := range now {
			if o.S("name") == in.Iface {
				pub = o.S("public-key")
			}
		}
	}

	err = a.store.Mutate(func(c *Config, exists bool) error {
		if !exists || c.SetupDone {
			return errors.New("estado inválido")
		}
		c.Wg = &WgConf{
			Iface: in.Iface, ListenPort: port, Subnet: sub.String(), ServerIP: sip.String(),
			Endpoint: endpoint, DNS: dns, AllowedIPs: allowed,
		}
		c.SetupDone = true
		return nil
	})
	if err != nil {
		log.Printf("gravar config: %v", err)
		writeErr(w, http.StatusInternalServerError, "A RouterBoard foi configurada, mas não foi possível gravar a configuração em /data.")
		return
	}
	fw := fmt.Sprintf("/ip firewall filter add chain=input action=accept protocol=udp dst-port=%d comment=\"wg-manager: WireGuard\" place-before=0\n"+
		"/ip firewall nat add chain=srcnat action=masquerade src-address=%s comment=\"wg-manager: internet para os peers\"", port, sub)
	writeJSON(w, http.StatusOK, M{"firewall": fw, "publicKey": pub, "iface": in.Iface, "listenPort": port})
}

// ---------- peers ----------

func (a *App) handlePeers(w http.ResponseWriter, r *http.Request, _ session) {
	cfg, ros, ok := a.readyConfig(w)
	if !ok {
		return
	}
	peers, err := ros.Peers()
	if err != nil {
		writeRosErr(w, err)
		return
	}
	out := []M{}
	for _, p := range peers {
		if p.S("interface") != cfg.Wg.Iface {
			continue
		}
		out = append(out, M{
			"id":            p.S(".id"),
			"name":          p.S("comment"),
			"publicKey":     p.S("public-key"),
			"address":       p.S("allowed-address"),
			"lastHandshake": p.S("last-handshake"),
			"rx":            p.S("rx"),
			"tx":            p.S("tx"),
			"disabled":      p.S("disabled") == "true",
		})
	}
	writeJSON(w, http.StatusOK, M{"iface": cfg.Wg.Iface, "endpoint": cfg.Wg.Endpoint, "port": cfg.Wg.ListenPort, "peers": out})
}

func (a *App) handlePeerCreate(w http.ResponseWriter, r *http.Request, _ session) {
	var in struct {
		Name      string `json:"name"`
		IP        string `json:"ip"`
		Keepalive int    `json:"keepalive"`
		PSK       bool   `json:"psk"`
	}
	if !decode(w, r, &in) {
		return
	}
	name, err := cleanName(in.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Keepalive < 0 || in.Keepalive > 65535 {
		writeErr(w, http.StatusBadRequest, "Keepalive deve estar entre 0 e 65535 segundos.")
		return
	}

	a.peerMu.Lock()
	defer a.peerMu.Unlock()

	cfg, ros, ok := a.readyConfig(w)
	if !ok {
		return
	}
	sub, err := parseSubnet(cfg.Wg.Subnet)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Sub-rede salva é inválida.")
		return
	}
	sip, err := netip.ParseAddr(cfg.Wg.ServerIP)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "IP do servidor salvo é inválido.")
		return
	}

	// Consulta a RB: interface (chave pública do servidor), peers e endereços.
	ifs, err := ros.Interfaces()
	if err != nil {
		writeRosErr(w, err)
		return
	}
	serverPub := ""
	for _, o := range ifs {
		if o.S("name") == cfg.Wg.Iface {
			serverPub = o.S("public-key")
		}
	}
	if serverPub == "" {
		writeErr(w, http.StatusBadGateway, "Não foi possível ler a public-key da interface "+cfg.Wg.Iface+" na RouterBoard.")
		return
	}
	peers, err := ros.Peers()
	if err != nil {
		writeRosErr(w, err)
		return
	}
	addrs, err := ros.Addresses()
	if err != nil {
		writeRosErr(w, err)
		return
	}
	u := collectUsage(peers, addrs, sip)

	var ip netip.Addr
	if s := strings.TrimSpace(in.IP); s != "" {
		ip, err = netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			writeErr(w, http.StatusBadRequest, "IP inválido. Informe só o endereço IPv4, por exemplo 10.8.0.5.")
			return
		}
		if !sub.Contains(ip) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("O IP %s está fora da sub-rede %s.", ip, sub))
			return
		}
		if ip == sub.Addr() || ip == broadcast(sub) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("O IP %s é o endereço de rede ou de broadcast da sub-rede.", ip))
			return
		}
		if why, used := u.inUse(ip); used {
			writeErr(w, http.StatusConflict, fmt.Sprintf("O IP %s já está em uso (%s).", ip, why))
			return
		}
	} else {
		free, found := nextFree(sub, u)
		if !found {
			writeErr(w, http.StatusConflict, fmt.Sprintf("Não há IPs livres na sub-rede %s.", sub))
			return
		}
		ip = free
	}

	priv, pub, err := genKeypair()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Falha ao gerar as chaves.")
		return
	}
	body := Obj{
		"interface":       cfg.Wg.Iface,
		"public-key":      pub,
		"allowed-address": ip.String() + "/32",
		"comment":         name,
	}
	psk := ""
	if in.PSK {
		if psk, err = genPSK(); err != nil {
			writeErr(w, http.StatusInternalServerError, "Falha ao gerar a preshared key.")
			return
		}
		body["preshared-key"] = psk
	}
	if err := ros.CreatePeer(body); err != nil {
		writeRosErr(w, err)
		return
	}

	conf := buildConf(priv, ip.String(), sub.Bits(), cfg.Wg.DNS, serverPub, psk,
		cfg.Wg.Endpoint, cfg.Wg.ListenPort, cfg.Wg.AllowedIPs, in.Keepalive)
	// A chave privada só existe nesta resposta: nada dela é gravado ou registrado.
	writeJSON(w, http.StatusCreated, M{"conf": conf, "filename": safeFilename(name) + ".conf", "address": ip.String()})
}

// ownedPeer valida o id e garante que o peer pertence à interface gerenciada.
func (a *App) ownedPeer(w http.ResponseWriter, r *http.Request) (string, *Ros, bool) {
	cfg, ros, ok := a.readyConfig(w)
	if !ok {
		return "", nil, false
	}
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "ID de peer inválido.")
		return "", nil, false
	}
	p, err := ros.Peer(id)
	if err != nil {
		writeRosErr(w, err)
		return "", nil, false
	}
	if p.S("interface") != cfg.Wg.Iface {
		writeErr(w, http.StatusNotFound, "Peer não encontrado.")
		return "", nil, false
	}
	return id, ros, true
}

func (a *App) handlePeerToggle(w http.ResponseWriter, r *http.Request, _ session) {
	var in struct {
		Disabled bool `json:"disabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, ros, ok := a.ownedPeer(w, r)
	if !ok {
		return
	}
	if err := ros.SetPeerDisabled(id, in.Disabled); err != nil {
		writeRosErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, M{"ok": true})
}

func (a *App) handlePeerDelete(w http.ResponseWriter, r *http.Request, _ session) {
	id, ros, ok := a.ownedPeer(w, r)
	if !ok {
		return
	}
	if err := ros.DeletePeer(id); err != nil {
		writeRosErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, M{"ok": true})
}
