package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// ---------- chaves ----------

// genKeypair gera um par Curve25519 no formato do WireGuard (base64).
func genKeypair() (priv, pub string, err error) {
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", err
	}
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	k, err := ecdh.X25519().NewPrivateKey(b[:])
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func genPSK() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// ---------- validações ----------

func validHost(h string) bool {
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return hostRe.MatchString(h)
}

func parseSubnet(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("Sub-rede inválida. Use IPv4 com máscara, por exemplo 10.8.0.0/24.")
	}
	if p.Bits() < 8 || p.Bits() > 30 {
		return netip.Prefix{}, errors.New("A máscara da sub-rede deve estar entre /8 e /30.")
	}
	return p.Masked(), nil
}

// broadcast devolve o último endereço da sub-rede IPv4.
func broadcast(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(a[:]) | ((uint32(1) << uint(32-p.Bits())) - 1)
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

func normAddrList(s string, required bool) (string, error) {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return "", fmt.Errorf("Endereço IP inválido: %q.", part)
		}
		out = append(out, a.String())
	}
	if required && len(out) == 0 {
		return "", errors.New("Informe ao menos um endereço IP.")
	}
	return strings.Join(out, ", "), nil
}

func normPrefixList(s string) (string, error) {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return "", fmt.Errorf("AllowedIPs inválido: %q (use CIDR, ex.: 0.0.0.0/0).", part)
		}
		out = append(out, p.String())
	}
	if len(out) == 0 {
		return "", errors.New("Informe ao menos um valor de AllowedIPs (ex.: 0.0.0.0/0).")
	}
	return strings.Join(out, ", "), nil
}

func cleanName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("Informe o nome do peer.")
	}
	if utf8.RuneCountInString(s) > 64 {
		return "", errors.New("O nome do peer pode ter no máximo 64 caracteres.")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", errors.New("O nome do peer contém caracteres inválidos.")
		}
	}
	return s, nil
}

// safeFilename gera um nome de arquivo ASCII com até 15 caracteres
// (o cliente WireGuard para Windows usa o nome do arquivo como nome do túnel).
func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		out = "peer"
	}
	if len(out) > 15 {
		out = out[:15]
	}
	return out
}

// ---------- IPs em uso ----------

type usedPrefix struct {
	p   netip.Prefix
	why string
}

type usage struct {
	addrs    map[netip.Addr]string
	prefixes []usedPrefix
}

func (u *usage) inUse(ip netip.Addr) (string, bool) {
	if why, ok := u.addrs[ip]; ok {
		return why, true
	}
	for _, up := range u.prefixes {
		if up.p.Contains(ip) {
			return up.why, true
		}
	}
	return "", false
}

// collectUsage junta o IP do servidor, os endereços de /ip/address e os
// allowed-address de todos os peers (de qualquer interface WireGuard).
func collectUsage(peers, addrs []Obj, server netip.Addr) *usage {
	u := &usage{addrs: map[netip.Addr]string{server: "IP do servidor WireGuard"}}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.S("address"))
		if err != nil || !p.Addr().Is4() {
			continue
		}
		if _, ok := u.addrs[p.Addr()]; !ok {
			u.addrs[p.Addr()] = "endereço da RouterBoard na interface " + a.S("interface")
		}
	}
	for _, pr := range peers {
		why := "peer sem nome"
		if c := pr.S("comment"); c != "" {
			why = "peer \"" + c + "\""
		}
		for _, part := range strings.Split(pr.S("allowed-address"), ",") {
			part = strings.TrimSpace(part)
			p, err := netip.ParsePrefix(part)
			if err != nil {
				ip, err2 := netip.ParseAddr(part)
				if err2 != nil {
					continue
				}
				p = netip.PrefixFrom(ip, ip.BitLen())
			}
			if !p.Addr().Is4() || p.Bits() == 0 { // ignora rota padrão 0.0.0.0/0
				continue
			}
			u.prefixes = append(u.prefixes, usedPrefix{p: p, why: why})
		}
	}
	return u
}

// nextFree devolve o primeiro IP livre entre o endereço de rede e o de broadcast.
func nextFree(sub netip.Prefix, u *usage) (netip.Addr, bool) {
	bc := broadcast(sub)
	for a := sub.Addr().Next(); a.IsValid() && a.Less(bc); a = a.Next() {
		if _, used := u.inUse(a); !used {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// ---------- arquivo .conf do cliente ----------

func buildConf(priv, addr string, bits int, dns, serverPub, psk, endpoint string, port int, allowed string, keepalive int) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	fmt.Fprintf(&b, "Address = %s/%d\n", addr, bits)
	if dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPub)
	if psk != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", net.JoinHostPort(endpoint, strconv.Itoa(port)))
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	if keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)
	}
	return b.String()
}
