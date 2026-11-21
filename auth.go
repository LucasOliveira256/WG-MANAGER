package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	cookieName  = "wgm_session"
	authedTTL   = 12 * time.Hour
	anonTTL     = 30 * time.Minute
	maxSessions = 2000

	loginMaxFails = 5
	loginWindow   = 15 * time.Minute
	loginBlock    = 15 * time.Minute
	maxTracked    = 10000
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // sem entropia: não há como continuar com segurança
	}
	return hex.EncodeToString(b)
}

// ---------- sessões (em memória; reiniciar o container desloga todos) ----------

type session struct {
	token   string
	csrf    string
	authed  bool
	expires time.Time
}

type Sessions struct {
	mu sync.Mutex
	m  map[string]session
}

func NewSessions() *Sessions {
	s := &Sessions{m: map[string]session{}}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		for range t.C {
			s.mu.Lock()
			s.pruneLocked(false)
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *Sessions) pruneLocked(dropAnon bool) {
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) || (dropAnon && !v.authed) {
			delete(s.m, k)
		}
	}
}

func (s *Sessions) Create(authed bool) session {
	ttl := anonTTL
	if authed {
		ttl = authedTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= maxSessions {
		s.pruneLocked(false)
		if len(s.m) >= maxSessions {
			s.pruneLocked(true)
		}
	}
	sess := session{token: randHex(32), csrf: randHex(32), authed: authed, expires: time.Now().Add(ttl)}
	s.m[sess.token] = sess
	return sess
}

func (s *Sessions) Get(token string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok {
		return session{}, false
	}
	if time.Now().After(sess.expires) {
		delete(s.m, token)
		return session{}, false
	}
	return sess, true
}

func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, s session) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.token,
		Path:     "/",
		Expires:  s.expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil, // o container serve HTTP simples; Secure quebraria o cookie na LAN
	})
}

func csrfOK(r *http.Request, s session) bool {
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf)) == 1
}

// ---------- limite de tentativas de login por IP ----------

type attempt struct {
	fails        int
	first        time.Time
	blockedUntil time.Time
}

type Limiter struct {
	mu sync.Mutex
	m  map[string]*attempt
}

func NewLimiter() *Limiter {
	l := &Limiter{m: map[string]*attempt{}}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		for range t.C {
			now := time.Now()
			l.mu.Lock()
			for k, a := range l.m {
				if now.Sub(a.first) > loginWindow && now.After(a.blockedUntil) {
					delete(l.m, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

// Check informa se o IP pode tentar login agora e, se não, quanto falta.
func (l *Limiter) Check(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	if a == nil {
		return true, 0
	}
	if now := time.Now(); now.Before(a.blockedUntil) {
		return false, a.blockedUntil.Sub(now)
	}
	return true, 0
}

func (l *Limiter) Fail(ip string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > maxTracked {
		l.m = map[string]*attempt{}
	}
	a := l.m[ip]
	if a == nil || now.Sub(a.first) > loginWindow {
		a = &attempt{first: now}
		l.m[ip] = a
	}
	a.fails++
	if a.fails >= loginMaxFails {
		a.blockedUntil = now.Add(loginBlock)
		a.fails = 0
		a.first = now
	}
}

func (l *Limiter) Reset(ip string) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}

// clientIP usa só o endereço da conexão. X-Forwarded-For não é confiável aqui.
func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
