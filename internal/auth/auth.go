// Package auth checks API keys and JWTs (RS256, ES256, EdDSA) and maps them to a role and environments.
package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/thomaskhub/loglantern/internal/config"
)

// Principal is an authenticated caller.
type Principal struct {
	Name    string   `json:"name"`
	Role    string   `json:"role"`     // viewer | logs
	Envs    []string `json:"envs"`     // environments the caller may see
	AllEnvs bool     `json:"all_envs"` // every configured environment (may manage env-less silences)
}

// CanSeeLogs reports whether log lines are allowed.
func (p Principal) CanSeeLogs() bool { return p.Role == config.RoleLogs || p.Role == config.RoleAdmin }

// CanSilence reports whether the caller may manage silences.
func (p Principal) CanSilence() bool { return p.Role == config.RoleAdmin }

// Allowed narrows requested envs to permitted ones (all permitted when none requested).
func (p Principal) Allowed(requested []string) []string {
	if len(requested) == 0 {
		return slices.Clone(p.Envs)
	}
	var out []string
	for _, e := range requested {
		if slices.Contains(p.Envs, e) {
			out = append(out, e)
		}
	}
	return out
}

// Errors.
var (
	ErrNoToken   = errors.New("no token")
	ErrForbidden = errors.New("token not valid")
)

type apiKey struct {
	key []byte
	p   Principal
}

type jwtKey struct {
	name  string
	pub   crypto.PublicKey
	envs  []string
	all   bool
	roles map[string][]config.ClaimMatch
}

// Auth verifies callers.
type Auth struct {
	keys []apiKey
	jwts []jwtKey
	Now  func() time.Time
}

// New loads keys from config; empty envs in config mean all configured environments.
func New(cfg *config.Config) (*Auth, error) {
	var all []string
	for e := range cfg.Envs {
		all = append(all, e)
	}
	slices.Sort(all)
	envs := func(list []string) ([]string, bool) {
		if len(list) == 0 {
			return all, true
		}
		for _, e := range all {
			if !slices.Contains(list, e) {
				return list, false
			}
		}
		return list, true
	}
	a := &Auth{Now: time.Now}
	for _, k := range cfg.Auth.APIKeys {
		v := cfg.Secret(k.KeyEnv)
		if len(v) < 16 {
			return nil, fmt.Errorf("auth: api key %s shorter than 16 characters", k.Name)
		}
		es, every := envs(k.Envs)
		a.keys = append(a.keys, apiKey{[]byte(v), Principal{Name: k.Name, Role: k.Role, Envs: es, AllEnvs: every}})
	}
	for _, j := range cfg.Auth.JWT {
		b, err := os.ReadFile(j.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("auth: %s: %w", j.Name, err)
		}
		pub, err := ParsePublicKey(b)
		if err != nil {
			return nil, fmt.Errorf("auth: %s: %w", j.Name, err)
		}
		es, every := envs(j.Envs)
		a.jwts = append(a.jwts, jwtKey{name: j.Name, pub: pub, envs: es, all: every, roles: j.Roles})
	}
	return a, nil
}

// ParsePublicKey reads a PEM public key or certificate (RSA, ECDSA P-256, Ed25519).
func ParsePublicKey(b []byte) (crypto.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	var pub any
	var err error
	switch blk.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(blk.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(blk.Bytes)
	case "CERTIFICATE":
		var c *x509.Certificate
		if c, err = x509.ParseCertificate(blk.Bytes); err == nil {
			pub = c.PublicKey
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", blk.Type)
	}
	if err != nil {
		return nil, err
	}
	switch k := pub.(type) {
	case *rsa.PublicKey, ed25519.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		if k.Curve.Params().Name != "P-256" {
			return nil, errors.New("only P-256 ECDSA keys are supported")
		}
		return k, nil
	}
	return nil, fmt.Errorf("unsupported key type %T", pub)
}

// Token returns the bearer token of a request; query access_token only when allowQuery (EventSource cannot set headers).
func Token(r *http.Request, allowQuery bool) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if allowQuery {
		return r.URL.Query().Get("access_token")
	}
	return ""
}

// Check verifies a token.
func (a *Auth) Check(tok string) (Principal, error) {
	if tok == "" {
		return Principal{}, ErrNoToken
	}
	if strings.Count(tok, ".") == 2 {
		return a.checkJWT(tok)
	}
	var found *Principal
	for i := range a.keys {
		if subtle.ConstantTimeCompare([]byte(tok), a.keys[i].key) == 1 {
			found = &a.keys[i].p
		}
	}
	if found == nil {
		return Principal{}, ErrForbidden
	}
	return *found, nil
}

const leeway = time.Minute

func (a *Auth) checkJWT(tok string) (Principal, error) {
	parts := strings.Split(tok, ".")
	var hdr struct {
		Alg string `json:"alg"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return Principal{}, ErrForbidden
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Principal{}, ErrForbidden
	}
	signed := []byte(parts[0] + "." + parts[1])
	var key *jwtKey
	for i := range a.jwts {
		if verify(hdr.Alg, a.jwts[i].pub, signed, sig) {
			key = &a.jwts[i]
			break
		}
	}
	if key == nil {
		return Principal{}, ErrForbidden
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Principal{}, ErrForbidden
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return Principal{}, ErrForbidden
	}
	now := a.Now()
	exp, ok := claims["exp"].(float64)
	if !ok || now.After(time.Unix(int64(exp), 0).Add(leeway)) {
		return Principal{}, ErrForbidden // exp is required
	}
	if nbf, ok := claims["nbf"].(float64); ok && now.Add(leeway).Before(time.Unix(int64(nbf), 0)) {
		return Principal{}, ErrForbidden
	}
	role := ""
	for _, r := range config.Roles { // highest first
		if slices.ContainsFunc(key.roles[r], func(m config.ClaimMatch) bool { return matches(claims, m) }) {
			role = r
			break
		}
	}
	if role == "" {
		return Principal{}, ErrForbidden
	}
	name, _ := claims["sub"].(string)
	return Principal{Name: key.name + ":" + name, Role: role, Envs: key.envs, AllEnvs: key.all}, nil
}

// verify checks a signature; the algorithm must fit the key type (no algorithm confusion, no "none").
func verify(alg string, pub crypto.PublicKey, signed, sig []byte) bool {
	h := sha256.Sum256(signed)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" && rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return false
		}
		return ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case ed25519.PublicKey:
		return alg == "EdDSA" && ed25519.Verify(k, signed, sig)
	}
	return false
}

// matches looks up a dot-separated claim path; arrays match if any element equals.
func matches(claims map[string]any, m config.ClaimMatch) bool {
	var v any = claims
	for _, p := range strings.Split(m.Claim, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return false
		}
		if v, ok = obj[p]; !ok {
			return false
		}
	}
	want := fmt.Sprint(m.Equals)
	if arr, ok := v.([]any); ok {
		return slices.ContainsFunc(arr, func(x any) bool { return fmt.Sprint(x) == want })
	}
	return fmt.Sprint(v) == want
}
