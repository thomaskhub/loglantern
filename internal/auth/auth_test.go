package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomkin/loglantern/internal/config"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func writePub(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "pub.pem")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	return p
}

func sign(t *testing.T, alg string, key crypto.Signer, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	var sig []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		d := sha256.Sum256([]byte(in))
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	case *ecdsa.PrivateKey:
		d := sha256.Sum256([]byte(in))
		r, s, e := ecdsa.Sign(rand.Reader, k, d[:])
		err = e
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(in))
	}
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAuth(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, dk, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	roles := map[string][]config.ClaimMatch{
		config.RoleLogs:   {{Claim: "permissions.admin", Equals: true}, {Claim: "groups", Equals: "dev"}},
		config.RoleViewer: {{Claim: "permissions.media", Equals: true}},
	}
	cfg := &config.Config{
		Envs: map[string]config.Env{"uat": {}, "prod": {}},
		Auth: config.Auth{
			APIKeys: []config.APIKey{{Name: "board", KeyEnv: "K", Role: config.RoleViewer, Envs: []string{"prod"}}},
			JWT: []config.JWTKey{
				{Name: "app", PublicKeyFile: writePub(t, &rk.PublicKey), Roles: roles},
				{Name: "ec", PublicKeyFile: writePub(t, &ek.PublicKey), Envs: []string{"uat"}, Roles: roles},
				{Name: "ed", PublicKeyFile: writePub(t, dk.Public()), Roles: roles},
			},
		},
		Secrets: map[string]string{"K": "0123456789abcdefXYZ"},
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return now }
	exp := float64(now.Add(time.Hour).Unix())

	p, err := a.Check("0123456789abcdefXYZ")
	if err != nil || p.Role != "viewer" || len(p.Envs) != 1 || p.Envs[0] != "prod" {
		t.Fatalf("U1 api key: %+v %v", p, err)
	}
	if _, err := a.Check("0123456789abcdefXYz"); err == nil {
		t.Fatal("U1 wrong key accepted")
	}
	p, err = a.Check(sign(t, "RS256", rk, map[string]any{"sub": "u1", "exp": exp, "permissions": map[string]any{"admin": true}}))
	if err != nil || p.Role != "logs" || p.Name != "app:u1" || len(p.Envs) != 2 {
		t.Fatalf("U2 RS256 admin -> logs, all envs: %+v %v", p, err)
	}
	p, err = a.Check(sign(t, "RS256", rk, map[string]any{"exp": exp, "permissions": map[string]any{"admin": true, "media": true}}))
	if err != nil || p.Role != "logs" {
		t.Fatalf("U2 both roles match -> highest wins: %+v %v", p, err)
	}
	p, err = a.Check(sign(t, "ES256", ek, map[string]any{"exp": exp, "permissions": map[string]any{"media": true}}))
	if err != nil || p.Role != "viewer" || p.Envs[0] != "uat" {
		t.Fatalf("U3 ES256 viewer, env restricted: %+v %v", p, err)
	}
	p, err = a.Check(sign(t, "EdDSA", dk, map[string]any{"exp": exp, "groups": []any{"x", "dev"}}))
	if err != nil || p.Role != "logs" {
		t.Fatalf("U4 EdDSA array claim: %+v %v", p, err)
	}
	for name, tok := range map[string]string{
		"no role":     sign(t, "RS256", rk, map[string]any{"exp": exp, "permissions": map[string]any{"admin": false}}),
		"expired":     sign(t, "RS256", rk, map[string]any{"exp": float64(now.Add(-2 * time.Minute).Unix()), "permissions": map[string]any{"admin": true}}),
		"no exp":      sign(t, "RS256", rk, map[string]any{"permissions": map[string]any{"admin": true}}),
		"not yet":     sign(t, "RS256", rk, map[string]any{"exp": exp, "nbf": float64(now.Add(5 * time.Minute).Unix()), "permissions": map[string]any{"admin": true}}),
		"other key":   sign(t, "RS256", other, map[string]any{"exp": exp, "permissions": map[string]any{"admin": true}}),
		"alg confuse": sign(t, "ES256", rk, map[string]any{"exp": exp, "permissions": map[string]any{"admin": true}}),
		"garbage":     "a.b.c",
	} {
		if _, err := a.Check(tok); err == nil {
			t.Errorf("U5 %s accepted", name)
		}
	}
	// alg none
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	c := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":9999999999,"permissions":{"admin":true}}`))
	if _, err := a.Check(h + "." + c + "."); err == nil {
		t.Error("U5 alg none accepted")
	}
	if got := (Principal{Envs: []string{"uat"}}).Allowed([]string{"prod", "uat"}); len(got) != 1 || got[0] != "uat" {
		t.Errorf("U6 allowed: %v", got)
	}
}

func TestShortKey(t *testing.T) {
	cfg := &config.Config{Auth: config.Auth{APIKeys: []config.APIKey{{Name: "x", KeyEnv: "K", Role: "viewer"}}}, Secrets: map[string]string{"K": "short"}}
	if _, err := New(cfg); err == nil {
		t.Fatal("short key accepted")
	}
}
