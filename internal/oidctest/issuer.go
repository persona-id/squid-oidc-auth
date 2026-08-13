// Package oidctest runs a minimal OIDC provider for tests: a discovery
// document, a JWKS, and a token signer. It exists so the verifier and the
// end-to-end tests can exercise real signature checking without reaching the
// network or embedding a fixture token that expires.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const keyID = "test-key"

// testKey is generated once per process: RSA key generation is slow enough to
// dominate the runtime of a table-driven test otherwise.
var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("oidctest: generating key: " + err.Error())
	}

	return key
})

// Issuer is a running OIDC provider. It shuts down when the test ends.
type Issuer struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

// New starts an issuer and registers its shutdown with t.
func New(t *testing.T) *Issuer {
	t.Helper()

	issuer := &Issuer{key: testKey()}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", issuer.handleDiscovery)
	mux.HandleFunc("/keys", issuer.handleKeys)

	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)

	return issuer
}

// Sign mints a signed RS256 token for claims, filling in iss, aud, exp, iat, and
// sub when the caller has not set them. Pass an explicit value to override any
// default, including an already-past exp.
func (i *Issuer) Sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	full := make(map[string]any, len(claims)+5)
	maps.Copy(full, claims)

	now := time.Now()

	defaults := map[string]any{
		"aud": "https://proxy.example.com",
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"iss": i.URL(),
		"sub": "test-subject",
	}

	for key, value := range defaults {
		if _, ok := full[key]; !ok {
			full[key] = value
		}
	}

	header := encodeSegment(t, map[string]any{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	payload := encodeSegment(t, full)
	signing := header + "." + payload

	digest := sha256.Sum256([]byte(signing))

	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// SignRaw returns a token whose payload is arbitrary bytes, for exercising
// malformed-credential handling.
func (i *Issuer) SignRaw(payload string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

// URL returns the issuer URL, which is also the value of the iss claim.
func (i *Issuer) URL() string {
	return i.server.URL
}

func (i *Issuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"authorization_endpoint":                i.URL() + "/auth",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"issuer":                                i.URL(),
		"jwks_uri":                              i.URL() + "/keys",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"token_endpoint":                        i.URL() + "/token",
	})
}

func (i *Issuer) handleKeys(w http.ResponseWriter, _ *http.Request) {
	public := i.key.Public().(*rsa.PublicKey)

	writeJSON(w, map[string]any{
		"keys": []map[string]any{{
			"alg": "RS256",
			"e":   base64.RawURLEncoding.EncodeToString(big(public.E)),
			"kid": keyID,
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"use": "sig",
		}},
	})
}

// big renders an exponent as the minimal big-endian byte string a JWK expects.
func big(exponent int) []byte {
	var out []byte

	for exponent > 0 {
		out = append([]byte{byte(exponent & 0xff)}, out...)
		exponent >>= 8
	}

	return out
}

func encodeSegment(t *testing.T, value map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding token segment: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(encoded)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic("oidctest: writing response: " + err.Error())
	}
}
