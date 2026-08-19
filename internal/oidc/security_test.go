package oidc_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// forge builds a token with an arbitrary header and signature, which oidctest
// cannot produce because it only ever signs correctly.
func forge(t *testing.T, header map[string]any, claims map[string]any, sign func(signingInput string) string) string {
	t.Helper()

	encode := func(v map[string]any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshaling segment: %v", err)
		}

		return base64.RawURLEncoding.EncodeToString(b)
	}

	signingInput := encode(header) + "." + encode(claims)

	return signingInput + "." + sign(signingInput)
}

// attackClaims are claims that would be accepted if the signature check passed,
// so each test below fails only on the property it is meant to check.
func attackClaims(issuerURL string) map[string]any {
	return map[string]any{
		"aud":               "https://proxy.example.com",
		"exp":               time.Now().Add(time.Hour).Unix(),
		"iat":               time.Now().Unix(),
		"iss":               issuerURL,
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
		"sub":               "attacker",
	}
}

// TestVerifyRejectsUnsignedToken covers the alg=none downgrade: a token with no
// signature at all, whose claims would otherwise be accepted.
func TestVerifyRejectsUnsignedToken(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	token := forge(t,
		map[string]any{"alg": "none", "typ": "JWT"},
		attackClaims(issuer.URL()),
		func(string) string { return "" },
	)

	if _, err := verifier.Verify(t.Context(), token); err == nil {
		t.Fatal("Verify() error = nil, want an unsigned token to be rejected")
	}
}

// TestVerifyRejectsSymmetricAlgorithm covers algorithm confusion: an attacker
// who knows the provider's public key signs with it as an HMAC secret, hoping
// the verifier treats a symmetric algorithm as acceptable.
func TestVerifyRejectsSymmetricAlgorithm(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	token := forge(t,
		map[string]any{"alg": "HS256", "kid": "test-key", "typ": "JWT"},
		attackClaims(issuer.URL()),
		func(signingInput string) string {
			mac := hmac.New(sha256.New, []byte("the provider's public key"))
			mac.Write([]byte(signingInput))

			return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		},
	)

	if _, err := verifier.Verify(t.Context(), token); err == nil {
		t.Fatal("Verify() error = nil, want a symmetrically signed token to be rejected")
	}
}

// TestVerifyRejectsClaimsSwappedAfterSigning covers a token whose payload has
// been replaced with one naming a different tenant, leaving the signature over
// the original payload.
func TestVerifyRejectsClaimsSwappedAfterSigning(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	signed := issuer.Sign(t, map[string]any{
		"organization_slug": "someone-else",
		"pipeline_slug":     "deploy-api",
	})

	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d segments, want 3", len(parts))
	}

	swapped, err := json.Marshal(attackClaims(issuer.URL()))
	if err != nil {
		t.Fatalf("marshaling claims: %v", err)
	}

	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(swapped) + "." + parts[2]

	if _, err := verifier.Verify(t.Context(), tampered); err == nil {
		t.Fatal("Verify() error = nil, want a swapped payload to be rejected")
	}
}

// TestVerifyRejectsUnknownKeyID covers a token naming a key the provider does
// not publish, which must not cause the key set to be trusted or bypassed.
func TestVerifyRejectsUnknownKeyID(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	token := forge(t,
		map[string]any{"alg": "RS256", "kid": "attacker-key", "typ": "JWT"},
		attackClaims(issuer.URL()),
		func(string) string { return base64.RawURLEncoding.EncodeToString([]byte("not a signature")) },
	)

	if _, err := verifier.Verify(t.Context(), token); err == nil {
		t.Fatal("Verify() error = nil, want an unknown key ID to be rejected")
	}
}

// TestVerifyDoesNotLogTheCredential is a guard against the token reaching a log
// line. The helper logs verification errors, and an error that embedded the
// credential would put a live bearer token in the proxy's logs.
func TestVerifyDoesNotLogTheCredential(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	token := issuer.Sign(t, map[string]any{
		"exp":               time.Now().Add(-time.Hour).Unix(),
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})

	_, err := verifier.Verify(t.Context(), token)
	if err == nil {
		t.Fatal("Verify() error = nil, want the expired token to be rejected")
	}

	// The signature is the part that must never be quoted back, and it is the
	// longest opaque segment, so look for it specifically as well as the whole.
	signature := token[strings.LastIndexByte(token, '.')+1:]

	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), signature) {
		t.Errorf("Verify() error = %v, want it not to contain the credential", err)
	}
}
