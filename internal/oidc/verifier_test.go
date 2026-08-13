package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/persona-id/squid-oidc-auth/internal/config"
	"github.com/persona-id/squid-oidc-auth/internal/oidc"
	"github.com/persona-id/squid-oidc-auth/internal/oidctest"
)

// newVerifier starts a test issuer and builds a verifier whose single issuer
// entry is rendered from body, with %s replaced by the issuer URL.
func newVerifier(t *testing.T, body string) (*oidc.Verifier, *oidctest.Issuer) {
	t.Helper()

	issuer := oidctest.New(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, fmt.Appendf(nil, body, issuer.URL()), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	verifier, err := oidc.NewVerifier(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}

	return verifier, issuer
}

const issuerConfig = `
issuers:
  ci:
    annotations: [build_branch, pipeline_slug]
    audiences: [https://proxy.example.com]
    issuer: %s
    max_ttl: 2m
    require:
      organization_slug: persona-id
    username_template: "{{.organization_slug}}/{{.pipeline_slug}}"
`

func TestVerify(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	token := issuer.Sign(t, map[string]any{
		"build_branch":      "main",
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})

	result, err := verifier.Verify(t.Context(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if want := "persona-id/deploy-api"; result.Username != want {
		t.Errorf("Username = %q, want %q", result.Username, want)
	}

	if result.Claims["build_branch"] != "main" {
		t.Errorf("Claims[build_branch] = %v, want main", result.Claims["build_branch"])
	}

	if time.Until(result.Expiry) <= 0 {
		t.Errorf("Expiry = %s, want a future time", result.Expiry)
	}

	if result.Issuer.Name != "ci" {
		t.Errorf("Issuer.Name = %q, want ci", result.Issuer.Name)
	}
}

func TestVerifyRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		claims  map[string]any
		wantErr error
	}{
		"wrong organization": {
			claims: map[string]any{
				"organization_slug": "some-other-org",
				"pipeline_slug":     "deploy-api",
			},
			wantErr: oidc.ErrRequirementUnmet,
		},
		"missing required claim": {
			claims:  map[string]any{"pipeline_slug": "deploy-api"},
			wantErr: oidc.ErrRequirementUnmet,
		},
		"wrong audience": {
			claims: map[string]any{
				"aud":               "https://someone-elses-proxy.example.com",
				"organization_slug": "persona-id",
				"pipeline_slug":     "deploy-api",
			},
			wantErr: oidc.ErrAudienceMismatch,
		},
		"expired token": {
			claims: map[string]any{
				"exp":               time.Now().Add(-time.Minute).Unix(),
				"organization_slug": "persona-id",
				"pipeline_slug":     "deploy-api",
			},
			wantErr: nil, // go-oidc returns an unexported expiry error
		},
		"missing username claim": {
			claims:  map[string]any{"organization_slug": "persona-id"},
			wantErr: nil, // template execution error
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier, issuer := newVerifier(t, issuerConfig)

			_, err := verifier.Verify(t.Context(), issuer.Sign(t, tc.claims))
			if err == nil {
				t.Fatal("Verify() error = nil, want an error")
			}

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("Verify() error = %v, want %v", err, tc.wantErr)
			}

			// Whatever the cause, a bad token is the token's problem: reporting
			// it as temporary would make Squid treat a rejection as an outage.
			if oidc.IsTemporary(err) {
				t.Errorf("Verify() error = %v, want a permanent error", err)
			}
		})
	}
}

// TestVerifyRejectsForeignSignature is the case that matters most: a token that
// claims our issuer but was signed by someone else.
func TestVerifyRejectsForeignSignature(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	token := issuer.Sign(t, map[string]any{
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})

	// Alter the first character of the signature. The last character will not
	// do: it carries only two significant bits, and the rest is padding that
	// decodes to the same bytes.
	dot := strings.LastIndexByte(token, '.')

	replacement := byte('A')
	if token[dot+1] == replacement {
		replacement = 'B'
	}

	tampered := token[:dot+1] + string(replacement) + token[dot+2:]

	if _, err := verifier.Verify(t.Context(), tampered); err == nil {
		t.Error("Verify() error = nil, want a signature failure")
	}
}

func TestVerifyUnknownIssuer(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	token := issuer.Sign(t, map[string]any{
		"iss":               "https://attacker.example.com",
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})

	_, err := verifier.Verify(t.Context(), token)
	if !errors.Is(err, oidc.ErrUnknownIssuer) {
		t.Errorf("Verify() error = %v, want %v", err, oidc.ErrUnknownIssuer)
	}
}

func TestVerifyMalformedCredential(t *testing.T) {
	t.Parallel()

	verifier, issuer := newVerifier(t, issuerConfig)

	tests := map[string]string{
		"not a JWT":             "hunter2",
		"two segments":          "header.payload",
		"payload is not base64": "header.!!!.signature",
		"payload is not JSON":   issuer.SignRaw("this is not json"),
		"payload has no iss":    issuer.SignRaw(`{"sub":"x"}`),
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.Verify(t.Context(), token)
			if !errors.Is(err, oidc.ErrMalformedToken) {
				t.Errorf("Verify() error = %v, want %v", err, oidc.ErrMalformedToken)
			}
		})
	}
}

// TestVerifyMultipleIssuers checks that a token is routed to the policy of the
// issuer that signed it, not to the first issuer that happens to match.
func TestVerifyMultipleIssuers(t *testing.T) {
	t.Parallel()

	first := oidctest.New(t)
	second := oidctest.New(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`
issuers:
  first:
    audiences: [https://proxy.example.com]
    issuer: %s
    require: {organization_slug: persona-id}
    username_template: "first/{{.organization_slug}}"
  second:
    audiences: [https://proxy.example.com]
    issuer: %s
    require: {hd: example.com}
    username_template: "second/{{.hd}}"
`, first.URL(), second.URL())

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	verifier, err := oidc.NewVerifier(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}

	result, err := verifier.Verify(t.Context(), second.Sign(t, map[string]any{"hd": "example.com"}))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if want := "second/example.com"; result.Username != want {
		t.Errorf("Username = %q, want %q", result.Username, want)
	}

	// The first issuer's policy must not accept a token the second one signed.
	if _, err := verifier.Verify(t.Context(), second.Sign(t, map[string]any{"organization_slug": "persona-id"})); err == nil {
		t.Error("Verify() error = nil, want the second issuer's require block to reject this token")
	}
}

func TestClaimStrings(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		claim any
		want  []string
	}{
		"string":        {claim: "main", want: []string{"main"}},
		"string list":   {claim: []any{"eng", "sre"}, want: []string{"eng", "sre"}},
		"number":        {claim: float64(1234), want: []string{"1234"}},
		"large number":  {claim: float64(1e15), want: []string{"1000000000000000"}},
		"bool":          {claim: true, want: []string{"true"}},
		"absent":        {claim: nil, want: nil},
		"nested object": {claim: map[string]any{"a": "b"}, want: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := oidc.ClaimStrings(tc.claim)
			if len(got) != len(tc.want) {
				t.Fatalf("ClaimStrings() = %q, want %q", got, tc.want)
			}

			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ClaimStrings() = %q, want %q", got, tc.want)

					break
				}
			}
		})
	}
}

// TestNewVerifierDiscoversConcurrently proves the discoveries overlap: every
// issuer's handler blocks until all of them have been asked, which can only
// finish if the requests are in flight at the same time. Run in sequence, the
// first handler would block forever and this would fail on the context.
func TestNewVerifierDiscoversConcurrently(t *testing.T) {
	t.Parallel()

	const issuers = 3

	var (
		arrived sync.WaitGroup
		release = make(chan struct{})
	)

	arrived.Add(issuers)

	go func() {
		arrived.Wait()
		close(release)
	}()

	body := "issuers:\n"

	for i := range issuers {
		var server *httptest.Server

		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			arrived.Done()
			<-release

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"issuer":                                server.URL,
				"jwks_uri":                              server.URL + "/keys",
			})
		})

		server = httptest.NewServer(mux)
		t.Cleanup(server.Close)

		body += fmt.Sprintf(`  issuer%d:
    audiences: [https://proxy.example.com]
    issuer: %s
    require: {organization_slug: persona-id}
`, i, server.URL)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	if _, err := oidc.NewVerifier(ctx, cfg); err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}
}

// TestNewVerifierNamesFailureDeterministically checks that when more than one
// issuer is unreachable, the reported failure is always the same one rather
// than whichever goroutine lost the race.
func TestNewVerifierNamesFailureDeterministically(t *testing.T) {
	t.Parallel()

	// Ports 1 and 2 on loopback refuse connections immediately.
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
issuers:
  aaa:
    audiences: [https://proxy.example.com]
    issuer: http://127.0.0.1:1
    require: {organization_slug: persona-id}
  zzz:
    audiences: [https://proxy.example.com]
    issuer: http://127.0.0.1:2
    require: {organization_slug: persona-id}
`

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	for range 5 {
		_, err := oidc.NewVerifier(t.Context(), cfg)
		if err == nil {
			t.Fatal("NewVerifier() error = nil, want an error")
		}

		if !strings.Contains(err.Error(), "http://127.0.0.1:1") {
			t.Errorf("NewVerifier() error = %v, want it to name the first issuer URL", err)
		}
	}
}

// TestVerifyMultiplePoliciesPerIssuer covers several policies sharing one issuer
// URL: the first whose audience and require both accept the token decides the
// identity, so two tenants of the same provider get different usernames.
func TestVerifyMultiplePoliciesPerIssuer(t *testing.T) {
	t.Parallel()

	issuer := oidctest.New(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`
issuers:
  team-a:
    annotations: [organization_slug]
    audiences: [https://proxy.example.com]
    issuer: %[1]s
    require: {organization_slug: team-a}
    username_template: "a/{{.pipeline_slug}}"
  team-b:
    audiences: [https://other-proxy.example.com]
    issuer: %[1]s
    require: {organization_slug: team-b}
    username_template: "b/{{.pipeline_slug}}"
`, issuer.URL())

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	verifier, err := oidc.NewVerifier(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}

	tests := map[string]struct {
		claims       map[string]any
		wantIssuer   string
		wantUsername string
	}{
		"first policy": {
			claims:       map[string]any{"organization_slug": "team-a", "pipeline_slug": "deploy"},
			wantIssuer:   "team-a",
			wantUsername: "a/deploy",
		},
		// A different audience as well as a different tenant, so this only
		// passes if each policy is checked with its own audience list.
		"second policy": {
			claims: map[string]any{
				"aud":               "https://other-proxy.example.com",
				"organization_slug": "team-b",
				"pipeline_slug":     "test",
			},
			wantIssuer:   "team-b",
			wantUsername: "b/test",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := verifier.Verify(t.Context(), issuer.Sign(t, tc.claims))
			if err != nil {
				t.Fatalf("Verify() error = %v, want nil", err)
			}

			if result.Username != tc.wantUsername {
				t.Errorf("Username = %q, want %q", result.Username, tc.wantUsername)
			}

			if result.Issuer.Name != tc.wantIssuer {
				t.Errorf("Issuer.Name = %q, want %q", result.Issuer.Name, tc.wantIssuer)
			}
		})
	}

	// A tenant no policy covers is rejected, not quietly matched to the first.
	_, err = verifier.Verify(t.Context(), issuer.Sign(t, map[string]any{
		"organization_slug": "team-c",
		"pipeline_slug":     "deploy",
	}))
	if !errors.Is(err, oidc.ErrRequirementUnmet) {
		t.Errorf("Verify() error = %v, want %v", err, oidc.ErrRequirementUnmet)
	}
}

// TestVerifyPreservesLargeIntegerClaims guards the claim decoding: as float64,
// an integer above 2^53 would be compared and reported as a value the provider
// never sent, so a require on it would match the wrong tokens.
func TestVerifyPreservesLargeIntegerClaims(t *testing.T) {
	t.Parallel()

	// 2^53 + 1, the smallest integer a float64 cannot represent.
	const accountID = "9007199254740993"

	issuer := oidctest.New(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`
issuers:
  ci:
    annotations: [account_id]
    audiences: [https://proxy.example.com]
    issuer: %s
    require: {account_id: "%s"}
    username_template: "{{.account_id}}"
`, issuer.URL(), accountID)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	verifier, err := oidc.NewVerifier(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}

	result, err := verifier.Verify(t.Context(), issuer.Sign(t, map[string]any{
		"account_id": json.RawMessage(accountID),
	}))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if got := oidc.ClaimStrings(result.Claims["account_id"]); len(got) != 1 || got[0] != accountID {
		t.Errorf("account_id = %q, want [%s]", got, accountID)
	}

	if result.Username != accountID {
		t.Errorf("Username = %q, want %q", result.Username, accountID)
	}
}
