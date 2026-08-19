package auth_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/persona-id/squid-oidc-auth/internal/auth"
	"github.com/persona-id/squid-oidc-auth/internal/config"
	"github.com/persona-id/squid-oidc-auth/internal/oidc"
	"github.com/persona-id/squid-oidc-auth/internal/protocol"
)

// fakeVerifier stands in for the real verifier so these tests exercise the
// response contract without a signing key or a network.
type fakeVerifier struct {
	err    error
	result *oidc.Result
}

func (f *fakeVerifier) Verify(_ context.Context, _ string) (*oidc.Result, error) {
	return f.result, f.err
}

// testIssuer loads a real config so annotation prefixing and max_ttl behave
// exactly as they would in production.
func testIssuer(t *testing.T, body string) *config.Issuer {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if len(cfg.Issuers) != 1 {
		t.Fatalf("len(Issuers) = %d, want exactly 1 for this helper", len(cfg.Issuers))
	}

	for _, issuer := range cfg.Issuers {
		return issuer
	}

	panic("unreachable")
}

const issuerConfig = `
issuers:
  ci:
    annotations: [build_branch, pipeline_slug]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    max_ttl: 2m
    require: {organization_slug: persona-id}
`

// now is the instant every test pretends it is, so an asserted ttl= is exact
// rather than a second short depending on scheduling.
var now = time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

func newHandler(verifier auth.Verifier) *auth.Handler {
	return &auth.Handler{
		Logger:   slog.New(slog.DiscardHandler),
		Now:      func() time.Time { return now },
		Verifier: verifier,
	}
}

func request(fields ...string) protocol.Request {
	return protocol.Request{ChannelID: protocol.NoChannel, Fields: fields}
}

func TestHandleAccepts(t *testing.T) {
	t.Parallel()

	handler := newHandler(&fakeVerifier{result: &oidc.Result{
		Claims: map[string]any{
			"build_branch":  "main",
			"pipeline_slug": "deploy-api",
		},
		Expiry:   now.Add(30 * time.Second),
		Issuer:   testIssuer(t, issuerConfig),
		Username: "persona-id/deploy-api",
	}})

	got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	want := "OK auth_policy=ci oidc_build_branch=main oidc_pipeline_slug=deploy-api ttl=30"
	if got != want {
		t.Errorf("Handle() = %q, want %q", got, want)
	}
}

// TestHandleProjectsListClaims covers a multi-valued claim, which must become
// one pair per value so a `note` ACL matches any of them.
func TestHandleProjectsListClaims(t *testing.T) {
	t.Parallel()

	handler := newHandler(&fakeVerifier{result: &oidc.Result{
		Claims:   map[string]any{"pipeline_slug": []any{"deploy-api", "deploy-web"}},
		Expiry:   now.Add(time.Minute),
		Issuer:   testIssuer(t, issuerConfig),
		Username: "persona-id",
	}})

	got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	if !strings.Contains(got, "oidc_pipeline_slug=deploy-api oidc_pipeline_slug=deploy-web") {
		t.Errorf("Handle() = %q, want both pipeline_slug values", got)
	}

	// build_branch was not in the claims, so it must not appear at all.
	if strings.Contains(got, "oidc_build_branch") {
		t.Errorf("Handle() = %q, want no pair for the absent claim", got)
	}
}

func TestHandleTTL(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		expiresIn time.Duration
		want      string
	}{
		"shorter than max_ttl uses the token expiry": {expiresIn: 45 * time.Second, want: "ttl=45"},
		"longer than max_ttl is capped":              {expiresIn: 10 * time.Minute, want: "ttl=120"},
		"already expired never goes negative":        {expiresIn: -time.Minute, want: "ttl=0"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := newHandler(&fakeVerifier{result: &oidc.Result{
				Claims:   map[string]any{},
				Expiry:   now.Add(tc.expiresIn),
				Issuer:   testIssuer(t, issuerConfig),
				Username: "persona-id",
			}})

			got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
			if err != nil {
				t.Fatalf("Encode() error = %v, want nil", err)
			}

			if !strings.HasSuffix(got, tc.want) {
				t.Errorf("Handle() = %q, want it to end with %q", got, tc.want)
			}
		})
	}
}

func TestHandleRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err    error
		fields []string
		want   string
	}{
		"no credential": {
			fields: []string{"bk"},
			want:   `ERR message="no credential supplied"`,
		},
		"empty credential": {
			fields: []string{"bk", ""},
			want:   `ERR message="no credential supplied"`,
		},
		"unknown issuer": {
			err:    oidc.ErrUnknownIssuer,
			fields: []string{"bk", "token"},
			want:   `ERR message="token issuer is not trusted"`,
		},
		"requirement unmet": {
			err:    oidc.ErrRequirementUnmet,
			fields: []string{"bk", "token"},
			want:   `ERR message="token is not authorized for this proxy"`,
		},
		"audience mismatch": {
			err:    oidc.ErrAudienceMismatch,
			fields: []string{"bk", "token"},
			want:   `ERR message="token audience is not accepted"`,
		},
		"malformed token": {
			err:    oidc.ErrMalformedToken,
			fields: []string{"bk", "token"},
			want:   `ERR message="credential is not a JWT"`,
		},
		"expired or otherwise invalid": {
			err:    errors.New("oidc: token is expired"),
			fields: []string{"bk", "token"},
			want:   `ERR message="token is not valid"`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := newHandler(&fakeVerifier{err: tc.err})

			got, err := handler.Handle(t.Context(), request(tc.fields...)).Encode()
			if err != nil {
				t.Fatalf("Encode() error = %v, want nil", err)
			}

			if got != tc.want {
				t.Errorf("Handle() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHandleTemporaryFailureIsBH is the distinction that decides whether an
// outage looks like a rejected build or like a broken proxy.
func TestHandleTemporaryFailureIsBH(t *testing.T) {
	t.Parallel()

	handler := newHandler(&fakeVerifier{
		err: &oidc.TemporaryError{Err: errors.New("dial tcp: connection refused")},
	})

	got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	if want := `BH message="verification unavailable"`; got != want {
		t.Errorf("Handle() = %q, want %q", got, want)
	}
}

// TestHandleDoesNotLeakPolicyDetail checks that the reason a token failed stays
// in the log rather than traveling back to the client in message=.
func TestHandleDoesNotLeakPolicyDetail(t *testing.T) {
	t.Parallel()

	handler := newHandler(&fakeVerifier{
		err: errors.New("requirement unmet: claim organization_slug is acme-corp"),
	})

	got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	if strings.Contains(got, "acme-corp") || strings.Contains(got, "organization_slug") {
		t.Errorf("Handle() = %q, want no policy detail in the response", got)
	}
}

// TestHandleEchoesChannelID guards the concurrent case: an answer routed to the
// wrong channel would authorize a different request.
func TestHandleEchoesChannelID(t *testing.T) {
	t.Parallel()

	handler := newHandler(&fakeVerifier{err: oidc.ErrUnknownIssuer})

	req := protocol.Request{ChannelID: 7, Fields: []string{"bk", "token"}}

	got, err := handler.Handle(t.Context(), req).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	if !strings.HasPrefix(got, "7 ERR") {
		t.Errorf("Handle() = %q, want it to start with %q", got, "7 ERR")
	}
}

// TestHandlePolicyAnnotationIsAlwaysSent covers the annotation naming the policy
// that accepted the token. With several policies sharing an issuer it is the
// only signal saying which one matched, so squid.conf can gate on it instead of
// restating the claims that policy matches on.
func TestHandlePolicyAnnotationIsAlwaysSent(t *testing.T) {
	t.Parallel()

	// An issuer projecting no claims at all still reports its policy.
	issuer := testIssuer(t, `
issuers:
  team-a:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: team-a}
`)

	handler := newHandler(&fakeVerifier{result: &oidc.Result{
		Claims:   map[string]any{},
		Expiry:   now.Add(time.Minute),
		Issuer:   issuer,
		Username: "team-a",
	}})

	got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	if want := "OK auth_policy=team-a ttl=60"; got != want {
		t.Errorf("Handle() = %q, want %q", got, want)
	}
}

// TestHandlePolicyAnnotationDisabled covers an issuer that has turned the
// annotation off, which must leave the rest of the response untouched.
func TestHandlePolicyAnnotationDisabled(t *testing.T) {
	t.Parallel()

	issuer := testIssuer(t, `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    policy_annotation: ""
    require: {organization_slug: persona-id}
`)

	handler := newHandler(&fakeVerifier{result: &oidc.Result{
		Claims:   map[string]any{},
		Expiry:   now.Add(time.Minute),
		Issuer:   issuer,
		Username: "persona-id",
	}})

	got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	if want := "OK ttl=60"; got != want {
		t.Errorf("Handle() = %q, want %q", got, want)
	}
}

// TestHandleVerifyUsername covers the login check. Squid keeps the client's
// login as the transaction username however the helper answers, so without this
// a client can pair any login it likes with a valid token.
func TestHandleVerifyUsername(t *testing.T) {
	t.Parallel()

	const config = `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: persona-id}
    username_template: "{{.organization_slug}}"
    verify_username: %t
`

	tests := map[string]struct {
		login    string
		verify   bool
		wantCode string
	}{
		"matching login is accepted":        {login: "persona-id", verify: true, wantCode: "OK"},
		"mismatched login is rejected":      {login: "i-am-root", verify: true, wantCode: "ERR"},
		"mismatch is ignored when disabled": {login: "i-am-root", verify: false, wantCode: "OK"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := newHandler(&fakeVerifier{result: &oidc.Result{
				Claims:   map[string]any{"organization_slug": "persona-id"},
				Expiry:   now.Add(time.Minute),
				Issuer:   testIssuer(t, fmt.Sprintf(config, tc.verify)),
				Username: "persona-id",
			}})

			got, err := handler.Handle(t.Context(), request(tc.login, "token")).Encode()
			if err != nil {
				t.Fatalf("Encode() error = %v, want nil", err)
			}

			if code, _, _ := strings.Cut(got, " "); code != tc.wantCode {
				t.Errorf("Handle() = %q, want a %s", got, tc.wantCode)
			}
		})
	}
}

// TestHandleBoundsVerification covers a provider that accepts the connection and
// never answers. go-oidc refetches the key set on the request path whenever a
// token names an unknown key, over an HTTP client with no timeout, and a token
// needs no valid signature to reach that path. Unbounded, a handful of such
// requests would occupy every helper slot and stop authentication proxy-wide.
func TestHandleBoundsVerification(t *testing.T) {
	t.Parallel()

	handler := newHandler(&blockingVerifier{})
	handler.Timeout = 50 * time.Millisecond

	done := make(chan string, 1)

	go func() {
		got, err := handler.Handle(t.Context(), request("bk", "token")).Encode()
		if err != nil {
			done <- "encode error: " + err.Error()

			return
		}

		done <- got
	}()

	select {
	case got := <-done:
		// BH, not ERR: the helper could not reach a verdict, which is an
		// environment failure rather than a bad credential.
		if want := `BH message="verification unavailable"`; got != want {
			t.Errorf("Handle() = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle() did not return, want it bounded by Timeout")
	}
}

// blockingVerifier stands in for an identity provider that never answers.
type blockingVerifier struct{}

func (b *blockingVerifier) Verify(ctx context.Context, _ string) (*oidc.Result, error) {
	<-ctx.Done()

	return nil, &oidc.TemporaryError{Err: ctx.Err()}
}
