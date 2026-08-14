package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/persona-id/squid-oidc-auth/internal/config"
)

// write puts a config on disk and returns its path.
func write(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	return path
}

const validConfig = `
issuers:
  ci:
    annotations: [build_branch, pipeline_slug]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    max_ttl: 2m
    require:
      organization_slug: persona-id
    username_template: "{{.organization_slug}}/{{.pipeline_slug}}"
`

func TestLoadValid(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if len(cfg.Issuers) != 1 {
		t.Fatalf("len(Issuers) = %d, want 1", len(cfg.Issuers))
	}

	issuer, ok := cfg.Issuers["ci"]
	if !ok {
		t.Fatalf("Issuers has no %q entry, got %v", "ci", cfg.Issuers)
	}

	// The name comes from the map key, not from a field.
	if issuer.Name != "ci" {
		t.Errorf("Name = %q, want %q", issuer.Name, "ci")
	}

	if issuer.MaxTTL.Duration() != 2*time.Minute {
		t.Errorf("MaxTTL = %s, want 2m", issuer.MaxTTL.Duration())
	}

	if got := issuer.AnnotationKey("build_branch"); got != "oidc_build_branch" {
		t.Errorf("AnnotationKey() = %q, want %q", got, "oidc_build_branch")
	}

	if got := issuer.Require["organization_slug"]; len(got) != 1 || got[0] != "persona-id" {
		t.Errorf("Require[organization_slug] = %q, want [persona-id]", got)
	}
}

func TestLoadRequireAcceptsScalarAndList(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require:
      organization_slug: persona-id
      pipeline_slug: [deploy-api, deploy-web]
`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	require := cfg.Issuers["ci"].Require

	if len(require["organization_slug"]) != 1 {
		t.Errorf("scalar require decoded to %q, want one value", require["organization_slug"])
	}

	if len(require["pipeline_slug"]) != 2 {
		t.Errorf("list require decoded to %q, want two values", require["pipeline_slug"])
	}
}

func TestLoadRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body    string
		wantErr string
	}{
		"no issuers": {
			body:    "issuers: {}\n",
			wantErr: "at least one issuer",
		},
		"missing require": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
`,
			wantErr: "require is mandatory",
		},
		"empty require": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {}
`,
			wantErr: "require is mandatory",
		},
		"unknown field": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    requires:
      organization_slug: persona-id
`,
			wantErr: "field requires not found",
		},
		// The name used to be a field. Rejecting it points anyone with an older
		// config at the change rather than silently ignoring the name.
		"name given as a field": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    name: ci
    require: {organization_slug: persona-id}
`,
			wantErr: "field name not found",
		},
		"empty issuer name": {
			body: `
issuers:
  "":
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: persona-id}
`,
			wantErr: "name may not be empty",
		},
		"issuer with no settings": {
			body: `
issuers:
  ci:
`,
			wantErr: "has no settings",
		},
		"missing audiences": {
			body: `
issuers:
  ci:
    issuer: https://issuer.example.com
    require:
      organization_slug: persona-id
`,
			wantErr: "at least one audience",
		},
		"issuer URL without scheme": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: issuer.example.com
    require:
      organization_slug: persona-id
`,
			wantErr: "must use https",
		},
		"annotation collides with a reserved key": {
			body: `
issuers:
  ci:
    annotation_prefix: ""
    annotations: [user]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: persona-id}
`,
			wantErr: "collides with a key Squid reserves",
		},
		"annotation key is not a bare token": {
			body: `
issuers:
  ci:
    annotations: ["build branch"]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: persona-id}
`,
			wantErr: "not a valid response key",
		},
		// Both land on oidc_policy, and `note` ORs the values for a key, so a
		// policy ACL would match tokens it should not.
		"annotation collides with the policy annotation": {
			body: `
issuers:
  ci:
    annotations: [policy]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    policy_annotation: oidc_policy
    require: {organization_slug: persona-id}
`,
			wantErr: "collides with policy_annotation",
		},
		"duplicate annotation": {
			body: `
issuers:
  ci:
    annotations: [build_branch, build_branch]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: persona-id}
`,
			wantErr: "more than once",
		},
		"malformed username template": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: persona-id}
    username_template: "{{.organization_slug"
`,
			wantErr: "parsing username template",
		},
		"malformed duration": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    max_ttl: "two minutes"
    require: {organization_slug: persona-id}
`,
			wantErr: "parsing duration",
		},
		"require value of the wrong type": {
			body: `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require:
      organization_slug: {nested: value}
`,
			wantErr: "expected a string or a list of strings",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Load(write(t, tc.body))
			if err == nil {
				t.Fatalf("Load() error = nil, want an error containing %q", tc.wantErr)
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Load() error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoadRejectsDuplicateIssuerNames is what keying by name buys: the YAML
// parser refuses the document, so this package needs no check of its own.
func TestLoadRejectsDuplicateIssuerNames(t *testing.T) {
	t.Parallel()

	_, err := config.Load(write(t, `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://first.example.com
    require: {organization_slug: persona-id}
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://second.example.com
    require: {organization_slug: persona-id}
`))
	if err == nil {
		t.Fatal("Load() error = nil, want the duplicate key to be rejected")
	}

	if !strings.Contains(err.Error(), "already defined") {
		t.Errorf("Load() error = %v, want it to report a duplicate key", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("Load() error = nil, want an error")
	}
}

func TestRenderUsername(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	claims := map[string]any{
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	}

	got, err := cfg.Issuers["ci"].RenderUsername(claims)
	if err != nil {
		t.Fatalf("RenderUsername() error = %v, want nil", err)
	}

	if want := "persona-id/deploy-api"; got != want {
		t.Errorf("RenderUsername() = %q, want %q", got, want)
	}
}

// TestRenderUsernameMissingClaim guards the case that matters most: a provider
// that stops sending a claim must fail the lookup, not collapse every token onto
// one shared username.
func TestRenderUsernameMissingClaim(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	_, err = cfg.Issuers["ci"].RenderUsername(map[string]any{"organization_slug": "persona-id"})
	if err == nil {
		t.Error("RenderUsername() error = nil, want an error for the missing claim")
	}
}

func TestRenderUsernameDefaultsToSubject(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: persona-id}
`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	got, err := cfg.Issuers["ci"].RenderUsername(map[string]any{"sub": "organization:persona-id:pipeline:x"})
	if err != nil {
		t.Fatalf("RenderUsername() error = %v, want nil", err)
	}

	if want := "organization:persona-id:pipeline:x"; got != want {
		t.Errorf("RenderUsername() = %q, want %q", got, want)
	}
}

// TestLoadAllowsSharedIssuerURL covers several policies for one provider, which
// is how two tenants of the same issuer get different usernames and annotations.
func TestLoadAllowsSharedIssuerURL(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, `
issuers:
  team-a:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: team-a}
    username_template: "a/{{.pipeline_slug}}"
  team-b:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    require: {organization_slug: team-b}
    username_template: "b/{{.pipeline_slug}}"
`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if len(cfg.Issuers) != 2 {
		t.Fatalf("len(Issuers) = %d, want 2", len(cfg.Issuers))
	}
}

// TestLoadAllowsPolicyClaimWhenAnnotationMoved covers a provider whose tokens
// carry a genuine "policy" claim. It is projectable as long as the helper's own
// policy key is moved out of the way, which is why that key is configurable
// rather than derived from annotation_prefix.
func TestLoadAllowsPolicyClaimWhenAnnotationMoved(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, `
issuers:
  ci:
    annotations: [policy]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    policy_annotation: oidc_matched_policy
    require: {organization_slug: persona-id}
`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	issuer := cfg.Issuers["ci"]

	if got := issuer.AnnotationKey("policy"); got != "oidc_policy" {
		t.Errorf("AnnotationKey(policy) = %q, want %q", got, "oidc_policy")
	}

	if got := issuer.PolicyAnnotationKey(); got != "oidc_matched_policy" {
		t.Errorf("PolicyAnnotationKey() = %q, want %q", got, "oidc_matched_policy")
	}
}

// TestLoadPolicyAnnotationDefault pins the default, which must stay outside the
// annotation_prefix namespace so a "policy" claim remains projectable.
func TestLoadPolicyAnnotationDefault(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got := cfg.Issuers["ci"].PolicyAnnotationKey(); got != "auth_policy" {
		t.Errorf("PolicyAnnotationKey() = %q, want %q", got, "auth_policy")
	}
}

// TestLoadPolicyAnnotationCanBeDisabled covers turning the annotation off.
func TestLoadPolicyAnnotationCanBeDisabled(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(write(t, `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    policy_annotation: ""
    require: {organization_slug: persona-id}
`))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got := cfg.Issuers["ci"].PolicyAnnotationKey(); got != "" {
		t.Errorf("PolicyAnnotationKey() = %q, want it disabled", got)
	}
}

// TestLoadIssuerURLScheme covers the transport the key set is fetched over.
// Discovery and the JWKS come from this URL, so over plaintext anyone on the
// path can publish their own signing keys and mint tokens the helper accepts.
func TestLoadIssuerURLScheme(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issuer  string
		wantErr bool
	}{
		"https":                    {issuer: "https://issuer.example.com"},
		"http to a remote host":    {issuer: "http://issuer.example.com", wantErr: true},
		"http to 127.0.0.1":        {issuer: "http://127.0.0.1:9099"},
		"http to ::1":              {issuer: "http://[::1]:9099"},
		"http to localhost":        {issuer: "http://localhost:9099"},
		"http to a lookalike host": {issuer: "http://127.0.0.1.example.com", wantErr: true},
		"no scheme":                {issuer: "issuer.example.com", wantErr: true},
		"non-http scheme":          {issuer: "ftp://issuer.example.com", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Load(write(t, fmt.Sprintf(`
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: %s
    require: {organization_slug: persona-id}
`, tc.issuer)))

			if tc.wantErr && err == nil {
				t.Fatalf("Load(%s) error = nil, want it rejected", tc.issuer)
			}

			if !tc.wantErr && err != nil {
				t.Fatalf("Load(%s) error = %v, want nil", tc.issuer, err)
			}
		})
	}
}
