// Package e2e drives the real helper binary the way Squid does: as a child
// process speaking the line protocol over stdin and stdout.
//
// The tests below are the only ones that exercise flag parsing, discovery at
// startup, and the wiring in main. Everything else is covered by unit tests.
package e2e_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/persona-id/squid-oidc-auth/internal/oidctest"
)

// helperPath is the binary under test, built once for the whole package.
var helperPath string

func TestMain(m *testing.M) {
	os.Exit(buildAndRun(m))
}

// buildAndRun exists so the temporary directory is cleaned up by defer, which
// os.Exit in TestMain would otherwise skip.
func buildAndRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "squid-oidc-auth-e2e")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temp dir: %v\n", err)

		return 1
	}

	defer func() { _ = os.RemoveAll(dir) }()

	helperPath = filepath.Join(dir, "squid-oidc-auth")

	build := exec.Command("go", "build", "-o", helperPath, "github.com/persona-id/squid-oidc-auth/cmd/squid-oidc-auth")
	build.Stderr = os.Stderr

	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "building helper: %v\n", err)

		return 1
	}

	return m.Run()
}

const configTemplate = `
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

// newIssuer starts a test provider and writes a config pointing at it.
func newIssuer(t *testing.T) (*oidctest.Issuer, string) {
	t.Helper()

	issuer := oidctest.New(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, fmt.Appendf(nil, configTemplate, issuer.URL()), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	return issuer, path
}

// runHelper feeds requests to the helper, closes stdin, and returns the response
// lines. Closing stdin is how Squid signals shutdown, so this also covers the
// helper exiting cleanly.
func runHelper(t *testing.T, configPath string, concurrent bool, requests ...string) []string {
	t.Helper()

	args := []string{"--config", configPath, "--log-level", "error"}
	if concurrent {
		args = append(args, "--concurrent")
	}

	cmd := exec.CommandContext(t.Context(), helperPath, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("opening stdout: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting helper: %v", err)
	}

	var lines []string

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("reading responses: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exited with an error: %v", err)
	}

	return lines
}

func TestAcceptsValidToken(t *testing.T) {
	t.Parallel()

	issuer, configPath := newIssuer(t)

	token := issuer.Sign(t, map[string]any{
		"build_branch":      "main",
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})

	lines := runHelper(t, configPath, false, "bk "+token)

	if len(lines) != 1 {
		t.Fatalf("got %d responses, want 1: %q", len(lines), lines)
	}

	for _, want := range []string{
		"OK ",
		"auth_policy=ci",
		"oidc_build_branch=main",
		"oidc_pipeline_slug=deploy-api",
		"ttl=",
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("response %q, want it to contain %q", lines[0], want)
		}
	}
}

func TestRejectsTokens(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		claims  map[string]any
		rawLine string
	}{
		"another tenant of the same provider": {
			claims: map[string]any{
				"organization_slug": "someone-else",
				"pipeline_slug":     "deploy-api",
			},
		},
		"audience we do not serve": {
			claims: map[string]any{
				"aud":               "https://another-proxy.example.com",
				"organization_slug": "persona-id",
				"pipeline_slug":     "deploy-api",
			},
		},
		"expired token": {
			claims: map[string]any{
				"exp":               time.Now().Add(-time.Hour).Unix(),
				"organization_slug": "persona-id",
				"pipeline_slug":     "deploy-api",
			},
		},
		"not a token at all": {rawLine: "bk hunter2"},
		"no credential":      {rawLine: "bk"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer, configPath := newIssuer(t)

			line := tc.rawLine
			if line == "" {
				line = "bk " + issuer.Sign(t, tc.claims)
			}

			lines := runHelper(t, configPath, false, line)

			if len(lines) != 1 {
				t.Fatalf("got %d responses, want 1: %q", len(lines), lines)
			}

			if !strings.HasPrefix(lines[0], "ERR ") {
				t.Errorf("response %q, want an ERR", lines[0])
			}
		})
	}
}

// TestConcurrentChannelsAreEchoed is the property Squid relies on to match
// answers to requests when several are in flight on one pipe.
func TestConcurrentChannelsAreEchoed(t *testing.T) {
	t.Parallel()

	issuer, configPath := newIssuer(t)

	good := issuer.Sign(t, map[string]any{
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})
	bad := issuer.Sign(t, map[string]any{
		"organization_slug": "someone-else",
		"pipeline_slug":     "deploy-api",
	})

	lines := runHelper(t, configPath, true,
		"0 bk "+good,
		"1 bk "+bad,
		"2 bk hunter2",
		"3 bk "+good,
	)

	if len(lines) != 4 {
		t.Fatalf("got %d responses, want 4: %q", len(lines), lines)
	}

	want := map[string]string{
		"0": "OK",
		"1": "ERR",
		"2": "ERR",
		"3": "OK",
	}

	seen := make(map[string]bool, len(want))

	for _, line := range lines {
		id, rest, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("response %q has no channel ID", line)
		}

		if seen[id] {
			t.Errorf("channel %s answered twice", id)
		}

		seen[id] = true

		if code, _, _ := strings.Cut(rest, " "); code != want[id] {
			t.Errorf("channel %s got %s, want %s", id, code, want[id])
		}
	}

	for id := range want {
		if !seen[id] {
			t.Errorf("channel %s was never answered", id)
		}
	}
}

// TestPercentEncodedCredential covers Squid's encoding of request fields, which
// it applies to any value containing a reserved character.
func TestPercentEncodedCredential(t *testing.T) {
	t.Parallel()

	issuer, configPath := newIssuer(t)

	token := issuer.Sign(t, map[string]any{
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})

	// The username Squid sends is whatever preceded the colon in the proxy URL,
	// and carries no authority: an encoded one must not change the outcome.
	lines := runHelper(t, configPath, false, "some%20user "+token)

	if len(lines) != 1 || !strings.HasPrefix(lines[0], "OK ") {
		t.Fatalf("responses = %q, want a single OK", lines)
	}
}

// TestUnreachableIssuerFailsStartup checks that a helper which cannot verify
// anything refuses to start, rather than running and denying every request.
func TestUnreachableIssuerFailsStartup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")

	// Port 1 on loopback refuses connections immediately.
	body := fmt.Appendf(nil, configTemplate, "http://127.0.0.1:1")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), helperPath, "--config", path, "--log-level", "error")
	cmd.Stdin = strings.NewReader("")

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("helper exited 0, want a non-zero status; output: %s", output)
	}

	if !strings.Contains(string(output), "discovering issuer") {
		t.Errorf("output = %s, want it to name the unreachable issuer", output)
	}
}

// TestRejectsConfigWithoutRequire guards the multi-tenant issuer problem: a
// config that trusts an issuer without constraining a tenant claim would accept
// tokens from every one of that provider's customers, so it must not start.
func TestRejectsConfigWithoutRequire(t *testing.T) {
	t.Parallel()

	issuer := oidctest.New(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Appendf(nil, `
issuers:
  ci:
    audiences: [https://proxy.example.com]
    issuer: %s
`, issuer.URL())

	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), helperPath, "--config", path)
	cmd.Stdin = strings.NewReader("")

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("helper exited 0, want a non-zero status; output: %s", output)
	}

	if !strings.Contains(string(output), "require is mandatory") {
		t.Errorf("output = %s, want it to explain the missing require block", output)
	}
}

// TestTTLNeverExceedsTokenLifetime is the caching invariant: Squid must not be
// told it can reuse an answer for longer than the token stays valid.
func TestTTLNeverExceedsTokenLifetime(t *testing.T) {
	t.Parallel()

	issuer, configPath := newIssuer(t)

	// Well under max_ttl, so the token's own expiry is what binds.
	token := issuer.Sign(t, map[string]any{
		"exp":               time.Now().Add(20 * time.Second).Unix(),
		"organization_slug": "persona-id",
		"pipeline_slug":     "deploy-api",
	})

	lines := runHelper(t, configPath, false, "bk "+token)

	if len(lines) != 1 {
		t.Fatalf("got %d responses, want 1: %q", len(lines), lines)
	}

	fields := strings.Fields(lines[0])

	index := slices.IndexFunc(fields, func(field string) bool {
		return strings.HasPrefix(field, "ttl=")
	})
	if index < 0 {
		t.Fatalf("response %q has no ttl", lines[0])
	}

	var ttl int
	if _, err := fmt.Sscanf(fields[index], "ttl=%d", &ttl); err != nil {
		t.Fatalf("parsing %q: %v", fields[index], err)
	}

	if ttl <= 0 || ttl > 20 {
		t.Errorf("ttl = %d, want it in (0, 20]", ttl)
	}
}
