// Package config loads and validates the helper's YAML configuration.
//
// Validation is strict and happens entirely at load time so a helper that
// starts has a coherent policy. Squid keeps helpers running for the life of the
// proxy process.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/persona-id/squid-oidc-auth/internal/protocol"
)

// DefaultAnnotationPrefix namespaces claim-derived annotations away from the
// keys Squid reserves for itself.
const DefaultAnnotationPrefix = "oidc_"

// DefaultPolicyAnnotation is the response key naming the policy that accepted a
// token.
//
// It deliberately avoids AnnotationPrefix, for two reasons. A provider with a
// genuine "policy" claim would otherwise have nowhere to project it, since the
// claim and this key would collide at every prefix. And a prefixed key, sitting
// in squid.conf next to oidc_build_branch and the rest, would read as something
// the helper found in the token rather than something it decided.
const DefaultPolicyAnnotation = "auth_policy"

// reservedKeys are the response keys Squid interprets. An annotation may not
// land on one of these, since doing so would let a claim value masquerade as a
// protocol field.
var reservedKeys = []string{
	"clt_conn_tag",
	"log",
	"message",
	"password",
	"tag",
	"ttl",
	"user",
}

// Config is the helper's whole configuration.
type Config struct {
	// Issuers is keyed by name, so a duplicate is a YAML error rather than
	// something this package has to check for.
	Issuers map[string]*Issuer `yaml:"issuers"`
}

// Load reads and validates the configuration at path.
func Load(path string) (*Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(body))
	// Reject unknown fields: a typo in a `require` key would otherwise be
	// silently dropped, quietly widening who the proxy trusts.
	decoder.KnownFields(true)

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config %s: %w", path, err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if len(c.Issuers) == 0 {
		return errors.New("at least one issuer is required")
	}

	// Sorted, so a config with several problems always reports the same one.
	for _, name := range slices.Sorted(maps.Keys(c.Issuers)) {
		issuer := c.Issuers[name]
		if issuer == nil {
			return fmt.Errorf("issuer %s: has no settings", name)
		}

		// The key is the name; the struct carries it for logs and errors.
		issuer.Name = name

		if err := issuer.validate(); err != nil {
			return fmt.Errorf("issuer %s: %w", name, err)
		}
	}

	return nil
}

// Duration is a time.Duration written in YAML as a string such as "2m".
type Duration time.Duration

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// UnmarshalYAML parses the duration syntax accepted by time.ParseDuration.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var text string
	if err := node.Decode(&text); err != nil {
		return fmt.Errorf("line %d: expected a duration string such as \"2m\"", node.Line)
	}

	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("line %d: parsing duration %q: %w", node.Line, text, err)
	}

	*d = Duration(parsed)

	return nil
}

// Issuer describes one trusted OIDC provider and the policy applied to the
// tokens it signs.
type Issuer struct {
	// AnnotationPrefix namespaces projected claims. Defaults to
	// DefaultAnnotationPrefix; set it to "" only if you have checked the
	// resulting keys against Squid's reserved set.
	AnnotationPrefix *string `yaml:"annotation_prefix"`
	// Annotations lists the claims projected into Squid annotations, for
	// `note` ACLs in squid.conf.
	Annotations []string `yaml:"annotations"`
	// Audiences lists the accepted aud values, OR'd together. Required.
	Audiences []string `yaml:"audiences"`
	// Issuer is the provider's issuer URL, used for OIDC discovery. Required.
	Issuer string `yaml:"issuer"`
	// MaxTTL caps how long Squid may cache an answer. The effective TTL is
	// always the lesser of this and the token's own remaining lifetime.
	MaxTTL Duration `yaml:"max_ttl"`
	// Name labels the issuer in logs and errors. It comes from the key in
	// Config.Issuers rather than from a field, so it cannot be duplicated or
	// omitted.
	Name string `yaml:"-"`
	// PolicyAnnotation is the key reporting which policy accepted a token.
	// Defaults to DefaultPolicyAnnotation; set it to "" to send nothing, or to
	// another key if this one is wanted for a claim.
	PolicyAnnotation *string `yaml:"policy_annotation"`
	// Require constrains which tokens from this issuer are accepted. Claims are
	// AND'd together, and each claim's values are OR'd.
	//
	// Mandatory: hosted issuers are multi-tenant and the audience is usually
	// chosen by whoever requests the token, so trusting an issuer without a
	// tenant claim trusts that provider's entire customer base.
	Require map[string]Values `yaml:"require"`
	// UsernameTemplate is a Go template over the token's claims. It renders the
	// identity named in this helper's logs and, when VerifyUsername is set, the
	// login a client must send. Defaults to "{{.sub}}".
	//
	// The result is not sent to Squid. Under the Basic scheme the username is
	// the login the client sent and a helper cannot override it, so %ul and
	// proxy_auth carry no authority unless VerifyUsername is set.
	UsernameTemplate string `yaml:"username_template"`
	// VerifyUsername rejects a request whose login does not equal the rendered
	// Username. Squid keeps the client's login as the transaction's username, so
	// this is what makes %ul and proxy_auth trustworthy: without it a client can
	// send any login it likes alongside a valid token.
	//
	// It requires the client to send the rendered username as the basic-auth
	// login, so it is off by default.
	VerifyUsername bool `yaml:"verify_username"`

	usernameTmpl *template.Template
}

// AnnotationKey returns the response key a claim is projected onto.
func (i *Issuer) AnnotationKey(claim string) string {
	prefix := DefaultAnnotationPrefix
	if i.AnnotationPrefix != nil {
		prefix = *i.AnnotationPrefix
	}

	return prefix + claim
}

// PolicyAnnotationKey returns the response key naming the policy that accepted
// the token, or "" when the issuer has turned it off. squid.conf can gate on it
// directly rather than restating the claims the policy matches on.
func (i *Issuer) PolicyAnnotationKey() string {
	if i.PolicyAnnotation != nil {
		return *i.PolicyAnnotation
	}

	return DefaultPolicyAnnotation
}

// RenderUsername builds the identity a verified token describes, for this
// helper's logs and for the login check VerifyUsername performs.
func (i *Issuer) RenderUsername(claims map[string]any) (string, error) {
	var b strings.Builder

	if err := i.usernameTmpl.Execute(&b, claims); err != nil {
		return "", fmt.Errorf("rendering username for issuer %q: %w", i.Name, err)
	}

	username := b.String()
	if username == "" {
		return "", fmt.Errorf("username template for issuer %q produced an empty result", i.Name)
	}

	return username, nil
}

func (i *Issuer) parseUsername() error {
	text := i.UsernameTemplate
	if text == "" {
		text = "{{.sub}}"
	}

	// missingkey=error turns a claim the provider did not send into a failed
	// lookup, rather than a user of "<no value>" shared by every such token.
	tmpl, err := template.New("username").Option("missingkey=error").Parse(text)
	if err != nil {
		return fmt.Errorf("parsing username template %q: %w", text, err)
	}

	i.usernameTmpl = tmpl

	return nil
}

func (i *Issuer) validate() error {
	if i.Name == "" {
		return errors.New("name may not be empty")
	}

	if err := i.validateIssuerURL(); err != nil {
		return err
	}

	if len(i.Audiences) == 0 {
		return errors.New("at least one audience is required")
	}

	if slices.Contains(i.Audiences, "") {
		return errors.New("audiences may not contain an empty value")
	}

	if err := i.validateRequire(); err != nil {
		return err
	}

	if err := i.validateAnnotations(); err != nil {
		return err
	}

	if i.MaxTTL < 0 {
		return fmt.Errorf("max_ttl may not be negative, got %s", i.MaxTTL.Duration())
	}

	return i.parseUsername()
}

func (i *Issuer) validateAnnotations() error {
	seen := make(map[string]bool, len(i.Annotations))

	for _, claim := range i.Annotations {
		if claim == "" {
			return errors.New("annotations contains an empty claim name")
		}

		if seen[claim] {
			return fmt.Errorf("annotations lists %q more than once", claim)
		}

		seen[claim] = true

		key := i.AnnotationKey(claim)

		if !protocol.ValidKey(key) {
			return fmt.Errorf("annotation key %q is not a valid response key", key)
		}

		if slices.Contains(reservedKeys, key) {
			return fmt.Errorf(
				"annotation key %q collides with a key Squid reserves (%s); set annotation_prefix",
				key, strings.Join(reservedKeys, ", "),
			)
		}

		if key == i.PolicyAnnotationKey() {
			return fmt.Errorf(
				"annotation key %q collides with policy_annotation; set one of them to something else",
				key,
			)
		}
	}

	return i.validatePolicyAnnotation()
}

func (i *Issuer) validatePolicyAnnotation() error {
	key := i.PolicyAnnotationKey()
	if key == "" {
		return nil
	}

	if !protocol.ValidKey(key) {
		return fmt.Errorf("policy_annotation %q is not a valid response key", key)
	}

	if slices.Contains(reservedKeys, key) {
		return fmt.Errorf(
			"policy_annotation %q collides with a key Squid reserves (%s)",
			key, strings.Join(reservedKeys, ", "),
		)
	}

	return nil
}

func (i *Issuer) validateIssuerURL() error {
	if i.Issuer == "" {
		return errors.New("issuer is required")
	}

	parsed, err := url.Parse(i.Issuer)
	if err != nil {
		return fmt.Errorf("parsing issuer URL %q: %w", i.Issuer, err)
	}

	// http is allowed so tests can point at a local issuer; anything else is a
	// configuration mistake rather than a deployment choice.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("issuer URL %q must use http or https", i.Issuer)
	}

	if parsed.Host == "" {
		return fmt.Errorf("issuer URL %q has no host", i.Issuer)
	}

	return nil
}

func (i *Issuer) validateRequire() error {
	if len(i.Require) == 0 {
		return errors.New(
			"require is mandatory: a hosted issuer signs tokens for every one of its tenants, " +
				"so constrain at least one claim identifying yours",
		)
	}

	for _, claim := range slices.Sorted(maps.Keys(i.Require)) {
		if claim == "" {
			return errors.New("require contains an empty claim name")
		}

		values := i.Require[claim]
		if len(values) == 0 {
			return fmt.Errorf("require.%s lists no values", claim)
		}

		if slices.Contains(values, "") {
			return fmt.Errorf("require.%s contains an empty value", claim)
		}
	}

	return nil
}

// Values is a claim constraint, written in YAML as either a scalar or a list.
type Values []string

// UnmarshalYAML accepts both `key: value` and `key: [a, b]`.
func (v *Values) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var single string
		if err := node.Decode(&single); err != nil {
			return err
		}

		*v = Values{single}

		return nil
	case yaml.SequenceNode:
		var many []string
		if err := node.Decode(&many); err != nil {
			return err
		}

		*v = many

		return nil
	default:
		return fmt.Errorf("line %d: expected a string or a list of strings", node.Line)
	}
}
