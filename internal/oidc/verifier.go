// Package oidc verifies OIDC ID tokens against the issuers named in the
// configuration and reports the claims the helper acts on.
package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/persona-id/squid-oidc-auth/internal/config"
)

var (
	// ErrAudienceMismatch reports a token issued for an audience this helper
	// does not serve.
	ErrAudienceMismatch = errors.New("token audience is not accepted")
	// ErrMalformedToken reports a credential that is not a JWT at all.
	ErrMalformedToken = errors.New("credential is not a well-formed JWT")
	// ErrRequirementUnmet reports a token whose claims fail the issuer's
	// require block.
	ErrRequirementUnmet = errors.New("token does not satisfy the issuer's requirements")
	// ErrUnknownIssuer reports a token from an issuer this helper does not
	// trust.
	ErrUnknownIssuer = errors.New("token issuer is not configured")
)

// Result is a verified token, reduced to what the helper reports to Squid.
type Result struct {
	Claims   map[string]any
	Expiry   time.Time
	Issuer   *config.Issuer
	Username string
}

// TemporaryError marks a failure caused by the helper's own environment - an
// unreachable provider or a canceled context - rather than by the token. The
// distinction drives the response code: a token problem is ERR, an environment
// problem is BH, and conflating them would report an outage as a rejected
// request, or vice versa.
type TemporaryError struct {
	Err error
}

// IsTemporary reports whether err represents an environment failure rather than
// a problem with the token.
func IsTemporary(err error) bool {
	var temporary *TemporaryError

	return errors.As(err, &temporary)
}

// Error implements error.
func (e *TemporaryError) Error() string {
	return e.Err.Error()
}

// Unwrap allows errors.Is and errors.As to reach the cause.
func (e *TemporaryError) Unwrap() error {
	return e.Err
}

// Verifier checks tokens against every configured issuer. It is safe for
// concurrent use; the underlying key sets are cached and refreshed on demand.
type Verifier struct {
	issuers map[string]*issuerGroup
}

// NewVerifier performs OIDC discovery for every configured issuer URL, once per
// URL however many policies share it. Discovery is a network call, so ctx bounds
// startup rather than any later verification. Failing here is deliberate: a
// helper that cannot reach an issuer should not start and then quietly deny
// every request.
func NewVerifier(ctx context.Context, cfg *config.Config) (*Verifier, error) {
	// Policies are grouped by issuer URL and kept in name order, which is the
	// order Verify consults them in.
	groups := make(map[string][]*config.Issuer, len(cfg.Issuers))
	for _, name := range slices.Sorted(maps.Keys(cfg.Issuers)) {
		issuerCfg := cfg.Issuers[name]
		groups[issuerCfg.Issuer] = append(groups[issuerCfg.Issuer], issuerCfg)
	}

	urls := slices.Sorted(maps.Keys(groups))

	type discovery struct {
		err      error
		verifier *goidc.IDTokenVerifier
	}

	// Concurrently, not for speed - it's unlikely there will be more than a
	// handful of issuers - but because every discovery shares ctx's deadline.
	// Done in sequence, one slow issuer consumes the whole budget and the
	// issuers after it fail on a deadline they never got a chance to meet, so
	// the startup error could name a provider that wasn't given enough time.
	results := make([]discovery, len(urls))

	var wg sync.WaitGroup

	for i, url := range urls {
		wg.Go(func() {
			provider, err := goidc.NewProvider(ctx, url)
			if err != nil {
				results[i].err = fmt.Errorf("discovering issuer %s: %w", url, err)

				return
			}

			// go-oidc checks a single client ID; audience is checked in Verify
			// so that a list of accepted audiences behaves the same as one.
			results[i].verifier = provider.Verifier(&goidc.Config{SkipClientIDCheck: true})
		})
	}

	wg.Wait()

	issuers := make(map[string]*issuerGroup, len(urls))

	// Walked in URL order, so several unreachable issuers always report the same
	// one rather than whichever lost the race.
	for i, url := range urls {
		if results[i].err != nil {
			return nil, results[i].err
		}

		issuers[url] = &issuerGroup{policies: groups[url], verifier: results[i].verifier}
	}

	return &Verifier{issuers: issuers}, nil
}

// Verify checks a raw ID token's signature, issuer, and expiry, then applies the
// first policy for that issuer whose audience and require block both accept the
// token, and renders the username reported to Squid.
func (v *Verifier) Verify(ctx context.Context, rawIDToken string) (*Result, error) {
	// Route on the unverified issuer claim. This is safe because the verifier
	// chosen here pins that issuer's keys and re-checks iss against them, so a
	// forged iss can only select a verifier that will reject the token.
	issuerURL, err := unverifiedIssuer(rawIDToken)
	if err != nil {
		return nil, err
	}

	group, ok := v.issuers[issuerURL]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownIssuer, issuerURL)
	}

	// One signature check for the whole group: policies sharing an issuer share
	// its keys.
	idToken, err := group.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, classify(fmt.Errorf("verifying token from %s: %w", issuerURL, err))
	}

	claims, err := decodeClaims(idToken)
	if err != nil {
		return nil, err
	}

	return group.apply(idToken, claims)
}

// issuerGroup is every policy configured for one issuer URL, sharing the single
// verifier built from that issuer's keys.
type issuerGroup struct {
	// policies are in name order; the first whose audience and require both
	// accept a token decides the identity.
	policies []*config.Issuer
	verifier *goidc.IDTokenVerifier
}

// apply returns the identity described by the first policy that accepts the
// token. The signature is already verified by the time this runs.
func (g *issuerGroup) apply(idToken *goidc.IDToken, claims map[string]any) (*Result, error) {
	// The first require failure is kept so a single-policy issuer still reports
	// exactly why it turned the token away.
	var (
		audienceMatched bool
		requireErr      error
	)

	for _, policy := range g.policies {
		if !slices.ContainsFunc(idToken.Audience, func(aud string) bool {
			return slices.Contains(policy.Audiences, aud)
		}) {
			continue
		}

		audienceMatched = true

		if err := matchRequire(policy.Require, claims); err != nil {
			if requireErr == nil {
				requireErr = err
			}

			continue
		}

		// The policy accepted the token, so a broken username template is its
		// problem to report rather than a reason to try the next one.
		username, err := policy.RenderUsername(claims)
		if err != nil {
			return nil, err
		}

		return &Result{
			Claims:   claims,
			Expiry:   idToken.Expiry,
			Issuer:   policy,
			Username: username,
		}, nil
	}

	if !audienceMatched {
		return nil, fmt.Errorf("%w: %s", ErrAudienceMismatch, strings.Join(idToken.Audience, ", "))
	}

	return nil, requireErr
}

// ClaimStrings renders a claim as the list of string values it can be matched
// against, since require and the projected annotations both compare text.
//
// Providers are inconsistent about whether a single-valued claim arrives as a
// string or a one-element list. Numbers and booleans are compared by their
// literal JSON text, so a claim of 1234 matches the configured value "1234".
// A claim that is an object has no string form and matches nothing.
func ClaimStrings(claim any) []string {
	switch value := claim.(type) {
	case nil:
		return nil
	case bool:
		return []string{strconv.FormatBool(value)}
	case float64:
		return []string{strconv.FormatFloat(value, 'f', -1, 64)}
	case json.Number:
		return []string{value.String()}
	case string:
		return []string{value}
	case []any:
		out := make([]string, 0, len(value))

		for _, entry := range value {
			out = append(out, ClaimStrings(entry)...)
		}

		return out
	case []string:
		return value
	default:
		return nil
	}
}

// classify decides whether a verification failure is the token's fault or the
// environment's. Anything it cannot attribute to the environment is treated as
// a token failure, so an unrecognized error denies access rather than handing
// Squid an outage to interpret.
func classify(err error) error {
	var (
		netErr net.Error
		urlErr *url.Error
	)

	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr), errors.As(err, &urlErr):
		return &TemporaryError{Err: err}
	default:
		return err
	}
}

// decodeClaims reads the token's claims with numbers left as json.Number rather
// than float64. Decoded as float64, an integer claim above 2^53 - an account or
// run ID, say - would be compared and logged as a value the provider never sent.
func decodeClaims(idToken *goidc.IDToken) (map[string]any, error) {
	var raw json.RawMessage
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("reading claims: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}

	return claims, nil
}

// matchRequire enforces the issuer's require block: every claim must match, and
// a claim matches when any of its values is allowed.
func matchRequire(require map[string]config.Values, claims map[string]any) error {
	for _, claim := range slices.Sorted(maps.Keys(require)) {
		allowed := require[claim]

		present, ok := claims[claim]
		if !ok {
			return fmt.Errorf("%w: claim %s is absent", ErrRequirementUnmet, claim)
		}

		values := ClaimStrings(present)
		if len(values) == 0 {
			return fmt.Errorf("%w: claim %s has no usable value", ErrRequirementUnmet, claim)
		}

		if !slices.ContainsFunc(values, func(value string) bool {
			return slices.Contains(allowed, value)
		}) {
			return fmt.Errorf("%w: claim %s is %s", ErrRequirementUnmet, claim, strings.Join(values, ", "))
		}
	}

	return nil
}

// unverifiedIssuer reads the iss claim without checking the signature, purely to
// choose which issuer's keys to verify against.
func unverifiedIssuer(rawIDToken string) (string, error) {
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: got %d segments, want 3", ErrMalformedToken, len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: decoding payload: %w", ErrMalformedToken, err)
	}

	var claims struct {
		Issuer string `json:"iss"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("%w: parsing payload: %w", ErrMalformedToken, err)
	}

	if claims.Issuer == "" {
		return "", fmt.Errorf("%w: payload has no iss claim", ErrMalformedToken)
	}

	return claims.Issuer, nil
}
