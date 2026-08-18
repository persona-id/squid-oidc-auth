// Package auth answers Squid's basic-authentication lookups by verifying the
// supplied OIDC token and describing the identity behind it.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/persona-id/squid-oidc-auth/internal/oidc"
	"github.com/persona-id/squid-oidc-auth/internal/protocol"
)

// Field positions in a basic-authentication helper request. Squid sends
// "username password"; the login is whatever the client put before the colon in
// the proxy URL, so only the password is trusted unless the issuer has asked for
// the login to be checked against the token.
const (
	loginField = 0
	tokenField = 1
)

// DefaultTimeout bounds one verification. A token naming a key the provider has
// not published sends go-oidc to refetch the key set on the request path, over
// an HTTP client with no timeout of its own, so without this a provider that
// accepts connections and never answers would pin the request forever. Squid
// only has children x concurrency slots, and a token needs no valid signature to
// reach this path, so unbounded waits are a way to stop authentication entirely.
const DefaultTimeout = 10 * time.Second

// Handler verifies the credential in each request and reports the result.
type Handler struct {
	Logger *slog.Logger
	// Now defaults to time.Now. Tests set it to make the ttl= they assert on
	// deterministic.
	Now func() time.Time
	// Timeout defaults to DefaultTimeout.
	Timeout  time.Duration
	Verifier Verifier
}

// Handle implements protocol.Handler.
func (h *Handler) Handle(ctx context.Context, req protocol.Request) protocol.Response {
	token := req.Field(tokenField)
	if token == "" {
		return h.reject(req, "no credential supplied")
	}

	timeout := h.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := h.Verifier.Verify(ctx, token)
	if err != nil {
		// Detail goes to the log, not to Squid: message= can reach the client,
		// and the specifics of why a token failed describe our policy.
		if oidc.IsTemporary(err) {
			h.Logger.Error("verification unavailable", "error", err)

			return protocol.Response{
				ChannelID: req.ChannelID,
				Code:      protocol.CodeBH,
				Pairs:     []protocol.Pair{{Key: "message", Value: "verification unavailable"}},
			}
		}

		h.Logger.Info("credential rejected", "error", err)

		return h.reject(req, summarize(err))
	}

	// The policy name goes out for every token: with several policies sharing an
	// issuer, it is the only thing that says which one accepted this one, and it
	// saves squid.conf restating the claims that policy matches on.
	// Squid keeps the login as the transaction's username whatever the helper
	// answers, so an issuer that wants %ul or proxy_auth to mean anything has to
	// have the login checked against the token here.
	if result.Issuer.VerifyUsername && req.Field(loginField) != result.Username {
		h.Logger.Info("login does not match the token",
			"login", req.Field(loginField), "expected", result.Username)

		return h.reject(req, "login does not match the credential")
	}

	// No user= pair: Squid's Basic scheme discards it and keeps the client's
	// login, so sending it would only suggest an authority it does not have. The
	// identity travels in the annotations below, which squid.conf can act on.
	var pairs []protocol.Pair

	if key := result.Issuer.PolicyAnnotationKey(); key != "" {
		pairs = append(pairs, protocol.Pair{Key: key, Value: result.Issuer.Name})
	}

	for _, claim := range result.Issuer.Annotations {
		key := result.Issuer.AnnotationKey(claim)

		// A claim the provider did not send is simply absent from the response;
		// a `note` ACL on it then does not match, which is the safe direction.
		for _, value := range oidc.ClaimStrings(result.Claims[claim]) {
			pairs = append(pairs, protocol.Pair{Key: key, Value: value})
		}
	}

	// Truncation rounds down, so a cached answer never outlives its token.
	pairs = append(pairs, protocol.Pair{
		Key:   "ttl",
		Value: strconv.Itoa(int(cacheTTL(result, h.now()).Seconds())),
	})

	h.Logger.Debug("credential accepted", "user", result.Username, "issuer", result.Issuer.Name)

	return protocol.Response{
		ChannelID: req.ChannelID,
		Code:      protocol.CodeOK,
		Pairs:     pairs,
	}
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}

	return time.Now()
}

func (h *Handler) reject(req protocol.Request, message string) protocol.Response {
	return protocol.Response{
		ChannelID: req.ChannelID,
		Code:      protocol.CodeERR,
		Pairs:     []protocol.Pair{{Key: "message", Value: message}},
	}
}

// Verifier is the part of oidc.Verifier this package depends on, named here so
// tests can substitute one without a network or a signing key.
type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.Result, error)
}

// cacheTTL is how long Squid may reuse this answer: never past the point where
// the token itself stops being valid, and never longer than the issuer allows.
//
// Squid's basic-authentication scheme may ignore ttl= and cache according to
// credentialsttl instead, so this is a tightening, not a guarantee. Set
// credentialsttl below the token lifetime as well.
func cacheTTL(result *oidc.Result, now time.Time) time.Duration {
	ttl := result.Expiry.Sub(now)

	if limit := result.Issuer.MaxTTL.Duration(); limit > 0 && limit < ttl {
		ttl = limit
	}

	return max(ttl, 0)
}

// summarize reduces a verification failure to a category safe to hand back to
// the client, which may be outside our trust boundary.
func summarize(err error) string {
	switch {
	case errors.Is(err, oidc.ErrAudienceMismatch):
		return "token audience is not accepted"
	case errors.Is(err, oidc.ErrMalformedToken):
		return "credential is not a JWT"
	case errors.Is(err, oidc.ErrRequirementUnmet):
		return "token is not authorized for this proxy"
	case errors.Is(err, oidc.ErrUnknownIssuer):
		return "token issuer is not trusted"
	default:
		return "token is not valid"
	}
}
