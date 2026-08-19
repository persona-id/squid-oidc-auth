package protocol_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/persona-id/squid-oidc-auth/internal/protocol"
)

func TestParseRequest(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		concurrent bool
		line       string
		wantErr    error
		wantFields []string
		wantID     int
	}{
		"basic auth credentials": {
			line:       "bk eyJhbGciOiJSUzI1NiJ9.payload.sig",
			wantFields: []string{"bk", "eyJhbGciOiJSUzI1NiJ9.payload.sig"},
			wantID:     protocol.NoChannel,
		},
		"channel ID consumed when concurrent": {
			concurrent: true,
			line:       "42 bk token",
			wantFields: []string{"bk", "token"},
			wantID:     42,
		},
		// Squid sends two fields for basic auth, so a third led by a number
		// means channel IDs are arriving that this helper is not consuming.
		"channel ID arriving without --concurrent": {
			line:    "42 bk token",
			wantErr: protocol.ErrChannelMismatch,
		},
		// A numeric login is not a channel ID: there are only two fields.
		"numeric login is not mistaken for a channel ID": {
			line:       "42 token",
			wantFields: []string{"42", "token"},
			wantID:     protocol.NoChannel,
		},
		"percent-encoded fields are decoded": {
			line:       "user%40example.com pass%20word",
			wantFields: []string{"user@example.com", "pass word"},
			wantID:     protocol.NoChannel,
		},
		"plus is not a space": {
			line:       "bk abc+def",
			wantFields: []string{"bk", "abc+def"},
			wantID:     protocol.NoChannel,
		},
		"undecodable field passes through": {
			line:       "bk 100%pure",
			wantFields: []string{"bk", "100%pure"},
			wantID:     protocol.NoChannel,
		},
		"empty line": {
			line:    "   ",
			wantErr: protocol.ErrEmptyRequest,
		},
		"no channel ID arriving with --concurrent": {
			concurrent: true,
			line:       "abc bk token",
			wantErr:    protocol.ErrChannelMismatch,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := protocol.ParseRequest(tc.line, tc.concurrent)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseRequest() error = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseRequest() error = %v, want nil", err)
			}

			if got.ChannelID != tc.wantID {
				t.Errorf("ChannelID = %d, want %d", got.ChannelID, tc.wantID)
			}

			if !slices.Equal(got.Fields, tc.wantFields) {
				t.Errorf("Fields = %q, want %q", got.Fields, tc.wantFields)
			}
		})
	}
}

func TestRequestField(t *testing.T) {
	t.Parallel()

	req := protocol.Request{Fields: []string{"bk", "token"}}

	if got := req.Field(1); got != "token" {
		t.Errorf("Field(1) = %q, want %q", got, "token")
	}

	if got := req.Field(7); got != "" {
		t.Errorf("Field(7) = %q, want empty string", got)
	}

	if got := req.Field(-1); got != "" {
		t.Errorf("Field(-1) = %q, want empty string", got)
	}
}

func TestResponseEncode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		resp protocol.Response
		want string
	}{
		"bare code without channel": {
			resp: protocol.Response{ChannelID: protocol.NoChannel, Code: protocol.CodeERR},
			want: "ERR",
		},
		"channel ID is echoed": {
			resp: protocol.Response{ChannelID: 42, Code: protocol.CodeOK},
			want: "42 OK",
		},
		"simple values are unquoted": {
			resp: protocol.Response{
				ChannelID: protocol.NoChannel,
				Code:      protocol.CodeOK,
				Pairs:     []protocol.Pair{{Key: "user", Value: "persona-id/deploy-api"}},
			},
			want: "OK user=persona-id/deploy-api",
		},
		"values with spaces are quoted": {
			resp: protocol.Response{
				ChannelID: protocol.NoChannel,
				Code:      protocol.CodeERR,
				Pairs:     []protocol.Pair{{Key: "message", Value: "token expired"}},
			},
			want: `ERR message="token expired"`,
		},
		"quotes and backslashes are escaped": {
			resp: protocol.Response{
				ChannelID: protocol.NoChannel,
				Code:      protocol.CodeERR,
				Pairs:     []protocol.Pair{{Key: "message", Value: `say "hi\bye"`}},
			},
			want: `ERR message="say \"hi\\bye\""`,
		},
		"empty values are quoted so the pair stays parseable": {
			resp: protocol.Response{
				ChannelID: protocol.NoChannel,
				Code:      protocol.CodeOK,
				Pairs:     []protocol.Pair{{Key: "user", Value: ""}},
			},
			want: `OK user=""`,
		},
		"repeated keys are preserved in order": {
			resp: protocol.Response{
				ChannelID: protocol.NoChannel,
				Code:      protocol.CodeOK,
				Pairs: []protocol.Pair{
					{Key: "oidc_group", Value: "eng"},
					{Key: "oidc_group", Value: "sre"},
				},
			},
			want: "OK oidc_group=eng oidc_group=sre",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.resp.Encode()
			if err != nil {
				t.Fatalf("Encode() error = %v, want nil", err)
			}

			if got != tc.want {
				t.Errorf("Encode() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResponseEncodeRejects covers the injection cases: a value or key that
// would let token-derived data escape its field and forge protocol structure.
func TestResponseEncodeRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		pair    protocol.Pair
		wantErr error
	}{
		"newline in value would forge a second response": {
			pair:    protocol.Pair{Key: "user", Value: "alex\n7 OK user=root"},
			wantErr: protocol.ErrControlCharacter,
		},
		"carriage return in value": {
			pair:    protocol.Pair{Key: "user", Value: "alex\r7 OK"},
			wantErr: protocol.ErrControlCharacter,
		},
		"NUL in value": {
			pair:    protocol.Pair{Key: "user", Value: "alex\x00"},
			wantErr: protocol.ErrControlCharacter,
		},
		"DEL in value": {
			pair:    protocol.Pair{Key: "user", Value: "alex\x7f"},
			wantErr: protocol.ErrControlCharacter,
		},
		"empty key": {
			pair:    protocol.Pair{Key: "", Value: "x"},
			wantErr: protocol.ErrInvalidKey,
		},
		"key containing the separator": {
			pair:    protocol.Pair{Key: "us=er", Value: "x"},
			wantErr: protocol.ErrInvalidKey,
		},
		"key containing a space": {
			pair:    protocol.Pair{Key: "us er", Value: "x"},
			wantErr: protocol.ErrInvalidKey,
		},
		"key containing a newline": {
			pair:    protocol.Pair{Key: "user\nOK", Value: "x"},
			wantErr: protocol.ErrInvalidKey,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := protocol.Response{
				ChannelID: protocol.NoChannel,
				Code:      protocol.CodeOK,
				Pairs:     []protocol.Pair{tc.pair},
			}

			got, err := resp.Encode()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Encode() error = %v, want %v", err, tc.wantErr)
			}

			if got != "" {
				t.Errorf("Encode() = %q on failure, want empty string", got)
			}
		})
	}
}

// FuzzResponseEncode asserts the invariant the whole line protocol rests on:
// a successful encode is always exactly one line, whatever the value holds.
func FuzzResponseEncode(f *testing.F) {
	f.Add("user", "persona-id/deploy-api")
	f.Add("message", "token expired")
	f.Add("user", "alex\n7 OK user=root")
	f.Add("oidc_branch", `refs/heads/"weird\branch"`)

	f.Fuzz(func(t *testing.T, key, value string) {
		resp := protocol.Response{
			ChannelID: 1,
			Code:      protocol.CodeOK,
			Pairs:     []protocol.Pair{{Key: key, Value: value}},
		}

		got, err := resp.Encode()
		if err != nil {
			return
		}

		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("Encode() = %q, want a single line", got)
		}
	})
}
