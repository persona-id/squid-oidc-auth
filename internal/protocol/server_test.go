package protocol_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/persona-id/squid-oidc-auth/internal/protocol"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestServerRunSequential(t *testing.T) {
	t.Parallel()

	var out strings.Builder

	srv := &protocol.Server{
		Handler: protocol.HandlerFunc(func(_ context.Context, req protocol.Request) protocol.Response {
			return protocol.Response{
				ChannelID: req.ChannelID,
				Code:      protocol.CodeOK,
				Pairs:     []protocol.Pair{{Key: "user", Value: req.Field(0)}},
			}
		}),
		Logger: discardLogger(),
		Stdin:  strings.NewReader("alex token\nblake token\n"),
		Stdout: &out,
	}

	if err := srv.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	want := "OK user=alex\nOK user=blake\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// TestServerRunConcurrentInterleaves checks that responses stay whole lines and
// every channel is answered exactly once, even when handlers finish out of
// order.
func TestServerRunConcurrentInterleaves(t *testing.T) {
	t.Parallel()

	const requests = 50

	var in strings.Builder
	for i := range requests {
		fmt.Fprintf(&in, "%d alex token\n", i)
	}

	// Release every handler only once all of them have arrived, so the
	// completion order cannot match the request order.
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		out   strings.Builder
	)

	wg.Add(requests)

	srv := &protocol.Server{
		Concurrent: true,
		Handler: protocol.HandlerFunc(func(_ context.Context, req protocol.Request) protocol.Response {
			wg.Done()
			<-start

			return protocol.Response{ChannelID: req.ChannelID, Code: protocol.CodeOK}
		}),
		Logger: discardLogger(),
		Stdin:  strings.NewReader(in.String()),
		Stdout: &out,
	}

	go func() {
		wg.Wait()
		close(start)
	}()

	if err := srv.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	seen := make(map[string]bool, requests)

	for line := range strings.Lines(strings.TrimSuffix(out.String(), "\n")) {
		line = strings.TrimSuffix(line, "\n")
		if seen[line] {
			t.Errorf("duplicate response %q", line)
		}

		seen[line] = true
	}

	for i := range requests {
		want := strconv.Itoa(i) + " OK"
		if !seen[want] {
			t.Errorf("missing response %q", want)
		}
	}
}

func TestServerRunUnparseableLine(t *testing.T) {
	t.Parallel()

	var out strings.Builder

	srv := &protocol.Server{
		Concurrent: true,
		Handler: protocol.HandlerFunc(func(_ context.Context, _ protocol.Request) protocol.Response {
			t.Error("handler called for an unparseable line")

			return protocol.Response{Code: protocol.CodeOK}
		}),
		Logger: discardLogger(),
		Stdin:  strings.NewReader("not-a-channel-id alex token\n"),
		Stdout: &out,
	}

	if err := srv.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if !strings.HasPrefix(out.String(), "BH ") {
		t.Errorf("output = %q, want a BH response", out.String())
	}
}

// TestServerRunUnrepresentableResponse covers a handler returning data that
// cannot be encoded: the server must answer BH rather than emit a line that
// Squid would read as two responses.
func TestServerRunUnrepresentableResponse(t *testing.T) {
	t.Parallel()

	var out strings.Builder

	srv := &protocol.Server{
		Concurrent: true,
		Handler: protocol.HandlerFunc(func(_ context.Context, req protocol.Request) protocol.Response {
			return protocol.Response{
				ChannelID: req.ChannelID,
				Code:      protocol.CodeOK,
				Pairs:     []protocol.Pair{{Key: "user", Value: "alex\n9 OK user=root"}},
			}
		}),
		Logger: discardLogger(),
		Stdin:  strings.NewReader("3 alex token\n"),
		Stdout: &out,
	}

	if err := srv.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if out.String() != "3 BH\n" {
		t.Errorf("output = %q, want %q", out.String(), "3 BH\n")
	}
}

func TestServerRunStopsOnCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	srv := &protocol.Server{
		Handler: protocol.HandlerFunc(func(_ context.Context, _ protocol.Request) protocol.Response {
			t.Error("handler called after cancellation")

			return protocol.Response{Code: protocol.CodeOK}
		}),
		Logger: discardLogger(),
		Stdin:  strings.NewReader("alex token\n"),
		Stdout: io.Discard,
	}

	if err := srv.Run(ctx); err == nil {
		t.Error("Run() error = nil, want context cancellation")
	}
}
