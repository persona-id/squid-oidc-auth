package protocol

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// maxLineBytes bounds a single request line. ID tokens carrying group claims
// routinely run past the 64KiB bufio default.
const maxLineBytes = 1 << 20

// Handler answers a single lookup. Implementations must be safe for concurrent
// use when the server runs in concurrent mode.
type Handler interface {
	Handle(ctx context.Context, req Request) Response
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req Request) Response

// Handle calls f.
func (f HandlerFunc) Handle(ctx context.Context, req Request) Response {
	return f(ctx, req)
}

// Server runs the helper's request loop over a pair of streams, normally the
// process's stdin and stdout.
type Server struct {
	// Concurrent must match the concurrency= setting on the Squid side. When
	// true, requests carry a channel ID and are answered in parallel.
	Concurrent bool
	Handler    Handler
	Logger     *slog.Logger
	Stdin      io.Reader
	Stdout     io.Writer
}

// Run reads requests until stdin reaches EOF or ctx is canceled, and returns
// once every in-flight request has been answered.
//
// Canceling ctx stops the loop between requests; it cannot interrupt a read
// already blocked on stdin, so a helper that must exit promptly should also
// close stdin.
func (s *Server) Run(ctx context.Context) error {
	var (
		wg      sync.WaitGroup
		writeMu sync.Mutex
	)

	defer wg.Wait()

	respond := func(resp Response) {
		line, err := resp.Encode()
		if err != nil {
			// The answer we meant to send cannot be represented, so send none
			// of it. Degrading to a partial line would be worse than failing.
			s.Logger.Error("encoding response", "error", err, "channel_id", resp.ChannelID)

			line, err = Response{ChannelID: resp.ChannelID, Code: CodeBH}.Encode()
			if err != nil {
				s.Logger.Error("encoding fallback response", "error", err)

				return
			}
		}

		writeMu.Lock()
		defer writeMu.Unlock()

		if _, err := fmt.Fprintln(s.Stdout, line); err != nil {
			s.Logger.Error("writing response", "error", err)
		}
	}

	scanner := bufio.NewScanner(s.Stdin)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxLineBytes)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}

		req, err := ParseRequest(scanner.Text(), s.Concurrent)
		if err != nil {
			// A line we cannot even parse has no channel ID to echo, so the
			// only honest answer is an unaddressed failure.
			s.Logger.Error("parsing request", "error", err)
			respond(Response{
				ChannelID: NoChannel,
				Code:      CodeBH,
				Pairs:     []Pair{{Key: "message", Value: err.Error()}},
			})

			continue
		}

		if !s.Concurrent {
			respond(s.Handler.Handle(ctx, req))

			continue
		}

		wg.Go(func() {
			respond(s.Handler.Handle(ctx, req))
		})
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading requests: %w", err)
	}

	return nil
}
