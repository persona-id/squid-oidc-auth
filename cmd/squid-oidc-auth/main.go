// squid-oidc-auth is a Squid basic-authentication helper that accepts an OIDC
// token as the proxy password.
//
// Squid runs it as a long-lived child process, writing "username password" per
// line on stdin and reading one response per line from stdout. See
// configs/squid.conf.example for the matching Squid configuration.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/persona-id/squid-oidc-auth/internal/auth"
	"github.com/persona-id/squid-oidc-auth/internal/config"
	"github.com/persona-id/squid-oidc-auth/internal/oidc"
	"github.com/persona-id/squid-oidc-auth/internal/protocol"
)

// discoveryTimeout bounds startup. Squid gives a helper a limited window to
// become useful, and hanging on an unreachable issuer is worse than exiting.
const discoveryTimeout = 30 * time.Second

// Build metadata, injected by GoReleaser's ldflags. The defaults are what a
// plain `go build` produces.
var (
	commit  = "none"
	version = "dev"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "squid-oidc-auth: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		concurrent = flag.Bool("concurrent", false,
			"expect a channel ID on each request; must match concurrency= in squid.conf")
		configPath = flag.String("config", "/etc/squid-oidc-auth.yaml", "path to the configuration file")
		logLevel   = flag.String("log-level", "info", "one of debug, info, warn, error")
	)

	flag.Parse()

	// Flag parsing stops at the first bare argument, so anything after one is
	// silently dropped, leaving the helper running with defaults it was never
	// asked for. Refuse rather than start half-configured.
	if flag.NArg() > 0 {
		return fmt.Errorf(
			"unexpected argument %q: this helper takes flags only, and parsing stops at the "+
				"first bare argument, so any flag after it would be ignored",
			flag.Arg(0),
		)
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		return err
	}

	// stderr only: stdout carries the protocol, and a stray log line there
	// would be read as a response.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	discoveryCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	// Discovery failure is fatal rather than deferred: a helper that starts
	// without reachable issuers would incorrectly deny every request.
	verifier, err := oidc.NewVerifier(discoveryCtx, cfg)
	if err != nil {
		return err
	}

	logger.Info("helper ready",
		"commit", commit,
		"concurrent", *concurrent,
		"config", *configPath,
		"issuers", len(cfg.Issuers),
		"version", version,
	)

	server := &protocol.Server{
		Concurrent: *concurrent,
		Handler: &auth.Handler{
			Logger:   logger,
			Verifier: verifier,
		},
		Logger: logger,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
	}

	if err := server.Run(ctx); err != nil {
		return err
	}

	logger.Info("stdin closed, exiting")

	return nil
}

func parseLevel(name string) (slog.Level, error) {
	var level slog.Level

	if err := level.UnmarshalText([]byte(name)); err != nil {
		return level, fmt.Errorf("parsing log level %q: %w", name, err)
	}

	return level, nil
}
