BIN := $(CURDIR)/bin

# .tool-versions is the single pin for the toolchain. Everything that has to
# repeat a version reads it from here, and `check-versions` guards the two
# places that cannot (go.mod's floor, and the Dockerfile build args).
GO_VERSION := $(shell awk '$$1 == "golang" { print $$2 }' .tool-versions)

# golangci-lint is pinned in .tool-versions and installed as an official binary
# by asdf. Upstream explicitly does not support `go install` or the go.mod tool
# directive for it, so this Makefile does not build it from source.
GOLANGCI_LINT_VERSION := $(shell awk '$$1 == "golangci-lint" { print $$2 }' .tool-versions)

# govulncheck has no asdf plugin, and `go install` is its supported install
# path, so its version is pinned here. This is the only place it appears; CI
# runs `make vulncheck` rather than repeating it.
GOVULNCHECK_VERSION := v1.6.0

.PHONY: build check-versions ci clean fmt fmt-check fuzz lint snapshot test tidy tools vulncheck

build:
	go build -o $(BIN)/squid-oidc-auth ./cmd/squid-oidc-auth

# go.mod states a floor rather than a pin, so it is not a duplicate of
# .tool-versions - but the pin still has to satisfy it, and the Dockerfile
# defaults still have to match it.
check-versions:
	@floor=$$(awk '$$1 == "go" { print $$2 }' go.mod); \
	case "$(GO_VERSION)" in \
		$$floor|$$floor.*) ;; \
		*) echo ".tool-versions pins golang $(GO_VERSION), which does not satisfy go.mod's 'go $$floor'"; exit 1 ;; \
	esac
	@for file in deployments/Dockerfile.squid; do \
		pinned=$$(awk -F= '/^ARG GO_VERSION=/ { print $$2 }' $$file); \
		if [ "$$pinned" != "$(GO_VERSION)" ]; then \
			echo "$$file defaults GO_VERSION to $$pinned, but .tool-versions pins $(GO_VERSION)"; \
			exit 1; \
		fi; \
	done

ci: build check-versions fmt-check lint test vulncheck

clean:
	rm -rf $(BIN)

fmt: tools
	golangci-lint fmt
	go mod tidy

fmt-check: tools
	golangci-lint fmt --diff

# The response encoder is the one place where token-derived data reaches a
# line-oriented wire format, so it gets a longer soak than the unit tests.
fuzz:
	go test -run='^$$' -fuzz=FuzzResponseEncode -fuzztime=60s ./internal/protocol/

lint: tools
	golangci-lint run

# Runs the real release pipeline without publishing anything. dockers_v2 builds
# and pushes in one buildx step, so a snapshot produces platform-suffixed local
# images rather than a multi-arch manifest.
snapshot:
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "goreleaser is not installed. Install the pinned version with:"; \
		echo "    asdf plugin add goreleaser && asdf install"; \
		exit 1; \
	}
	goreleaser release --snapshot --clean

test:
	go test -race ./...

tidy:
	go mod tidy

# Checks that the pinned toolchain is actually what is on PATH, so a stale local
# install cannot report a different set of lint failures than CI does.
tools:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed."; \
		echo "Install the pinned version with:"; \
		echo "    asdf plugin add golangci-lint && asdf install"; \
		exit 1; \
	}
	@installed=$$(golangci-lint version --short 2>/dev/null | tr -d 'v'); \
	if [ "$$installed" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "golangci-lint $$installed is on PATH, but .tool-versions pins $(GOLANGCI_LINT_VERSION)."; \
		echo "Run 'asdf install' to sync."; \
		exit 1; \
	fi

vulncheck: $(BIN)/govulncheck
	$(BIN)/govulncheck ./...

$(BIN)/govulncheck:
	GOBIN=$(BIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
