# squid-oidc-auth

A Squid authentication helper that accepts a short-lived OIDC token as the proxy password, so traffic through the proxy is authorized per workload instead of by a long-lived shared secret.

Any OIDC provider that publishes a discovery document is supported.

## How It Works

A client puts a token in the proxy URL:

```sh
export https_proxy="http://ci:$TOKEN@proxy.example.com:3128"

curl https://api.internal.example.com/...
```

The token rides as the basic-auth password, so anything honoring `https_proxy` works unchanged.

Squid hands the credential to the helper, which verifies the signature against the provider's published keys, checks issuer, audience, and expiry, enforces the configured claim requirements, and answers with the identity:

```
OK auth_policy=ci oidc_build_branch=main oidc_pipeline_slug=deploy-api ttl=118
```

`squid.conf` then decides where that identity may go:

```
acl ci_deploy     note oidc_pipeline_slug deploy-api deploy-web
acl ci_main       note oidc_build_branch  main
acl internal_apis dstdomain .internal.example.com

http_access allow authenticated ci_deploy ci_main internal_apis
http_access deny all
```

The helper answers *who this is*; Squid decides *where they may go*.

## Getting Started

```console
$ make build
$ cp configs/squid-oidc-auth.example.yaml /etc/squid-oidc-auth.yaml
$ $EDITOR /etc/squid-oidc-auth.yaml
```

Add the Squid side from [`configs/squid.conf.example`](configs/squid.conf.example), then confirm your Squid build propagates annotations from auth helpers:

```console
$ scripts/check-annotation-support.sh
```

Verified on Squid 6.13; older builds may differ - see [`docs/annotations.md`](docs/annotations.md).

To try the whole thing locally:

```console
$ docker compose -f deployments/docker-compose.yaml up --build
```

## Configuration

See [`configs/squid-oidc-auth.example.yaml`](configs/squid-oidc-auth.example.yaml) for a fully commented file. The shape:

```yaml
issuers:
  ci:
    annotations: [build_branch, pipeline_slug]
    audiences: [https://proxy.example.com]
    issuer: https://issuer.example.com
    max_ttl: 2m
    require:
      organization_slug: persona-id
    username_template: "{{.organization_slug}}/{{.pipeline_slug}}"
```

| Key | Meaning |
|-----|---------|
| `annotation_prefix` | Namespace for projected claims. Defaults to `oidc_` |
| `annotations` | Claims projected into Squid annotations for `note` ACLs |
| `audiences` | Accepted `aud` values, OR'd together |
| `issuer` | Issuer URL, used for OIDC discovery |
| `max_ttl` | Cap on how long Squid may cache an answer |
| `policy_annotation` | Key naming the entry that accepted the token. Defaults to `auth_policy`; `""` sends nothing |
| `require` | Claims that must match for the token to be accepted at all |
| `username_template` | Go template over claims, rendering the identity named in the helper's logs and, with `verify_username`, the login a client must send |
| `verify_username` | Reject a request whose login does not equal the rendered username. Off by default |

`policy_annotation` is sent for every token and deliberately sits outside `annotation_prefix`. A provider with its own `policy` claim would otherwise have nowhere to project it, since the two would collide at every prefix - and a prefixed key would read in `squid.conf` as something the helper found in the token rather than something it decided. Move either one if they clash.

Several entries may share an `issuer` URL. Tokens are routed by their `iss` claim to that issuer's policies, and the first in name order whose `audiences` and `require` both accept the token decides the identity - which is how two tenants of one provider get different usernames, annotations, or TTLs.

Configuration is validated at startup, and unknown fields are rejected - a typo in a `require` key would otherwise be dropped silently, widening who the proxy trusts.

Only asymmetric signatures are accepted: `EdDSA`, `ES256/384/512`, `PS256/384/512`, and `RS256/384/512`. The set is fixed rather than read from the provider's discovery document, so a provider cannot nominate an HMAC algorithm and turn its own published verification key into a signing key. A provider signing with anything else will be rejected at verification, not at startup.

### Mandatory `require`

Hosted issuers are often multi-tenant: one issuer signs for every customer of the provider, and the audience is usually chosen by whoever requests the token. Anyone with an account there can mint a token carrying your audience. **Issuer and audience alone authenticate nobody.**

`require` is what pins a token to your tenant:

```yaml
require:
  organization_slug: persona-id
```

The helper will fail to start without at least one required claim. Claims are AND'd together and each claim's values are OR'd, so the block above admits any token whose `organization_slug` is `persona-id`. Comparison is exact - regular expressions and wildcards are not supported.

The claim depends on the provider: `organization_slug` for Buildkite, `repository_owner` for GitHub Actions, `namespace_path` for GitLab, `hd` for Google Workspace.

## Caching

Workload identity tokens are short-lived; five minutes is common. The helper emits `ttl=min(max_ttl, token exp - now)`, so a cached answer never outlives the token that earned it.

Squid's basic-authentication scheme may ignore `ttl=` and use `credentialsttl` instead, so **set `credentialsttl` below your token lifetime as well**:

```
auth_param basic credentialsttl 2 minutes
```

## Operating

The helper logs to **stderr** only - stdout carries the protocol, where a stray line would be read as a response.

| Flag | Default | Meaning |
|------|---------|---------|
| `--concurrent` | `false` | Expect a channel ID per request. Must match `concurrency=` in `squid.conf` |
| `--config` | `/etc/squid-oidc-auth.yaml` | Configuration file |
| `--log-level` | `info` | `debug`, `info`, `warn`, or `error` |

It exits non-zero on a bad config or unreachable issuer, rather than starting and incorrectly denying everything.

Response codes separate a rejected token from a broken helper: a bad token is `ERR`, an unreachable provider is `BH`. Rejection reasons go to the log, not `message=`, which can reach the client and would describe your policy.

## Installing

The helper is not a service - Squid spawns it as a child process - so the binary must live alongside Squid. Released images carry it and nothing else:

```dockerfile
FROM ghcr.io/persona-id/squid-oidc-auth:1.0.0 AS helper
FROM ubuntu/squid:latest
COPY --from=helper /usr/local/bin/squid-oidc-auth /usr/local/bin/
```

The image is BusyBox-based, so copying the binary out works too - into a shared volume for a Kubernetes initContainer, or onto a host running Squid directly:

```console
$ docker run --rm -v /usr/local/bin:/mnt ghcr.io/persona-id/squid-oidc-auth:1.0.0 \
    cp /usr/local/bin/squid-oidc-auth /mnt/
```

Release archives are attached to each GitHub release for host installs.

## Development

```console
$ make ci        # build, version check, format check, lint, test, vulncheck
$ make test      # go test -race ./...
$ make fuzz      # 60s soak on the response encoder
$ make snapshot  # the full release pipeline, without publishing
```

Tool versions are pinned in [`.tool-versions`](.tool-versions), read from there by the Makefile, both workflows, and GoReleaser. `make check-versions` catches the few places that must repeat a version.

Layout follows [golang-standards/project-layout](https://github.com/golang-standards/project-layout):

| Path | Contents |
|------|----------|
| `build/package/` | Dockerfile for the released image |
| `cmd/squid-oidc-auth/` | Entry point, flags, wiring |
| `configs/` | Commented example configurations |
| `deployments/` | Local Squid + helper via docker-compose |
| `docs/` | Protocol reference and the annotations decision |
| `internal/auth/` | Request-to-response logic |
| `internal/config/` | YAML loading and validation |
| `internal/oidc/` | Discovery and token verification |
| `internal/oidctest/` | In-process OIDC provider for tests |
| `internal/protocol/` | Squid helper line protocol |
| `test/e2e/` | Tests driving the built binary as Squid does |

## Further Reading

- [`docs/annotations.md`](docs/annotations.md) - how claims become `note` ACLs, how to verify support, and the fallback
- [`docs/protocol.md`](docs/protocol.md) - the helper protocol, and why the response encoder rejects control characters
