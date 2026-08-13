# Binary-distribution image, built by GoReleaser.
#
# This helper is not a service: Squid spawns it as a child process, so the
# binary has to end up inside a Squid container or on a host running Squid. This
# image exists to carry the binary there, not to be run on its own.
#
# The preferred way to consume it needs no shell, and pins by digest exactly
# what you shipped:
#
#     FROM ghcr.io/persona-id/squid-oidc-auth:1.0.0 AS helper
#     FROM ubuntu/squid:latest
#     COPY --from=helper /usr/local/bin/squid-oidc-auth /usr/local/bin/
#
# BusyBox rather than scratch or distroless so the copy-out pattern also works -
# a Kubernetes initContainer writing to a shared volume, or a host install:
#
#     docker run --rm -v /usr/local/bin:/mnt ghcr.io/persona-id/squid-oidc-auth:1.0.0 \
#       cp /usr/local/bin/squid-oidc-auth /mnt/
#
# Deliberately no ENTRYPOINT and no USER: the default shell is what makes the
# copy-out work, and writing to a bind mount usually needs root.
#
# GoReleaser cross-compiles the binaries and stages them under one directory per
# target platform, so there is no Go toolchain here and nothing to keep in step
# with .tool-versions. A bare `docker build` will fail for want of them; use
# `make snapshot`, which runs the real pipeline.
FROM busybox:1.38-uclibc

# Supplied by buildx and redeclared here to be usable in this stage. It selects
# the matching binary from the staged layout, which is <os>/<arch>/<binary>.
ARG TARGETPLATFORM

COPY $TARGETPLATFORM/squid-oidc-auth /usr/local/bin/squid-oidc-auth
