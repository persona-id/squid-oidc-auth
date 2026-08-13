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
# GoReleaser cross-compiles the binary and places it at the root of the build
# context, so there is no Go toolchain here and nothing to keep in step with
# .tool-versions. A bare `docker build` will fail for want of that binary; use
# `make snapshot`, which runs the real pipeline.
FROM busybox:1.37-uclibc

COPY squid-oidc-auth /usr/local/bin/squid-oidc-auth
