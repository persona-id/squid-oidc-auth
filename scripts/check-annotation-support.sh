#!/usr/bin/env bash
#
# Determines whether your Squid build propagates annotations from a *basic
# authentication* helper into `note` ACLs.
#
# This is the one assumption squid-oidc-auth's design rests on. Annotations are
# well established for external_acl_type helpers; support in auth_param helpers
# has varied across Squid versions. Rather than guess, probe it: this script
# runs Squid with a stub helper that always answers
#
#     OK user=probe oidc_probe=yes
#
# and a policy that allows a request only when `note oidc_probe yes` matches. If
# the request is refused with 403, annotations did not survive, and you should
# fall back to encoding policy in the username template and gating with
# proxy_auth ACLs. See docs/annotations.md.
#
# Usage:
#   scripts/check-annotation-support.sh [squid-image]
#
# Requires Docker. Nothing is written outside a temporary directory.

set -euo pipefail

SQUID_IMAGE="${1:-${SQUID_IMAGE:-ubuntu/squid:latest}}"
CONTAINER_NAME="squid-oidc-annotation-probe-$$"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"; docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT

cat >"$workdir/helper.sh" <<'HELPER'
#!/bin/sh
# Stub auth helper: accepts everything, and attaches one annotation.
while read -r _line; do
  echo "OK user=probe oidc_probe=yes"
done
HELPER
chmod 0755 "$workdir/helper.sh"

cat >"$workdir/squid.conf" <<'CONF'
auth_param basic program /probe/helper.sh
auth_param basic children 1
auth_param basic realm probe
auth_param basic credentialsttl 1 second

acl authenticated proxy_auth REQUIRED
acl has_annotation note oidc_probe yes

acl Safe_ports port 80 443
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny !authenticated

# The whole probe: this is the only rule that can allow the request, and it can
# only match if the annotation survived from the auth helper.
http_access allow has_annotation

http_access deny all

http_port 3128
cache deny all
CONF

echo "Probing $SQUID_IMAGE ..."

docker run --rm --detach \
  --name "$CONTAINER_NAME" \
  --publish 127.0.0.1:0:3128 \
  --volume "$workdir/squid.conf:/etc/squid/squid.conf:ro" \
  --volume "$workdir:/probe:ro" \
  "$SQUID_IMAGE" >/dev/null

port="$(docker port "$CONTAINER_NAME" 3128/tcp | head -n1 | sed 's/.*://')"

# Wait for Squid to accept connections.
for _ in $(seq 1 30); do
  if curl --silent --max-time 1 --proxy "http://probe:secret@127.0.0.1:$port" \
    --output /dev/null --write-out '' http://example.com/ 2>/dev/null; then
    break
  fi
  sleep 1
done

status="$(curl --silent --show-error --max-time 10 \
  --proxy "http://probe:secret@127.0.0.1:$port" \
  --output /dev/null --write-out '%{http_code}' \
  http://example.com/ || true)"

echo
echo "Squid version: $(docker exec "$CONTAINER_NAME" squid -v 2>/dev/null | head -n1 || echo unknown)"
echo "HTTP status through the proxy: $status"
echo

case "$status" in
  403)
    echo "RESULT: annotations did NOT survive."
    echo
    echo "Squid refused the request, so 'note oidc_probe yes' never matched."
    echo "Use the username-template fallback described in docs/annotations.md."
    exit 1
    ;;
  000)
    echo "RESULT: inconclusive - no HTTP response."
    echo
    echo "Squid may have failed to start. Container log follows:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -n 30
    exit 2
    ;;
  *)
    echo "RESULT: annotations survived."
    echo
    echo "Squid allowed the request, which only the 'note' ACL could do."
    echo "A non-200 status here is fine: it means the request passed policy and"
    echo "then succeeded or failed upstream, which is not what we are testing."
    exit 0
    ;;
esac
