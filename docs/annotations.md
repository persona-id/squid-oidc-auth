# Annotations

## Context

The helper runs as a Squid **basic authentication** helper, so it is handed a credential and nothing else - no URL, no method, no destination. Authorization has to happen in `squid.conf` against something the helper reports back.

It projects the token's claims into Squid **annotations**, which `squid.conf` matches with `note` ACLs:

```
# helper answers:
#   OK auth_policy=ci oidc_build_branch=main oidc_pipeline_slug=deploy-api ttl=118

acl ci_deploy note oidc_pipeline_slug deploy-api deploy-web
acl ci_main   note oidc_build_branch  main

http_access allow authenticated ci_deploy ci_main internal_apis
```

That is claim-level policy with one helper process and one signature check.

`auth_policy` is sent for every token, naming the config entry that accepted it. Its key comes from `policy_annotation`, not `annotation_prefix`, so a provider with its own `policy` claim can still project it. Where several entries share an issuer URL, that is the only signal saying which one matched, so `squid.conf` can gate on the policy instead of restating the claims it matches on:

```
acl team_a note auth_policy team-a

http_access allow authenticated team_a internal_apis
```

## Verifying Support

Annotations are long established for `external_acl_type` helpers. Support in `auth_param` helpers has varied across Squid versions, so check yours:

```console
$ scripts/check-annotation-support.sh
Probing ubuntu/squid:latest ...

Squid version: Squid Cache: Version 6.13
HTTP status through the proxy: 200

RESULT: annotations survived.
```

Verified on Squid 6.13. The script runs your image with a stub helper answering `OK user=probe oidc_probe=yes`, and a policy whose only allow rule is `note oidc_probe yes`. A `403` means the annotation did not survive.

Pass an image to test a specific version:

```console
$ scripts/check-annotation-support.sh ubuntu/squid:5.7-22.04_edge
```

## Logging the Verified Identity

`%ul` in a `logformat` records the login the client sent, which Squid keeps as the transaction's username whatever the helper answers. Log the annotations instead, which come from the token:

```
logformat oidc %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %note{auth_policy} %note{oidc_organization_slug} %Sh/%<a %mt
```

Set `verify_username` on an issuer to have the helper reject a request whose login does not equal the rendered `username`. That makes `%ul` and `proxy_auth` meaningful, at the cost of every client sending the rendered username as its basic-auth login.
