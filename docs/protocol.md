# The Squid Helper Protocol

Reference for `internal/protocol`, which implements the line protocol Squid speaks to its helper processes.

## Shape

Squid starts the helper as a child process and keeps it running. Requests arrive on stdin, one per line; responses go to stdout, one per line. **stdout carries the protocol and nothing else** - this is why the helper logs exclusively to stderr.

### Requests

For a basic authentication helper, each line is:

```
<username> <password>
```

Both fields are percent-encoded by Squid, so a value containing a space or other reserved character arrives as a single field. `squid-oidc-auth` reads the OIDC token from the **password**; the username is whatever preceded the colon in the client's proxy URL and carries no authority.

Observed on Squid 6.13: a space arrives as `%20` and a literal `%` as `%25`, while `+` is passed through untouched. That last one is why `unescape` uses `url.PathUnescape` and not `url.QueryUnescape`, which would decode `+` to a space and corrupt the credential.

With `concurrency=N` configured, every line is prefixed with a channel ID:

```
<channel-id> <username> <password>
```

The helper must echo that ID on the corresponding response. This is what lets Squid keep several lookups in flight over one pipe but why a response that accidentally spans two lines can be a problem.

### Responses

```
[<channel-id> ]<code>[ key=value]...
```

| Code | Meaning |
|------|---------|
| `OK` | Lookup succeeded, result is positive |
| `ERR` | Lookup succeeded, result is negative - the credential is bad |
| `BH` | The helper failed; Squid applies its on-error policy |

An expired token is `ERR` whereas an unreachable identity provider is `BH` which distinguishes client issues from provider issues.

Keys Squid interprets:

| Key | Effect |
|-----|--------|
| `user` | Ignored by the Basic scheme, which keeps the login the client sent. This helper does not send it |
| `message` | Reason, which may reach the client - so it carries no policy detail |
| `log` | Access-log-only text |
| `ttl` | Seconds Squid may cache this answer |
| `tag`, `clt_conn_tag`, `password` | Reserved for other purposes |

Any other key becomes a transaction annotation, matchable with a `note` ACL. That is the mechanism this project uses to carry claims into `squid.conf`; see [annotations.md](annotations.md).

## Encoding Rules

Values are whitespace-delimited, so anything containing a space, tab, quote, or backslash is double-quoted with backslash escapes:

```
ERR message="token is not valid"
OK auth_policy=ci oidc_build_branch=main ttl=118
```

Empty values are written including the quotes - `key=""`, not a bare `key=`.

### Why `Encode` Returns an Error

`Response.Encode` fails rather than emitting anything containing a control character. Quoting cannot represent a newline: it would end the line, and Squid would read the remainder as an **additional response**. Under `concurrency=`, a forged line beginning with a plausible channel ID could answer `OK` for a request the helper never authorized.

Annotation values come from token claims, which are attacker-influenced in general even though a specific provider may constrain them (git ref names, for instance, cannot contain newlines). The encoder does not rely on that: a response it cannot represent becomes `BH`, and `FuzzResponseEncode` asserts the invariant that a successful encode is always exactly one line.

Keys are checked the same way, and additionally may not contain `=`, since a reader could not otherwise tell where the key ends.

## Ordering

`Response.Pairs` is a slice rather than a map for two reasons: output order is deterministic, which keeps tests and log lines stable; and repeated keys are representable, which multi-valued claims need:

```
OK auth_policy=people oidc_group=eng oidc_group=sre
```

A `note` ACL ORs its values, which is how a `groups` claim becomes usable policy.
