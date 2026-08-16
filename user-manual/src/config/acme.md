# Automatic Certificates (ACME)

River can obtain and renew TLS certificates for you, from a certificate
authority such as [Let's Encrypt], using the [ACME] protocol defined in
RFC 8555. Once configured, this needs no further attention: River obtains a
certificate before it starts serving traffic, and replaces it before it
expires.

[Let's Encrypt]: https://letsencrypt.org
[ACME]: https://datatracker.ietf.org/doc/html/rfc8555

There are two parts to the configuration:

* A top level `acme` section, holding the settings that apply to every managed
  domain - which CA to use, where to store certificates, when to renew.
* An `acme-domains` argument on each listener, naming the domains that listener
  serves.

Both are optional. A configuration with neither behaves exactly as it did
before, and River never contacts a certificate authority.

## A minimal example

```kdl
acme {
    provider "letsencrypt-staging"
    accept-terms-of-service true
    contact "mailto:ops@example.com"
    store-dir "/var/lib/river/acme"
}

services {
    Example {
        listeners {
            // The certificate authority reaches River here to validate
            "0.0.0.0:80"

            "0.0.0.0:443" acme-domains="example.com, www.example.com"
        }
        connectors {
            "127.0.0.1:8080"
        }
    }
}
```

That is enough to get a certificate covering `example.com` and
`www.example.com`, and to keep it renewed.

> **Start with staging.** `letsencrypt-staging` issues certificates that
> browsers do not trust, but it has far higher rate limits. Let's Encrypt's
> production rate limits are strict, and a misconfiguration that retries can
> exhaust them for a week. Switch `provider` to `letsencrypt` once you have
> seen a certificate issued successfully.

## How River proves it controls a domain

Before issuing a certificate, a certificate authority requires proof that you
control the domain. River supports the two challenge types that make sense for
a reverse proxy.

### `http-01` (the default)

The CA fetches `http://<domain>/.well-known/acme-challenge/<token>` over plain
HTTP and expects a specific value back.

River answers these on **any** listener it already has, so if one of your
services has a plaintext listener on port 80, there is nothing more to
configure. Challenges are answered before rate limiting and before request
filters, so a validation request cannot be throttled or blocked by your own
rules.

River only answers tokens it is actually waiting on. Any other request under
`/.well-known/acme-challenge/` is proxied as normal, so an upstream running its
own ACME client keeps working.

If you serve only HTTPS and have nothing on port 80, add a dedicated listener:

```kdl
acme {
    // ...
    challenge-listener "0.0.0.0:80"
}
```

That listener answers challenges and redirects everything else to HTTPS.

### `dns-01` (required for wildcards)

A certificate authority will **only** issue a wildcard certificate such as
`*.example.com` against a `dns-01` challenge. This is a rule of the ACME
protocol, not a River limitation - there is no way to get a wildcard over
`http-01`.

This challenge is proved by publishing a TXT record. River does not talk to DNS
providers itself; instead it runs a program you supply:

```kdl
acme {
    // ...
    domain "*.example.com" challenge="dns-01" hook="/usr/local/bin/river-dns-hook"
}
```

River calls the hook twice per validation:

```
hook set   _acme-challenge.example.com <txt-value>
hook clean _acme-challenge.example.com <txt-value>
```

An exit status of zero means success. Anything the hook writes to standard
error is logged. The hook has 120 seconds to finish.

This is the same shape as lego's `exec` provider and certbot's manual hooks, so
existing scripts usually work unchanged.

Note that for a wildcard, the record goes at the **parent** domain:
`*.example.com` is validated by a record at `_acme-challenge.example.com`.
River passes the correct name to the hook; you do not need to strip anything.

After the hook returns, River waits `dns-propagation-seconds` (60 by default)
before asking the CA to check, because a record that is not yet visible causes a
failed validation and costs a retry against the CA's rate limits. If your hook
already waits for propagation, set this to `0`.

> **Security note.** The hook runs as the user River runs as, and typically
> needs DNS API credentials. Treat it as you would any other credentialed
> service: restrict its permissions, and scope the API token to the one zone it
> needs.

## Certificates and listeners

Each listener that sets `acme-domains` gets one certificate covering exactly
the domains it names. Two listeners naming the same set of domains share a
single certificate and a single order.

### Combining with a static certificate

`acme-domains` can be used alongside `cert-path` and `key-path`:

```kdl
"0.0.0.0:443" \
    acme-domains="example.com" \
    cert-path="/etc/river/fallback.crt" \
    key-path="/etc/river/fallback.key"
```

River picks a certificate per connection, based on the name the client asks for
(SNI). Clients asking for a managed domain get the managed certificate; anyone
else gets the static one. This is useful while migrating, and as a safety net
before the first certificate is issued.

Without a static certificate, a listener with `acme-domains` has nothing to
serve until the first certificate arrives, and handshakes for unknown names
fail.

### Wildcards and exact names

A wildcard covers exactly one label. `*.example.com` matches
`www.example.com`, but **not** `example.com` itself, and not
`a.b.example.com`. If you need the bare domain as well, name both:

```kdl
"0.0.0.0:443" acme-domains="example.com, *.example.com"
```

Where both could apply, an exact name wins over a wildcard.

## When certificates are renewed

River checks hourly and renews on whichever policy you set:

```kdl
// Renew once fewer than 30 days remain before expiry (the default)
renew-before-expiry-days 30

// ...or renew 60 days after the certificate was obtained
renew-after-issue-days 60
```

Set at most one of the two.

A renewal happens **in place**. Because River picks the certificate during each
handshake, the new certificate is used by the next connection with no reload and
no dropped connections. Connections already established keep the certificate
they negotiated with.

## Where certificates are stored

`store-dir` must be set, and must be an absolute path. River creates it if it
does not exist, with `0700` permissions:

```
<store-dir>/
    account.json                  the ACME account credentials
    certs/<id>/fullchain.pem      an issued certificate chain
    certs/<id>/key.pem            its private key, mode 0600
    certs/<id>/meta.json          when it was issued, and for what
```

Certificates are loaded from here at startup. This matters: without it, every
restart would ask the CA for a new certificate, which is the quickest way to hit
a rate limit.

> **Permissions.** River may drop privileges after startup. `store-dir` must be
> writable by the user River runs as in steady state, not by the user that
> launched it. If River cannot write there, it refuses to start rather than
> failing at renewal time weeks later.

During a [graceful reload](../reloading.md) two River processes are alive at
once. Both would otherwise try to renew the same certificate, so River takes an
exclusive lock on the store while an order is in flight; the second process
waits and then finds the result already on disk.

## What happens at startup

1. River reads any certificates already in `store-dir` and starts serving them.
2. Services that serve **only** TLS wait, and do not accept traffic yet.
3. River obtains anything missing or due for renewal.
4. Those services start accepting traffic.

If the certificate authority cannot be reached, River logs the failure, starts
anyway with whatever certificates it has, and keeps retrying with a backoff. A
CA outage should not become a River outage.

### Which services wait

Only a service whose listeners are *all* TLS will wait for the first
certificate. A service with any plaintext listener starts immediately.

This is not arbitrary. A `http-01` challenge is answered over plain HTTP, so a
service with a plaintext listener may be the one the certificate authority
needs to reach. If it waited for the certificate, and the certificate waited on
the challenge, neither would ever arrive.

So if you want a TLS listener to serve nothing at all until its certificate
exists, keep it in a service of its own and put the plaintext listener
elsewhere - either in its own service, or in `challenge-listener`:

```kdl
acme {
    // ...
    // Answers challenges and redirects to HTTPS; starts immediately
    challenge-listener "0.0.0.0:80"
}

services {
    // All TLS, so this waits for its certificate before serving
    Secure {
        listeners {
            "0.0.0.0:443" acme-domains="example.com"
        }
        connectors {
            "127.0.0.1:8080"
        }
    }
}
```

Written the other way round, with `"0.0.0.0:80"` inside the `Secure` service,
that service starts immediately and TLS handshakes fail until the first
certificate arrives. Both arrangements work; this one just closes the gap.

## Configuration reference

### The `acme` section

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `provider STRING` | no | `"letsencrypt"` | `"letsencrypt"`, `"letsencrypt-staging"`, or an `https://` directory URL |
| `accept-terms-of-service BOOL` | **yes** | - | Must be `true`. Certificate authorities require agreement to their terms before creating an account |
| `contact STRING` | no | none | A contact URI such as `"mailto:ops@example.com"`. May be repeated |
| `store-dir PATH` | **yes** | - | Absolute path where the account key and certificates are kept |
| `renew-before-expiry-days INT` | no | `30` | Renew once fewer than this many days remain |
| `renew-after-issue-days INT` | no | - | Renew this many days after issue. Mutually exclusive with the above |
| `challenge STRING` | no | `"http-01"` | Default challenge: `"http-01"` or `"dns-01"` |
| `challenge-listener ADDR` | no | none | A listener used only for `http-01` challenges and HTTPS redirects |
| `dns-propagation-seconds INT` | no | `60` | How long to wait after a `dns-01` hook returns |
| `domain STRING challenge=... hook=...` | no | none | Per-domain override. `hook` is required for `dns-01`. May be repeated |

### On a listener

| Argument | Meaning |
| --- | --- |
| `acme-domains STRING` | Comma separated domains to obtain a certificate for |

River rejects a configuration at startup, with the offending line highlighted,
if a wildcard is not set to use `dns-01`, if a `dns-01` domain has no `hook`, if
`store-dir` is relative, if `accept-terms-of-service` is not `true`, or if a
listener sets `acme-domains` with no `acme` section present.
