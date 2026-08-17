# Request Normalization

River checks and canonicalizes every request before anything else looks at it.
This is **on by default**, for every service, with no configuration.

There are two jobs here. The first is putting a request into one canonical
form, so that a filter cannot be fooled by an unusual spelling of the same
thing. The second is turning away requests that are malformed in ways that
generally mean someone is trying something.

## Why it runs first

Consider a service that rate limits `/static` and proxies everything else, and
a request for:

```text
/static/../admin
```

Without normalization, the rate limiting rule sees a path beginning `/static`
and lets it through cheaply, while the upstream server resolves the `..` and
serves `/admin`. The two disagree about what was requested, and the disagreement
is the vulnerability.

Normalization runs before the ACME challenge handler, the client address
resolution, rate limiting, the path control filters, and route matching. By the
time any of them see the request, `/static/../admin`, `/static/%2E%2E/admin`,
and `/static//..///admin` have all become `/admin`, and every one of them is
matched against the same rules.

## What it does

### The path

* **Dot segments** (`dot-segments`) - `.` and `..` are resolved, per RFC 3986
  §5.2.4. A `..` that would climb above the root is **rejected**, not clamped.
  Most implementations clamp, which makes `/../../etc/passwd` and
  `/etc/passwd` the same request - so a rule written against one silently fails
  to cover the other.
* **Duplicate slashes** (`duplicate-slashes`) - runs of `/` are collapsed into
  one.
* **Encoded separators** (`encoded-separators`) - a `%2F` or `%5C` in the path
  is rejected. `%2F` means precisely *not* a path separator; if River decodes it
  and the upstream server does not, or the other way round, the two disagree
  about what the path segments are.
* **Control characters** (`control-characters`) - a control character or NUL in
  the path is rejected, whether written literally or percent-encoded.
* **Percent-encoding** (`percent-encoding`) - malformed encodings (a `%` not
  followed by two hex digits) are rejected. Unreserved characters are decoded,
  since `%61` and `a` mean the same thing, and everything else has its hex
  digits put in upper case. This is also what lets `%2E%2E` be seen as `..`.

The query string is **not** touched. It is not a path, River does not route or
filter on it, and rewriting it would change what an application receives.

### The `Host` header

`host` requires that a request has exactly one `Host` header, and that it agrees
with the authority in the request line when there is one - which for HTTP/2 is
the `:authority` pseudo-header. Two `Host` headers let a proxy and its upstream
server route to different sites, which is the shape of a request smuggling
attack.

### Header values

`header-non-ascii` rejects header values containing bytes outside US-ASCII.

**This is the one check that is off by default.** The HTTP/1.1 parser admits
these bytes (they are `obs-text`, deprecated but permitted), and real traffic
uses them - a UTF-8 filename in a `Content-Disposition`, for one. Turning it on
is worth doing if you know your traffic does not need them, and likely to break
things if you do not.

## What River deliberately does not check

Pingora already rejects a good deal, and duplicating it would be worse than
useless. Verified against pingora-core 0.8.1 and httparse 1.8:

* Duplicate `Content-Length` headers are rejected.
* `Transfer-Encoding` together with `Content-Length` is handled per RFC 9112
  §6.1: the `Content-Length` is dropped and keepalive disabled. River never sees
  this case, so it could not check for it even if it wanted to.
* A `Transfer-Encoding` whose final encoding is not `chunked`, and
  `Transfer-Encoding` on an HTTP/1.0 request, are both rejected.
* Control characters in *header values* are rejected by the parser, which admits
  only tab, space, `0x21`–`0x7E`, and `0x80` and above. That last band is what
  `header-non-ascii` covers; everything below it never arrives.
* Header count and size are bounded: 256 headers and about 1 MiB of header on
  HTTP/1.1, and a 64 KiB header list on HTTP/2.

## Configuration

```kdl
normalization {
    // Any check may be turned off on its own
    encoded-separators false

    // The one that is off by default may be turned on
    header-non-ascii true

    // How a request that fails a check is answered
    status 422
    body "Malformed request\n"
}
```

`status` defaults to `400` with no body - the request is malformed, which is the
client's doing.

To start from nothing and name only the checks you want, use `default`:

```kdl
normalization {
    default false
    host true
}
```

`default` sets the baseline for every check not named, whatever line it appears
on, so reordering the block never changes its meaning. To turn normalization off
completely:

```kdl
normalization {
    default false
}
```

## Upgrading

Normalization did not exist before v0.8.0, so it rejects some requests that
earlier versions passed through. That is the point of the feature, but it means
a configuration that worked before may now turn traffic away.

If you have an upstream server that genuinely needs one of these - an
application that serves paths containing an encoded slash, say - turn off that
one check rather than the whole block:

```kdl
normalization {
    encoded-separators false
}
```

River logs each rejection at `debug` level with the reason, so a request that
suddenly stops working will say which check turned it away.
