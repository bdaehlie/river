# Routing

A service may send different requests to different sets of upstream servers,
chosen by the request's URI path and method.

Without routing, a service has one `connectors` block and every request it
accepts goes to those servers. That is still the common case, and it still
looks exactly as it always has:

```kdl
Example {
    listeners {
        "0.0.0.0:80"
    }
    connectors {
        "10.0.0.1:8080"
    }
}
```

With routing, the `connectors` block is replaced by a `routes` block, and each
route has a `connectors` block of its own:

```kdl
Example {
    listeners {
        "0.0.0.0:80"
    }
    routes {
        route "/api" {
            connectors {
                load-balance {
                    selection "RoundRobin"
                    health-check "HTTP" host="api.example.com" path="/healthz"
                }
                dns "api.internal" port=8080
            }
        }
        route "/static" {
            connectors {
                "10.0.0.9:8080"
            }
        }
        route "/" {
            connectors {
                "10.0.0.1:8080"
            }
        }
    }
}
```

A service has either a `connectors` block or a `routes` block, not both.

Everything inside a route's `connectors` block works exactly as it does for a
service without routes - literal addresses, `dns` and `srv` discovery,
`load-balance`, health checks, and connection timeouts. Each route keeps its
own set of servers, its own selection algorithm, and its own health checking,
so the API route above can be consistently hashed and health checked over HTTP
while the static route is a single fixed address that is never checked.

## `route "PATH" [match="KIND"] [methods="METHODS"]`

`PATH` is matched against the request's URI path. `KIND` is one of:

* `prefix` (the default) - the path is `PATH`, or continues after it at a
  segment boundary. `/api` claims `/api` and `/api/users`, but **not**
  `/apiary`: a prefix that stops in the middle of a path segment is nearly
  always a coincidence rather than an intent.
* `exact` - the path is exactly `PATH`. `/health` does not claim `/health/`.
* `regex` - `PATH` is a regular expression matched against the path.

For `prefix` and `exact`, `PATH` must start with `/`.

`METHODS` is an optional comma separated list of HTTP methods, such as
`methods="POST,PUT"`. A route with no `methods` claims any method. A request
whose method is not listed does not match the route, and matching continues
with the next one - so a `GET` to a `POST`-only `/upload` route falls through
to whatever route would otherwise have claimed it, rather than failing.

## Which route wins

Routes are tried in a fixed order, decided when River starts rather than by
where they appear in the file:

1. `exact` routes
2. `prefix` routes, **longest prefix first**
3. `regex` routes, in the order written in the file
4. the catch-all, for a service with no `routes` block

The first route that claims the request gets it. Because the order does not
depend on the layout of the file, moving a route up or down changes nothing -
except among regular expressions, where file order is the only sensible
tie-breaker and is therefore preserved.

Two routes that would match exactly the same requests are a configuration
error, since the second could never be reached.

## `no-route [status=CODE] [body="TEXT"]`

How a request that matches no route is answered. It goes inside the `routes`
block:

```kdl
routes {
    no-route status=404 body="No route for that path\n"

    route "/api" {
        connectors {
            "10.0.0.1:8080"
        }
    }
}
```

Defaults to `404` with no body. That is more truthful than a `502` - River
knows perfectly well that nothing serves the path - and it is also the least
informative thing to tell someone probing for one.

A service with a `routes` block that has no catch-all `route "/"` will answer
`no-route` for anything the listed routes do not claim. If you would rather
every request reach a server, add a `route "/"`.
