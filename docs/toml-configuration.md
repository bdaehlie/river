# TOML configuration

This is a full explanation of the supported TOML configuration files.

Until the 1.0 release, expect breaking changes in the TOML configuration format.

## Full Configuration Tree

The following is a full tree of configuration options

* `system`: struct
    * `system.threads-per-service`: integer - number of threads per service worker
* `basic-proxy`: array
    * `basic-proxy.listeners`: array
        * `basic-proxy.listeners.source`: struct
            * `basic-proxy.listeners.source.kind`: String - "Tcp" or "Uds"
            * `basic-proxy.listeners.source.value`: struct
                * `basic-proxy.listeners.source.value.addr`: String - Host:Port
                * `basic-proxy.listeners.source.value.tls`: struct
                    * `basic-proxy.listeners.source.value.tls.cert_path`: Path
                    * `basic-proxy.listeners.source.value.tls.key_path`: Path
    * `basic-proxy.connector`: struct
        * `basic-proxy.connector.proxy_addr`: String - Host:Port
        * `basic-proxy.connector.tls_sni`: String
    * `basic-proxy.path-control`: struct
        * `basic-proxy.path-control.upstream-request-filters`: array
            * `basic-proxy.path-control.upstream-request-filters.kind`: String
            * `basic-proxy.path-control.upstream-request-filters.*`: Additional Key:Value parameters
        * `basic-proxy.path-control.upstream-response-filters`: array
            * `basic-proxy.path-control.upstream-response-filters.kind`: String
            * `basic-proxy.path-control.upstream-response-filters.*`: Additional Key:Value parameters

## Path control filters

Both filter arrays accept the same two kinds:

* `kind = "remove-header-key-regex"`, with `pattern` - a regular expression
  matched against header names, removing those that match
* `kind = "upsert-header"`, with `key` and `value` - adds the header, replacing
  any existing value

Any other `kind`, an unknown key, a regular expression that does not compile,
or a header name or value that is not valid, will stop River from starting.

Note that the TOML format has no equivalent of the KDL format's
`request-filters` stage, and is not being extended to gain one. The KDL format
is where new configuration goes. Unlike KDL, TOML carries no source location
information here, so a bad filter is reported by name rather than by pointing
at the line that has it.

