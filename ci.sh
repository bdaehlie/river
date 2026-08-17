#!/usr/bin/env bash

set -euxo pipefail

# Format check first
cargo fmt --all -- --check

# Test all crates, including the end-to-end suite in source/river/tests, which
# starts a real River process and speaks to it over a socket
cargo test --all

# Run configuration file checks
cd ./source/river
cargo run -p river -- --config-toml ./assets/example-config.toml --validate-configs
cargo run -p river -- --config-toml ./assets/test-config.toml --validate-configs
cargo run -p river -- --config-kdl ./assets/test-config.kdl --validate-configs
cargo run -p river -- --config-kdl ./assets/test-config-acme.kdl --validate-configs
cargo run -p river -- --config-kdl ./assets/test-config-discovery.kdl --validate-configs
cargo run -p river -- --config-kdl ./assets/test-config-path-control.kdl --validate-configs
cd ../../

# ensure the user manual can be built
cd user-manual
mdbook build
