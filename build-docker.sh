#!/bin/bash
set -eo pipefail
V=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
cargo test -j 4 2>&1 | tee smtp-proxy-${V}.test-output.txt
podman build --pull --tag smtp-proxy:${V} .
echo "you can now run 'podman run smtp-proxy:${V}'"
