# Build and packaging entry points. `make lint test release deb` is what the
# release workflow runs, so a failure in CI is reproducible with one command
# here.

# Parallel compile jobs. Kept modest by default because several tests bind
# sockets and spawn processes; override on the command line if your machine
# has room: `make test JOBS=16`.
JOBS ?= 4

# The triple the release ships. Static musl, so one .deb runs on any glibc
# vintage instead of only the one the builder happened to have.
TARGET ?= x86_64-unknown-linux-musl

# `cross`, not a bare `cargo build --target`: rustls here is pinned to the
# *ring* provider (see the comment in Cargo.toml), and ring assembles
# per-target assembly with a toolchain a plain host does not carry. cross's
# container images do. It writes to the ordinary target/<triple>/release/
# layout, so everything downstream is unchanged.
CROSS ?= cross

# Where cargo puts its output. Follows CARGO_TARGET_DIR when the environment
# sets one, so `verify-static` inspects the binary that was actually built
# rather than a stale ./target copy.
TARGET_DIR ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)
BINARY = $(TARGET_DIR)/$(TARGET)/release/smtp-proxy

# The man page is built from docs/manual.md by build/man.mk (repo-infra),
# which reads MAN_NAME and writes man/$(MAN_NAME).1. man/ is not in git.
MAN_NAME = smtp-proxy

.PHONY: build test lint release verify-static deb docker conformance

build:
	cargo build -j $(JOBS)

test:
	cargo test -j $(JOBS)

lint:
	cargo fmt --check
	cargo clippy --all-targets -j $(JOBS) -- -D warnings

release:
	RUSTFLAGS="-C target-feature=+crt-static" \
	  $(CROSS) build --release --locked -j $(JOBS) --bin smtp-proxy --target $(TARGET)

# `crt-static` is a hint the linker is free to ignore, so the result is
# asserted rather than assumed. A binary that turns out to be dynamically
# linked fails on the operator's machine, in a way that looks like a broken
# package rather than a broken build.
verify-static: release
	file $(BINARY)
	file $(BINARY) | grep -q 'static'
	! { command -v llvm-objdump >/dev/null && \
	    llvm-objdump -T $(BINARY) 2>/dev/null | grep -q GLIBC; }

# `--no-build` on purpose: the package must carry the binary `release` built
# and `verify-static` checked, not one cargo-deb rebuilds against the host's
# libc. `--no-strip` for the same reason -- the release profile already strips,
# and letting cargo-deb strip again would put a file through the package that
# nothing verified. cargo-deb rewrites the `target/release/` asset paths in
# Cargo.toml to the target triple when --target is given.
deb: verify-static man
	cargo deb --no-build --no-strip --target $(TARGET)

docker:
	./build-docker.sh

conformance: build
	$(MAKE) -C conformance

# Last, so that its `man` target does not become the default goal.
include build/man.mk
