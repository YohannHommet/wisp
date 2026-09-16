.PHONY: help build install test check fmt clippy discovery run clean

help:
	@printf '%s\n' \
		'make build      Build the optimized wisp binary' \
		'make install    Install wisp with Cargo' \
		'make test       Run the workspace tests' \
		'make check      Run format check and Clippy' \
		'make fmt        Check Rust formatting' \
		'make clippy     Run Clippy with warnings denied' \
		'make discovery  Run the multicast discovery test' \
		'make run ARGS="--help"  Run wisp from the checkout' \
		'make clean      Remove generated Cargo build files'

build:
	cargo build --locked --release --bin wisp

install:
	cargo install --locked --path crates/wisp-cli

test:
	cargo test --locked --workspace

check: fmt clippy

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --locked --workspace --all-targets -- -D warnings

discovery:
	cargo test --locked -p wisp --test cli discovery_two_cli_processes -- --ignored --nocapture

run:
	cargo run --locked --bin wisp -- $(ARGS)

clean:
	cargo clean
