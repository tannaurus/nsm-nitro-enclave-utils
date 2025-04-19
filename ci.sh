#!/bin/bash

set -e 

echo "Running cargo fmt --check..."
cargo fmt --check

echo "Running cargo clippy..."
cargo clippy -- -D warnings

echo "Running tests..."
cargo test

./scripts/ci/test_wasm.sh

echo "All checks passed!"
