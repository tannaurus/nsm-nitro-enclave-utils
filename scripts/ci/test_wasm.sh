#!/bin/bash

set -e

if [[ "$(uname)" == "Darwin" ]]; then
  export CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang"
fi

echo "Running wasm tests..."

if ! command -v wasm-bindgen &> /dev/null
then
    echo "wasm-bindgen could not be found. Please install it."
    echo "https://github.com/rustwasm/wasm-bindgen?tab=readme-ov-file#install-wasm-bindgen-cli"
    exit 1
fi

cd nsm-nitro-enclave-utils
wasm-pack test --node --no-default-features --features seed,rand,verify,pki
cd ..

