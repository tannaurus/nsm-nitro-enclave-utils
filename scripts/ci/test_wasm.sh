#!/bin/bash

set -e 

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

