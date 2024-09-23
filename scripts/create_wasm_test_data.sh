#!/bin/bash

CERT_DIRECTORY="./nsm-nitro-enclave-utils/wasm_test_data"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_CERT_DIR="$CERT_DIRECTORY"/root
INT_CERT_DIR="$CERT_DIRECTORY"/int
END_CERT_DIR="$CERT_DIRECTORY"/end
CLEAN_UP_CERT_DIRS=(
  "$ROOT_CERT_DIR"
  "$INT_CERT_DIR"
  "$END_CERT_DIR"
)

"$SCRIPT_DIR"/create_root_cert.sh $ROOT_CERT_DIR
"$SCRIPT_DIR"/create_int_cert.sh $INT_CERT_DIR $ROOT_CERT_DIR
"$SCRIPT_DIR"/create_end_cert.sh $END_CERT_DIR $INT_CERT_DIR

echo "Generating certs..."
sleep 3

echo "Cleaning up..."
for i in "${CLEAN_UP_CERT_DIRS[@]}"
do
    if [ -f "$i"/ecdsa_p384_cert.srl ]; then
        rm "$i"/ecdsa_p384_cert.srl
    fi
        rm "$i"/ecdsa_p384.csr
done

echo $(($(date +%s) * 1000)) > "$CERT_DIRECTORY"/created_at.txt

echo "Done 🚀"
