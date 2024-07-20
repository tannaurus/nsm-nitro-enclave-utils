#!/bin/bash

CERT_DIRECTORY=$1;
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

"$SCRIPT_DIR"/create_root_cert.sh "$CERT_DIRECTORY"/root
"$SCRIPT_DIR"/create_int_cert.sh "$CERT_DIRECTORY"/int "$CERT_DIRECTORY"/root
"$SCRIPT_DIR"/create_end_cert.sh "$CERT_DIRECTORY"/end "$CERT_DIRECTORY"/int


