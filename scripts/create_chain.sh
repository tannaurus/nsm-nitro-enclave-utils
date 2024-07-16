#!/bin/bash

CERT_DIRECTORY=$1;

mkdir -p "$CERT_DIRECTORY"/root
mkdir -p "$CERT_DIRECTORY"/int
mkdir -p "$CERT_DIRECTORY"/end

./create_root_cert.sh "$CERT_DIRECTORY"/root
./create_int_cert.sh "$CERT_DIRECTORY"/int "$CERT_DIRECTORY"/root
./create_end_cert.sh "$CERT_DIRECTORY"/end "$CERT_DIRECTORY"/int


