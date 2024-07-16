#!/bin/bash

CERT_DIRECTORY=$1;

openssl ecparam -name secp384r1 -genkey -noout -out "$CERT_DIRECTORY"/ecdsa_p384_key.pem

openssl req -new -key "$CERT_DIRECTORY"/ecdsa_p384_key.pem -out "$CERT_DIRECTORY"/ecdsa_p384.csr

openssl req -x509 -key "$CERT_DIRECTORY"/ecdsa_p384_key.pem -in "$CERT_DIRECTORY"/ecdsa_p384.csr -out "$CERT_DIRECTORY"/ecdsa_p384_cert.pem -days 365 -sha384
