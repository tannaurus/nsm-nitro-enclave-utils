#!/bin/bash

CERT_DIRECTORY=$1;
ROOT_CERT_DIRECTORY=$2;

openssl ecparam -name secp384r1 -genkey -noout -out "$CERT_DIRECTORY"/ecdsa_p384_key.pem

openssl req -new -key "$CERT_DIRECTORY"/ecdsa_p384_key.pem -out "$CERT_DIRECTORY"/ecdsa_p384.csr

openssl x509 -req -in "$CERT_DIRECTORY"/ecdsa_p384.csr -CA "$ROOT_CERT_DIRECTORY"/ecdsa_p384_cert.pem -CAkey "$ROOT_CERT_DIRECTORY"/ecdsa_p384_key.pem -CAcreateserial -out "$CERT_DIRECTORY"/ecdsa_p384_cert.pem -days 365 -sha384