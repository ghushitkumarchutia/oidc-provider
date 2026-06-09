#!/bin/bash

CERT_DIR="cert"

mkdir -p "$CERT_DIR"

# Generate RSA 2048-bit private key
openssl genpkey -algorithm RSA -out "$CERT_DIR/private-key.pem" -pkeyopt rsa_keygen_bits:2048

# Extract public key from private key
openssl rsa -in "$CERT_DIR/private-key.pem" -pubout -out "$CERT_DIR/public-key.pub"

echo "Keys generated in $CERT_DIR/"
