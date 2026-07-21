#!/bin/bash

# ==============================================================================
# PKI Generation Script for CertifPlus (Development/Mock Environment)
# ==============================================================================
# This script generates a local Certificate Authority (CA), server certificates
# for TLS, and the ECC key pair used for JWT signing and verification.
# 
# WARNING: These keys are for local testing only. DO NOT commit the generated
# .pem files to a public repository.
# ==============================================================================

# Create the PKI directory if it doesn't exist
mkdir -p PKI
cd PKI || exit

echo "--- Generating the local Certificate Authority (CA) ---"
# Generate private key for the CA (Elliptic Curve prime256v1)
openssl ecparam -name prime256v1 -genkey -noout -out ecc.ca.key.pem
# Create the self-signed Root CA certificate (Valid for 10 years)
openssl req -new -x509 -key ecc.ca.key.pem -out ecc.ca.cert.pem -days 3650 -subj "/C=FR/O=CertifPlus/CN=CertifPlus Root CA"
echo "[OK] CA generated: ecc.ca.cert.pem"


echo -e "\n--- Generating the TLS Server Certificate ---"
# Generate private key for the server
openssl ecparam -name prime256v1 -genkey -noout -out ecc.serveur.key.pem
# Create a Certificate Signing Request (CSR) for localhost
openssl req -new -key ecc.serveur.key.pem -out serveur.csr -subj "/C=FR/O=CertifPlus/CN=localhost"
# Sign the server certificate with our local CA (Valid for 1 year)
openssl x509 -req -in serveur.csr -CA ecc.ca.cert.pem -CAkey ecc.ca.key.pem -CAcreateserial -out ecc.serveur.pem -days 365
# Create the bundle required by socat (Key + Certificate)
cat ecc.serveur.key.pem ecc.serveur.pem > bundle_serveur.pem
echo "[OK] Server bundle generated for socat: bundle_serveur.pem"


echo -e "\n--- Generating ECC Keys for JWT (Signature & Verification) ---"
# Generate the private key for signing the JWT (used by create_certificate)
openssl ecparam -name prime256v1 -genkey -noout -out ecc.signature.key.pem
# Extract the public key for verifying the JWT (used by verify_certificate)
openssl ec -in ecc.signature.key.pem -pubout -out ecc.signature.pub.pem
echo "[OK] JWT keys generated: ecc.signature.key.pem & ecc.signature.pub.pem"


# Cleanup temporary OpenSSL files
rm serveur.csr ecc.ca.srl

echo -e "\n======================================================================"
echo "   Success! All cryptographic keys and certificates have been generated."
echo "   You can now start the application and the TLS relay."
echo "======================================================================"