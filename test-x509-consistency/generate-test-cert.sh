#!/bin/bash
set -e

echo "Generating CA certificate..."
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 3650 -nodes \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=TestCA/CN=Test CA"

echo "Generating server certificate request..."
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem -nodes \
  -subj "/C=CN/ST=Shanghai/L=Shanghai/O=TestOrg/CN=test.example.com"

echo "Creating extensions file..."
cat > server-ext.cnf <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:test.example.com, DNS:*.example.com, IP:192.168.1.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

echo "Signing server certificate..."
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365 -extfile server-ext.cnf

echo ""
echo "Generated certificates:"
echo "  ca-cert.pem - CA certificate"
echo "  server-cert.pem - Server certificate with extensions"
