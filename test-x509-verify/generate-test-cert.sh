#!/bin/bash
set -e

echo "=== Generating Test Certificates for Verification Test ==="
echo ""

# 1. Generate Root CA certificate
echo "[1/5] Generating Root CA certificate..."
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 3650 -nodes \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=TestCA/CN=Root CA"

echo "  Generated: ca-cert.pem, ca-key.pem"

# 2. Generate another CA (for negative test)
echo ""
echo "[2/5] Generating other CA certificate (for negative test)..."
openssl req -x509 -newkey rsa:2048 -keyout other-ca-key.pem -out other-ca-cert.pem -days 3650 -nodes \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=OtherCA/CN=Other CA"

echo "  Generated: other-ca-cert.pem, other-ca-key.pem"

# 3. Generate Server certificate request
echo ""
echo "[3/5] Generating Server certificate request..."
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem -nodes \
  -subj "/C=CN/ST=Shanghai/L=Shanghai/O=TestOrg/CN=test.example.com"

echo "  Generated: server-req.pem, server-key.pem"

# 4. Create extensions file
echo ""
echo "[4/5] Creating extensions file..."
cat > server-ext.cnf <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:test.example.com, DNS:*.example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

# 5. Sign server certificate with Root CA
echo ""
echo "[5/5] Signing server certificate..."
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365 -extfile server-ext.cnf

echo "  Generated: server-cert.pem"

# 6. Generate Intermediate CA (optional, for chain testing)
echo ""
echo "[6/6] Generating Intermediate CA..."
openssl req -newkey rsa:2048 -keyout intermediate-key.pem -out intermediate-req.pem -nodes \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=TestCA/CN=Intermediate CA"

cat > intermediate-ext.cnf <<EOF
basicConstraints = CA:TRUE,pathlen:0
keyUsage = digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

openssl x509 -req -in intermediate-req.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out intermediate-cert.pem -days 3650 -extfile intermediate-ext.cnf

echo "  Generated: intermediate-cert.pem, intermediate-key.pem"

# 7. Generate Leaf certificate signed by Intermediate CA
echo ""
echo "[7/7] Generating Leaf certificate signed by Intermediate CA..."
openssl req -newkey rsa:2048 -keyout leaf-key.pem -out leaf-req.pem -nodes \
  -subj "/C=CN/ST=Shanghai/L=Shanghai/O=TestOrg/CN=leaf.example.com"

cat > leaf-ext.cnf <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:leaf.example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

openssl x509 -req -in leaf-req.pem -CA intermediate-cert.pem -CAkey intermediate-key.pem \
  -CAcreateserial -out leaf-cert.pem -days 365 -extfile leaf-ext.cnf

echo "  Generated: leaf-cert.pem, leaf-key.pem"

# Clean up temporary files
rm -f server-req.pem server-ext.cnf intermediate-req.pem intermediate-ext.cnf leaf-req.pem leaf-ext.cnf

echo ""
echo "=========================================================="
echo "  Test certificates generated successfully!"
echo "=========================================================="
echo ""
echo "  Certificate Chain 1 (Root CA):"
echo "    ca-cert.pem              - Root CA certificate"
echo "    server-cert.pem          - Server cert signed by Root CA"
echo ""
echo "  Certificate Chain 2 (Intermediate CA):"
echo "    ca-cert.pem              - Root CA certificate"
echo "    intermediate-cert.pem    - Intermediate CA"
echo "    leaf-cert.pem            - Leaf cert signed by Intermediate"
echo ""
echo "  Other certificates:"
echo "    other-ca-cert.pem        - Other CA (for negative test)"
echo "=========================================================="
