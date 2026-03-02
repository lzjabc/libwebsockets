#!/bin/bash
#
# Generate test certificates for lws_x509_public_to_jwk testing
# This script creates various RSA and EC certificates for testing
#

set -e

# Certificate validity in days
VALIDITY_DAYS=3650

# Output directory
CERT_DIR="."

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Generating Test Certificates ===${NC}"

# Common certificate fields
CA_KEY="ca-key.pem"
CA_CERT="ca-cert.pem"
SUBJECT_CA="/C=CN/ST=Beijing/L=Beijing/O=Test CA/OU=Development/CN=Test CA"

SUBJECT_SERVER="/C=CN/ST=Beijing/L=Beijing/O=Test Server/OU=Development/CN=test.example.com"

# Function to create CA certificate
create_ca() {
    echo -e "${GREEN}Creating CA certificate...${NC}"
    openssl genrsa -out "${CERT_DIR}/${CA_KEY}" 4096
    openssl req -new -x509 -key "${CERT_DIR}/${CA_KEY}" \
        -out "${CERT_DIR}/${CA_CERT}" \
        -days "${VALIDITY_DAYS}" \
        -subj "${SUBJECT_CA}"
}

# Function to create RSA certificate
create_rsa_cert() {
    local name=$1
    local bits=$2
    local key_file="${name}-key.pem"
    local csr_file="${name}-csr.pem"
    local cert_file="${name}-cert.pem"

    echo -e "${GREEN}Creating RSA ${bits}-bit certificate...${NC}"
    openssl genrsa -out "${CERT_DIR}/${key_file}" "${bits}"
    openssl req -new -key "${CERT_DIR}/${key_file}" \
        -out "${CERT_DIR}/${csr_file}" \
        -subj "${SUBJECT_SERVER}"
    openssl x509 -req -in "${CERT_DIR}/${csr_file}" \
        -CA "${CERT_DIR}/${CA_CERT}" \
        -CAkey "${CERT_DIR}/${CA_KEY}" \
        -CAcreateserial \
        -out "${CERT_DIR}/${cert_file}" \
        -days "${VALIDITY_DAYS}"

    # Clean up CSR and serial files
    rm -f "${CERT_DIR}/${csr_file}"
}

# Function to create EC certificate
create_ec_cert() {
    local name=$1
    local curve=$2
    local key_file="${name}-key.pem"
    local csr_file="${name}-csr.pem"
    local cert_file="${name}-cert.pem"

    echo -e "${GREEN}Creating EC ${curve} certificate...${NC}"
    openssl ecparam -name "${curve}" -genkey -noout -out "${CERT_DIR}/${key_file}"
    openssl req -new -key "${CERT_DIR}/${key_file}" \
        -out "${CERT_DIR}/${csr_file}" \
        -subj "${SUBJECT_SERVER}"
    openssl x509 -req -in "${CERT_DIR}/${csr_file}" \
        -CA "${CERT_DIR}/${CA_CERT}" \
        -CAkey "${CERT_DIR}/${CA_KEY}" \
        -CAcreateserial \
        -out "${CERT_DIR}/${cert_file}" \
        -days "${VALIDITY_DAYS}"

    # Clean up CSR and serial files
    rm -f "${CERT_DIR}/${csr_file}"
}

# Clean up old files
echo -e "${GREEN}Cleaning up old test certificates...${NC}"
rm -f "${CERT_DIR}"/*.pem
rm -f "${CERT_DIR}"/.srl

# Create CA certificate
create_ca

# Generate RSA certificates
create_rsa_cert "rsa-2048" 2048
create_rsa_cert "rsa-4096" 4096
create_rsa_cert "rsa-1024" 1024

# Generate EC certificates
create_ec_cert "ec-p256" "prime256v1"
create_ec_cert "ec-p384" "secp384r1"
create_ec_cert "ec-p521" "secp521r1"
create_ec_cert "ec-p224" "secp224r1"

# Create a combined CA cert for easy use
cat "${CERT_DIR}/${CA_CERT}" > "${CERT_DIR}/combined-ca.pem"

echo -e "${GREEN}=== All certificates generated successfully ===${NC}"
echo ""
echo "Generated files:"
ls -1 "${CERT_DIR}"/*.pem | sed 's/^/  /'
echo ""
echo "Usage:"
echo "  ./test-x509-public-to-jwk ."
