#!/bin/bash
#
# Generate test certificates and private keys for lws_x509_jwk_privkey_pem testing
# This script creates various RSA and EC key pairs for testing
#

set -e

VALIDITY_DAYS=3650

CERT_DIR="."

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Generating Test Certificates and Private Keys ===${NC}"

CA_KEY="ca-key.pem"
CA_CERT="ca-cert.pem"
SUBJECT_CA="/C=CN/ST=Beijing/L=Beijing/O=Test CA/OU=Development/CN=Test CA"

SUBJECT_SERVER="/C=CN/ST=Beijing/L=Beijing/O=Test Server/OU=Development/CN=test.example.com"

create_ca() {
    echo -e "${GREEN}Creating CA certificate...${NC}"
    openssl genrsa -out "${CERT_DIR}/${CA_KEY}" 4096
    openssl req -new -x509 -key "${CERT_DIR}/${CA_KEY}" \
        -out "${CERT_DIR}/${CA_CERT}" \
        -days "${VALIDITY_DAYS}" \
        -subj "${SUBJECT_CA}"
}

create_rsa_keypair() {
    local name=$1
    local bits=$2
    local key_file="${name}-key.pem"
    local encrypted_key_file="${name}-key-encrypted.pem"
    local csr_file="${name}-csr.pem"
    local cert_file="${name}-cert.pem"

	echo -e "${GREEN}Creating RSA ${bits}-bit key pair...${NC}"
    openssl genrsa -out "${CERT_DIR}/${key_file}" "${bits}"

    openssl pkcs8 -topk8 -v2 aes256 -in "${CERT_DIR}/${key_file}" \
        -passout pass:testpass123 -out "${CERT_DIR}/${encrypted_key_file}"

    openssl req -new -key "${CERT_DIR}/${key_file}" \
        -out "${CERT_DIR}/${csr_file}" \
        -subj "${SUBJECT_SERVER}"
    openssl x509 -req -in "${CERT_DIR}/${csr_file}" \
        -CA "${CERT_DIR}/${CA_CERT}" \
        -CAkey "${CERT_DIR}/${CA_KEY}" \
        -CAcreateserial \
        -out "${CERT_DIR}/${cert_file}" \
        -days "${VALIDITY_DAYS}"

    rm -f "${CERT_DIR}/${csr_file}"
}

create_ec_keypair() {
    local name=$1
    local curve=$2
    local key_file="${name}-key.pem"
    local encrypted_key_file="${name}-key-encrypted.pem"
    local csr_file="${name}-csr.pem"
    local cert_file="${name}-cert.pem"

	echo -e "${GREEN}Creating EC ${curve} key pair...${NC}"
    openssl ecparam -name "${curve}" -genkey -noout -out "${CERT_DIR}/${key_file}"

    openssl pkcs8 -topk8 -v2 aes256 -in "${CERT_DIR}/${key_file}" \
        -passout pass:testpass123 -out "${CERT_DIR}/${encrypted_key_file}"

    openssl req -new -key "${CERT_DIR}/${key_file}" \
        -out "${CERT_DIR}/${csr_file}" \
        -subj "${SUBJECT_SERVER}"
    openssl x509 -req -in "${CERT_DIR}/${csr_file}" \
        -CA "${CERT_DIR}/${CA_CERT}" \
        -CAkey "${CERT_DIR}/${CA_KEY}" \
        -CAcreateserial \
        -out "${CERT_DIR}/${cert_file}" \
        -days "${VALIDITY_DAYS}"

    rm -f "${CERT_DIR}/${csr_file}"
}

echo -e "${GREEN}Cleaning up old test files...${NC}"
rm -f "${CERT_DIR}"/*.pem
rm -f "${CERT_DIR}"/.srl

create_ca

create_rsa_keypair "rsa-2048" 2048
create_rsa_keypair "rsa-4096" 4096

create_ec_keypair "ec-p256" "prime256v1"
create_ec_keypair "ec-p256-b" "prime256v1"
create_ec_keypair "ec-p384" "secp384r1"
create_ec_keypair "ec-p521" "secp521r1"

echo -e "${GREEN}=== All certificates and keys generated successfully ===${NC}"
echo ""
echo "Generated files:"
ls -1 "${CERT_DIR}"/*.pem | sed 's/^/  /'
echo ""
echo "Usage:"
echo "  ./test-x509-jwk-privkey-pem ."
