#!/usr/bin/env bash
set -euo pipefail

# Verify two properties for a DER cert/key pair:
# 1) SKI in cert equals SHA1(subjectPublicKey BIT STRING content)
# 2) cert public key matches private key public key
#
# Usage:
#   ./verify-selfsigned-openssl.sh [cert.der] [key.der]
#
# Defaults:
#   cert.der -> selfsigned_case01_cert.der
#   key.der  -> selfsigned_case01_key.der

CERT_DER="${1:-selfsigned_case01_cert.der}"
KEY_DER="${2:-selfsigned_case01_key.der}"

if ! command -v openssl >/dev/null 2>&1; then
	echo "ERROR: openssl not found in PATH"
	exit 2
fi

if [ ! -f "$CERT_DER" ]; then
	echo "ERROR: cert file not found: $CERT_DER"
	exit 2
fi

if [ ! -f "$KEY_DER" ]; then
	echo "ERROR: key file not found: $KEY_DER"
	exit 2
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail=0

echo "Cert: $CERT_DER"
echo "Key : $KEY_DER"

# --------------------------------------------------------------------
# 1) Verify SKI == SHA1(subjectPublicKey)
# --------------------------------------------------------------------

# Extract SKI hex from cert text output
CERT_SKI_HEX="$(
	openssl x509 -inform DER -in "$CERT_DER" -noout -text |
	awk '
		/Subject Key Identifier/ { capture = 1; next }
		capture == 1 {
			gsub(/[^0-9A-Fa-f]/, "", $0)
			if (length($0) > 0) {
				print toupper($0)
				exit
			}
		}
	'
)"

if [ -z "$CERT_SKI_HEX" ]; then
	echo "[FAIL] Could not extract SKI from certificate"
	exit 1
fi

# Build SPKI DER from cert public key
openssl x509 -inform DER -in "$CERT_DER" -pubkey -noout > "$TMP_DIR/cert_pub.pem"
openssl pkey -pubin -in "$TMP_DIR/cert_pub.pem" -outform DER -out "$TMP_DIR/cert_spki.der"

# Find BIT STRING offset/header/content length inside SPKI
BIT_INFO_LINE="$(
	openssl asn1parse -inform DER -in "$TMP_DIR/cert_spki.der" |
	awk '/BIT STRING/ { print; exit }'
)"

if [ -z "$BIT_INFO_LINE" ]; then
	echo "[FAIL] Could not locate BIT STRING in SPKI"
	exit 1
fi

BIT_OFF="$(echo "$BIT_INFO_LINE" | awk -F: '{print $1}')"
BIT_HL="$(echo "$BIT_INFO_LINE" | sed -n 's/.*hl=\([0-9][0-9]*\).*/\1/p')"
BIT_L="$(echo "$BIT_INFO_LINE" | sed -n 's/.*l= *\([0-9][0-9]*\).*/\1/p')"

if [ -z "$BIT_OFF" ] || [ -z "$BIT_HL" ] || [ -z "$BIT_L" ]; then
	echo "[FAIL] Failed to parse BIT STRING metadata from asn1parse output"
	echo "       line: $BIT_INFO_LINE"
	exit 1
fi

if [ "$BIT_L" -le 1 ]; then
	echo "[FAIL] BIT STRING length is invalid: $BIT_L"
	exit 1
fi

# BIT STRING payload layout: [unused-bits(1 byte)] [subjectPublicKey bytes...]
# Skip tag+len header and the first payload byte (unused-bits count), hash only subjectPublicKey.
SPK_SKIP="$((BIT_OFF + BIT_HL + 1))"
SPK_LEN="$((BIT_L - 1))"

dd if="$TMP_DIR/cert_spki.der" of="$TMP_DIR/subject_public_key.bin" \
	bs=1 skip="$SPK_SKIP" count="$SPK_LEN" 2>/dev/null

CALC_SKI_HEX="$(
	openssl dgst -sha1 -binary "$TMP_DIR/subject_public_key.bin" |
	od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F'
)"

if [ "$CERT_SKI_HEX" = "$CALC_SKI_HEX" ]; then
	echo "[PASS] SKI matches SHA1(subjectPublicKey)"
	echo "       SKI = $CERT_SKI_HEX"
else
	echo "[FAIL] SKI mismatch"
	echo "       Cert SKI = $CERT_SKI_HEX"
	echo "       Calc SKI = $CALC_SKI_HEX"
	fail=1
fi

# --------------------------------------------------------------------
# 2) Verify cert and key match
# --------------------------------------------------------------------

# cert pubkey DER
openssl pkey -pubin -in "$TMP_DIR/cert_pub.pem" -outform DER -out "$TMP_DIR/cert_pub.der"

# key -> pubkey DER (try generic pkey first, then EC/RSA fallbacks)
if ! openssl pkey -inform DER -in "$KEY_DER" -pubout -outform DER \
	-out "$TMP_DIR/key_pub.der" 2>/dev/null; then
	if ! openssl ec -inform DER -in "$KEY_DER" -pubout -outform DER \
		-out "$TMP_DIR/key_pub.der" 2>/dev/null; then
		if ! openssl rsa -inform DER -in "$KEY_DER" -pubout -outform DER \
			-out "$TMP_DIR/key_pub.der" 2>/dev/null; then
			echo "[FAIL] Could not derive public key from private key DER"
			exit 1
		fi
	fi
fi

if cmp -s "$TMP_DIR/cert_pub.der" "$TMP_DIR/key_pub.der"; then
	echo "[PASS] Certificate and private key match"
else
	echo "[FAIL] Certificate and private key do NOT match"
	echo "       cert pub sha256: $(openssl dgst -sha256 "$TMP_DIR/cert_pub.der" | awk '{print $2}')"
	echo "       key  pub sha256: $(openssl dgst -sha256 "$TMP_DIR/key_pub.der" | awk '{print $2}')"
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi

echo "All checks passed."
