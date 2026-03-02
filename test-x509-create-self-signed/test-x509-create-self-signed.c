/*
 * X.509 Self-signed Certificate Creation Test
 * Covers key type / key_bits behavior, x509 extensions, SAN handling,
 * signature algorithm, private key acceptance, and error paths.
 */

#include <libwebsockets.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#if defined(_WIN32)
#include <io.h>
#include <sys/stat.h>
#define LWS_TEST_OPEN  _open
#define LWS_TEST_WRITE _write
#define LWS_TEST_CLOSE _close
#ifndef O_BINARY
#define O_BINARY 0
#endif
#define LWS_TEST_OPEN_MODE (_S_IREAD | _S_IWRITE)
#else
#include <unistd.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif
#define LWS_TEST_OPEN  open
#define LWS_TEST_WRITE write
#define LWS_TEST_CLOSE close
#define LWS_TEST_OPEN_MODE 0644
#endif

#define TEST_PASS 0
#define TEST_FAIL 1
#define TEST_SKIP 2

#define TEST_KU_DIGITAL_SIGNATURE 0x0080u
#define TEST_KU_KEY_ENCIPHERMENT  0x0020u

enum expected_key_type {
	EKT_ANY = 0,
	EKT_RSA,
	EKT_EC
};

enum expected_sig_alg {
	ESA_ANY = 0,
	ESA_RSA_SHA256,
	ESA_ECDSA_SHA256
};

struct test_case {
	const char *name;
	const char *san;
	int key_bits;
	int use_context;
};

static const uint8_t oid_basic_constraints[] = { 0x06, 0x03, 0x55, 0x1d, 0x13 };
static const uint8_t oid_key_usage[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f };
static const uint8_t oid_ext_key_usage[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };
static const uint8_t oid_subject_alt_name[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
static const uint8_t oid_server_auth[] = {
	0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01
};
static const uint8_t oid_client_auth[] = {
	0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
};
static const uint8_t oid_sig_rsa_sha256[] = {
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
};
static const uint8_t oid_sig_ecdsa_sha256[] = {
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};

static int
der_has_bytes(const uint8_t *der, size_t der_len,
	      const uint8_t *needle, size_t needle_len)
{
	size_t n;

	if (!needle_len || der_len < needle_len)
		return 0;

	for (n = 0; n + needle_len <= der_len; n++)
		if (!memcmp(der + n, needle, needle_len))
			return 1;

	return 0;
}

#if !defined(LWS_WITH_MBEDTLS) && !defined(LWS_WITH_WOLFSSL)
static int
der_has_dns_general_name(const uint8_t *der, size_t der_len, const char *dns)
{
	uint8_t pat[258];
	size_t sl = strlen(dns);

	if (sl > 255u)
		return 0;

	pat[0] = 0x82; /* [2] dNSName */
	pat[1] = (uint8_t)sl;
	memcpy(pat + 2, dns, sl);

	return der_has_bytes(der, der_len, pat, sl + 2);
}

#if !defined(LWS_WITH_GNUTLS)
static int
der_has_ipv4_general_name_127001(const uint8_t *der, size_t der_len)
{
	static const uint8_t pat[] = { 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01 };

	return der_has_bytes(der, der_len, pat, sizeof(pat));
}
#endif
#endif

#if defined(LWS_WITH_JOSE)
static enum expected_key_type
backend_expected_key_type(void)
{
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_GNUTLS)
	return EKT_RSA;
#elif defined(LWS_WITH_WOLFSSL)
	return EKT_ANY;
#else
	return EKT_EC;
#endif
}
#endif

static enum expected_sig_alg
backend_expected_sig_alg(void)
{
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_GNUTLS)
	return ESA_RSA_SHA256;
#elif defined(LWS_WITH_WOLFSSL)
	return ESA_ANY;
#else
	return ESA_ECDSA_SHA256;
#endif
}

static int
backend_expect_keyencipherment_usage(void)
{
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_GNUTLS)
	return 1;
#else
	return 0;
#endif
}

static int
backend_expect_eku_extension(void)
{
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_GNUTLS)
	return 0;
#elif defined(LWS_WITH_WOLFSSL)
	return 0;
#else
	return 1;
#endif
}

static int
backend_expect_san_extension(void)
{
#if defined(LWS_WITH_MBEDTLS)
	return 0;
#elif defined(LWS_WITH_WOLFSSL)
	return 0;
#else
	return 1;
#endif
}

static int
backend_invalid_keybits_should_fail(void)
{
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_GNUTLS) || defined(LWS_WITH_WOLFSSL)
	return 1;
#else
	return 0;
#endif
}

static int
der_to_pem(const uint8_t *der, size_t der_len, const char *pem_type,
	   char **pem_out, size_t *pem_len_out)
{
	char *b64 = NULL, *pem = NULL;
	size_t b64_cap, pem_cap, i, o = 0, type_len, lines;
	int n;

	*pem_out = NULL;
	*pem_len_out = 0;

	b64_cap = (size_t)lws_base64_size((int)der_len) + 8;
	b64 = (char *)malloc(b64_cap);
	if (!b64)
		return -1;

	n = lws_b64_encode_string((const char *)der, (int)der_len,
				  b64, (int)b64_cap);
	if (n < 0)
		goto bail;

	type_len = strlen(pem_type);
	lines = ((size_t)n + 63u) / 64u;
	pem_cap = (size_t)n + lines + (type_len * 2u) + 64u;

	pem = (char *)malloc(pem_cap);
	if (!pem)
		goto bail;

	o += (size_t)lws_snprintf(pem + o, pem_cap - o,
				  "-----BEGIN %s-----\n", pem_type);
	for (i = 0; i < (size_t)n; i += 64u) {
		size_t chunk = (size_t)n - i;

		if (chunk > 64u)
			chunk = 64u;
		memcpy(pem + o, b64 + i, chunk);
		o += chunk;
		pem[o++] = '\n';
	}
	o += (size_t)lws_snprintf(pem + o, pem_cap - o,
				  "-----END %s-----\n", pem_type);
	pem[o] = '\0';

	*pem_out = pem;
	*pem_len_out = o + 1;
	free(b64);

	return 0;

bail:
	free(b64);
	free(pem);

	return -1;
}

static int
write_file_all(const char *path, const uint8_t *buf, size_t len)
{
	int fd;
	size_t off = 0;

	fd = LWS_TEST_OPEN(path, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY,
			   LWS_TEST_OPEN_MODE);
	if (fd < 0) {
		fprintf(stderr, "ERROR: open('%s') failed: %d\n", path, errno);
		return -1;
	}

	while (off < len) {
#if defined(_WIN32)
		int n = LWS_TEST_WRITE(fd, buf + off, (unsigned int)(len - off));
#else
		ssize_t n = LWS_TEST_WRITE(fd, buf + off, len - off);
#endif
		if (n < 0) {
			fprintf(stderr, "ERROR: write('%s') failed: %d\n", path, errno);
			LWS_TEST_CLOSE(fd);
			return -1;
		}
		if (!n) {
			fprintf(stderr, "ERROR: write('%s') wrote 0 bytes\n", path);
			LWS_TEST_CLOSE(fd);
			return -1;
		}
		off += (size_t)n;
	}

	if (LWS_TEST_CLOSE(fd) < 0) {
		fprintf(stderr, "ERROR: close('%s') failed: %d\n", path, errno);
		return -1;
	}

	return 0;
}

static int
dump_generated_artifacts(size_t case_idx, const uint8_t *cert_der, size_t cert_len,
			 const uint8_t *key_der, size_t key_len)
{
	char cert_der_path[64], key_der_path[64];

	lws_snprintf(cert_der_path, sizeof(cert_der_path),
		     "selfsigned_case%02u_cert.der", (unsigned int)(case_idx + 1u));
	lws_snprintf(key_der_path, sizeof(key_der_path),
		     "selfsigned_case%02u_key.der", (unsigned int)(case_idx + 1u));

	if (write_file_all(cert_der_path, cert_der, cert_len))
		return -1;

	if (write_file_all(key_der_path, key_der, key_len))
		return -1;

	printf("Generated files: %s, %s\n", cert_der_path, key_der_path);

	return 0;
}

static int
parse_cert_from_der(const uint8_t *cert_der, size_t cert_len,
		    struct lws_x509_cert **x509)
{
	char *pem = NULL;
	size_t pem_len = 0;

	*x509 = NULL;

	if (der_to_pem(cert_der, cert_len, "CERTIFICATE", &pem, &pem_len)) {
		fprintf(stderr, "ERROR: Failed to convert cert DER to PEM\n");
		return -1;
	}

	if (lws_x509_create(x509)) {
		fprintf(stderr, "ERROR: lws_x509_create failed\n");
		free(pem);
		return -1;
	}

	if (lws_x509_parse_from_pem(*x509, pem, pem_len)) {
		fprintf(stderr, "ERROR: lws_x509_parse_from_pem failed\n");
		lws_x509_destroy(x509);
		free(pem);
		return -1;
	}

	free(pem);

	return 0;
}

static int
check_base_cert_info(struct lws_x509_cert *x509, const uint8_t *cert_der,
		     size_t cert_len, const char *expected_cn)
{
	union lws_tls_cert_info_results *buf;
	unsigned char fixed[1024];
	unsigned char *raw = NULL;
	size_t expected_cn_len = strlen(expected_cn);
	size_t len;
	int n;
	time_t from, to;

	buf = (union lws_tls_cert_info_results *)fixed;
	len = sizeof(fixed) - sizeof(*buf) + sizeof(buf->ns.name);

	n = lws_x509_info(x509, LWS_TLS_CERT_INFO_COMMON_NAME, buf, len);
	if (n) {
		fprintf(stderr, "ERROR: LWS_TLS_CERT_INFO_COMMON_NAME failed: %d\n", n);
		return -1;
	}
	if ((size_t)buf->ns.len != expected_cn_len ||
	    memcmp(buf->ns.name, expected_cn, expected_cn_len)) {
		fprintf(stderr, "ERROR: CN mismatch, expected '%s', got '%.*s'\n",
			expected_cn, buf->ns.len, buf->ns.name);
		return -1;
	}

	n = lws_x509_info(x509, LWS_TLS_CERT_INFO_VALIDITY_FROM, buf, len);
	if (n) {
		fprintf(stderr, "ERROR: LWS_TLS_CERT_INFO_VALIDITY_FROM failed: %d\n", n);
		return -1;
	}
	from = buf->time;

	n = lws_x509_info(x509, LWS_TLS_CERT_INFO_VALIDITY_TO, buf, len);
	if (n) {
		fprintf(stderr, "ERROR: LWS_TLS_CERT_INFO_VALIDITY_TO failed: %d\n", n);
		return -1;
	}
	to = buf->time;

	if (to <= from) {
		fprintf(stderr, "ERROR: invalid validity range: from=%lld to=%lld\n",
			(long long)from, (long long)to);
		return -1;
	}

	n = lws_x509_info(x509, LWS_TLS_CERT_INFO_USAGE, buf, len);
	if (n) {
		fprintf(stderr, "ERROR: LWS_TLS_CERT_INFO_USAGE failed: %d\n", n);
		return -1;
	}
	if (!(buf->usage & TEST_KU_DIGITAL_SIGNATURE)) {
		fprintf(stderr, "ERROR: key usage missing digitalSignature bit: 0x%x\n",
			buf->usage);
		return -1;
	}
	if (backend_expect_keyencipherment_usage() &&
	    !(buf->usage & TEST_KU_KEY_ENCIPHERMENT)) {
		fprintf(stderr, "ERROR: key usage missing keyEncipherment bit: 0x%x\n",
			buf->usage);
		return -1;
	}

	raw = (unsigned char *)malloc(cert_len + 256u);
	if (!raw) {
		fprintf(stderr, "ERROR: OOM for DER raw check\n");
		return -1;
	}

	buf = (union lws_tls_cert_info_results *)raw;
	len = cert_len + 256u - sizeof(*buf) + sizeof(buf->ns.name);

	n = lws_x509_info(x509, LWS_TLS_CERT_INFO_DER_RAW, buf, len);
	if (n) {
		fprintf(stderr, "ERROR: LWS_TLS_CERT_INFO_DER_RAW failed: %d\n", n);
		free(raw);
		return -1;
	}
	if ((size_t)buf->ns.len != cert_len ||
	    memcmp(buf->ns.name, cert_der, cert_len)) {
		fprintf(stderr, "ERROR: DER roundtrip mismatch\n");
		free(raw);
		return -1;
	}
	free(raw);

	return 0;
}

static int
check_extension_oids(const uint8_t *cert_der, size_t cert_len, const char *san)
{
	int has_bc, has_ku, has_eku, has_san, expect_eku, expect_san;

	has_bc = der_has_bytes(cert_der, cert_len, oid_basic_constraints,
			       sizeof(oid_basic_constraints));
	has_ku = der_has_bytes(cert_der, cert_len, oid_key_usage,
			       sizeof(oid_key_usage));
	has_eku = der_has_bytes(cert_der, cert_len, oid_ext_key_usage,
				sizeof(oid_ext_key_usage));
	has_san = der_has_bytes(cert_der, cert_len, oid_subject_alt_name,
				sizeof(oid_subject_alt_name));

	if (!has_bc) {
		fprintf(stderr, "ERROR: basicConstraints extension OID missing\n");
		return -1;
	}
	if (!has_ku) {
		fprintf(stderr, "ERROR: keyUsage extension OID missing\n");
		return -1;
	}

	expect_eku = backend_expect_eku_extension();
	if (expect_eku && !has_eku) {
		fprintf(stderr, "ERROR: extKeyUsage extension OID missing\n");
		return -1;
	}
	if (expect_eku) {
		if (!der_has_bytes(cert_der, cert_len, oid_server_auth, sizeof(oid_server_auth))) {
			fprintf(stderr, "ERROR: extKeyUsage missing serverAuth OID\n");
			return -1;
		}
		if (!der_has_bytes(cert_der, cert_len, oid_client_auth, sizeof(oid_client_auth))) {
			fprintf(stderr, "ERROR: extKeyUsage missing clientAuth OID\n");
			return -1;
		}
	}

	expect_san = san && backend_expect_san_extension();
	if (expect_san && !has_san) {
		fprintf(stderr, "ERROR: SAN extension OID missing\n");
		return -1;
	}
	if (!san && has_san) {
		fprintf(stderr, "ERROR: SAN extension exists unexpectedly when san==NULL\n");
		return -1;
	}
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_WOLFSSL)
	if (san && has_san) {
		fprintf(stderr, "ERROR: SAN extension unexpectedly present for this backend\n");
		return -1;
	}
#endif

	if (san && expect_san) {
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_WOLFSSL)
		(void)cert_der;
		(void)cert_len;
#else
		if (!strcmp(san, "127.0.0.1")) {
#if defined(LWS_WITH_GNUTLS)
			if (!der_has_dns_general_name(cert_der, cert_len, san)) {
				fprintf(stderr, "ERROR: SAN DNS value '%s' not found\n", san);
				return -1;
			}
#else
			if (!der_has_ipv4_general_name_127001(cert_der, cert_len)) {
				fprintf(stderr, "ERROR: SAN IPv4 value 127.0.0.1 not found\n");
				return -1;
			}
#endif
		} else {
			if (!der_has_dns_general_name(cert_der, cert_len, san)) {
				fprintf(stderr, "ERROR: SAN DNS value '%s' not found\n", san);
				return -1;
			}
		}
#endif
	}

	return 0;
}

static int
check_signature_algorithm(const uint8_t *cert_der, size_t cert_len)
{
	int has_rsa, has_ecdsa;
	enum expected_sig_alg esa = backend_expected_sig_alg();

	has_rsa = der_has_bytes(cert_der, cert_len, oid_sig_rsa_sha256,
				sizeof(oid_sig_rsa_sha256));
	has_ecdsa = der_has_bytes(cert_der, cert_len, oid_sig_ecdsa_sha256,
				  sizeof(oid_sig_ecdsa_sha256));

	if (esa == ESA_RSA_SHA256 && !has_rsa) {
		fprintf(stderr, "ERROR: expected sha256WithRSAEncryption not found\n");
		return -1;
	}
	if (esa == ESA_ECDSA_SHA256 && !has_ecdsa) {
		fprintf(stderr, "ERROR: expected ecdsa-with-SHA256 not found\n");
		return -1;
	}

	return 0;
}

#if defined(LWS_WITH_JOSE)
static int
check_key_and_private_key(struct lws_context *context, struct lws_x509_cert *x509,
			  const uint8_t *key_der, size_t key_len, int requested_bits)
{
	struct lws_jwk jwk;
	const char *key_pem_type = NULL;
	enum expected_key_type ekt = backend_expected_key_type();
	char *key_pem = NULL;
	size_t key_pem_len = 0;
	int bits;
	int ret = -1;

	memset(&jwk, 0, sizeof(jwk));

	if (lws_x509_public_to_jwk(&jwk, x509, "P-256,P-384,P-521", 1)) {
		fprintf(stderr, "ERROR: lws_x509_public_to_jwk failed\n");
		goto bail;
	}

	if (ekt == EKT_RSA && jwk.kty != LWS_GENCRYPTO_KTY_RSA) {
		fprintf(stderr, "ERROR: expected RSA cert key type, got kty=%d\n", jwk.kty);
		goto bail;
	}
	if (ekt == EKT_EC && jwk.kty != LWS_GENCRYPTO_KTY_EC) {
		fprintf(stderr, "ERROR: expected EC cert key type, got kty=%d\n", jwk.kty);
		goto bail;
	}

	if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
		bits = (int)jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len * 8;
		if (requested_bits > 0 &&
		    (bits < requested_bits - 16 || bits > requested_bits + 16)) {
			fprintf(stderr, "ERROR: RSA bits %d not close to requested %d\n",
				bits, requested_bits);
			goto bail;
		}
		key_pem_type = "RSA PRIVATE KEY";
	} else if (jwk.kty == LWS_GENCRYPTO_KTY_EC) {
		if (jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len != 32 ||
		    jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len != 32) {
			fprintf(stderr, "ERROR: expected EC P-256 key length x=y=32, got x=%u y=%u\n",
				jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len,
				jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
			goto bail;
		}
		key_pem_type = "EC PRIVATE KEY";
	} else {
		fprintf(stderr, "ERROR: unsupported jwk kty=%d\n", jwk.kty);
		goto bail;
	}

	if (der_to_pem(key_der, key_len, key_pem_type, &key_pem, &key_pem_len)) {
		fprintf(stderr, "ERROR: failed to convert key DER to PEM (%s)\n",
			key_pem_type);
		goto bail;
	}

	if (lws_x509_jwk_privkey_pem(context, &jwk, key_pem, key_pem_len, NULL)) {
		fprintf(stderr, "ERROR: lws_x509_jwk_privkey_pem failed\n");
		goto bail;
	}

	ret = 0;

bail:
	lws_jwk_destroy(&jwk);
	if (key_pem)
		free(key_pem);

	return ret;
}
#endif

static int
run_test_case(struct lws_context *context, const struct test_case *tc, size_t case_idx)
{
	struct lws_context *cx = tc->use_context ? context : NULL;
	struct lws_x509_cert *x509 = NULL;
	uint8_t *cert_der = NULL, *key_der = NULL;
	size_t cert_len = 0, key_len = 0;
	const char *expected_cn = tc->san ? tc->san : "localhost";
	int ret, result = TEST_FAIL;

	printf("\n=== Test: %s ===\n", tc->name);
	printf("san=%s, key_bits=%d, context=%s\n",
	       tc->san ? tc->san : "(null)",
	       tc->key_bits, tc->use_context ? "yes" : "no");

	ret = lws_x509_create_self_signed(cx, &cert_der, &cert_len,
					  &key_der, &key_len,
					  tc->san, tc->key_bits);
	if (ret) {
#if defined(LWS_WITH_WOLFSSL)
		printf("SKIPPED: lws_x509_create_self_signed unsupported on wolfSSL\n");
		return TEST_SKIP;
#else
		fprintf(stderr, "ERROR: lws_x509_create_self_signed failed\n");
		goto bail;
#endif
	}

	if (!cert_der || !key_der || !cert_len || !key_len) {
		fprintf(stderr, "ERROR: invalid generated buffers cert=%p/%zu key=%p/%zu\n",
			(void *)cert_der, cert_len, (void *)key_der, key_len);
		goto bail;
	}

	if (cert_der[0] != 0x30 || key_der[0] != 0x30) {
		fprintf(stderr, "ERROR: DER output does not start with ASN.1 SEQUENCE\n");
		goto bail;
	}

	if (dump_generated_artifacts(case_idx, cert_der, cert_len, key_der, key_len))
		fprintf(stderr, "WARNING: failed to dump generated cert/key artifacts\n");

	if (parse_cert_from_der(cert_der, cert_len, &x509))
		goto bail;

	if (check_base_cert_info(x509, cert_der, cert_len, expected_cn))
		goto bail;

	if (check_extension_oids(cert_der, cert_len, tc->san))
		goto bail;

	if (check_signature_algorithm(cert_der, cert_len))
		goto bail;

#if defined(LWS_WITH_JOSE)
	if (check_key_and_private_key(context, x509, key_der, key_len, tc->key_bits))
		goto bail;
#else
	printf("NOTE: JOSE disabled, key type/key_bits/private-key checks skipped\n");
#endif

	printf("PASSED (cert=%zu bytes, key=%zu bytes)\n", cert_len, key_len);
	result = TEST_PASS;

bail:
	lws_x509_destroy(&x509);
	if (cert_der)
		free(cert_der);
	if (key_der)
		free(key_der);

	return result;
}

static int
run_invalid_keybits_test(struct lws_context *context)
{
	uint8_t *cert_der = NULL, *key_der = NULL;
	size_t cert_len = 0, key_len = 0;
	int ret;
	int expect_fail = backend_invalid_keybits_should_fail();

	printf("\n=== Test: Invalid key_bits (0) ===\n");

	ret = lws_x509_create_self_signed(context, &cert_der, &cert_len,
					  &key_der, &key_len, "localhost", 0);
	if (expect_fail && !ret) {
		fprintf(stderr, "ERROR: key_bits=0 unexpectedly succeeded\n");
		if (cert_der)
			free(cert_der);
		if (key_der)
			free(key_der);
		return TEST_FAIL;
	}
	if (!expect_fail && ret) {
		fprintf(stderr, "ERROR: key_bits=0 unexpectedly failed\n");
		return TEST_FAIL;
	}

	if (!ret) {
		if (!cert_der || !key_der || !cert_len || !key_len) {
			fprintf(stderr, "ERROR: key_bits=0 success but outputs invalid\n");
			if (cert_der)
				free(cert_der);
			if (key_der)
				free(key_der);
			return TEST_FAIL;
		}
		free(cert_der);
		free(key_der);
	}

	printf("PASSED (expected %s)\n", expect_fail ? "failure" : "success");

	return TEST_PASS;
}

int
main(void)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int total = 0, passed = 0, skipped = 0;
	size_t i;
	struct test_case tests[] = {
		{
			.name = "SAN hostname, key_bits=1024, no context",
			.san = "localhost",
			.key_bits = 1024,
			.use_context = 0
		},
		{
			.name = "SAN hostname, key_bits=2048, with context RNG",
			.san = "localhost",
			.key_bits = 2048,
			.use_context = 1
		},
		{
			.name = "SAN IP-like string",
			.san = "127.0.0.1",
			.key_bits = 2048,
			.use_context = 0
		},
		{
			.name = "NULL SAN defaults to localhost CN",
			.san = NULL,
			.key_bits = 2048,
			.use_context = 0
		}
	};

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

	memset(&info, 0, sizeof(info));
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		fprintf(stderr, "ERROR: Failed to create lws context\n");
		return 1;
	}

	printf("========================================================\n");
	printf("    X.509 Self-signed Certificate Creation Test Suite   \n");
	printf("========================================================\n");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int n;

		total++;
		n = run_test_case(context, &tests[i], i);
		if (n == TEST_PASS)
			passed++;
		else if (n == TEST_SKIP)
			skipped++;
	}

	total++;
	if (run_invalid_keybits_test(context) == TEST_PASS)
		passed++;

	printf("\n========================================================\n");
	printf("  Results: %d passed, %d skipped, %d failed\n",
	       passed, skipped, total - passed - skipped);
	printf("========================================================\n");

	lws_context_destroy(context);

	return (passed + skipped == total) ? 0 : 1;
}
