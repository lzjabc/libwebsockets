/*
 * X.509 Private Key PEM to JWK Test
 * Tests lws_x509_jwk_privkey_pem() function
 */

#include <libwebsockets.h>

#if !defined(LWS_WITH_JOSE)
#error "LWS_WITH_JOSE must be defined to build this test"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char key_dir[512] = ".";

struct test_case {
	const char *name;
	const char *cert_path;
	const char *key_path;
	const char *passphrase;
	const char *curves;
	int rsa_min_bits;
	enum lws_gencrypto_kty expected_kty;
	int expected_result;
};

static void
get_full_path(const char *rel_path, char *full_path, size_t size)
{
	snprintf(full_path, size, "%s/%s", key_dir, rel_path);
}

static int
load_file(const char *path, char *buf, size_t buf_size, size_t *len)
{
	FILE *fp;
	size_t n;

	fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "ERROR: Failed to open %s\n", path);
		return -1;
	}

	n = fread(buf, 1, buf_size - 1, fp);
	fclose(fp);
	if (n == 0) {
		fprintf(stderr, "ERROR: Empty file %s\n", path);
		return -1;
	}
	buf[n] = '\0';
	*len = n + 1;

	return 0;
}

static int
load_cert_and_pubkey(const char *cert_path, struct lws_x509_cert **x509,
		     struct lws_jwk *jwk, const char *curves, int rsa_min_bits)
{
	char pem[8192];
	size_t len;
	int ret;

	if (load_file(cert_path, pem, sizeof(pem), &len))
		return -1;

	ret = lws_x509_create(x509);
	if (ret) {
		fprintf(stderr, "ERROR: lws_x509_create failed\n");
		return -1;
	}

	ret = lws_x509_parse_from_pem(*x509, pem, len);
	if (ret) {
		fprintf(stderr, "ERROR: lws_x509_parse_from_pem failed for %s\n", cert_path);
		lws_x509_destroy(x509);
		return -1;
	}

	memset(jwk, 0, sizeof(*jwk));
	ret = lws_x509_public_to_jwk(jwk, *x509, curves, rsa_min_bits);
	if (ret) {
		fprintf(stderr, "ERROR: lws_x509_public_to_jwk failed for %s\n", cert_path);
		lws_x509_destroy(x509);
		return -1;
	}

	return 0;
}

static void
print_jwk_privkey_info(struct lws_jwk *jwk)
{
	int i;

	switch (jwk->kty) {
	case LWS_GENCRYPTO_KTY_RSA:
		printf("  Key Type: RSA\n");
		printf("  Modulus (n): %u bytes\n", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len);
		printf("  Exponent (e): %u bytes\n", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len);
		if (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf)
			printf("  Private exponent (d): %u bytes\n", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].len);
		if (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf)
			printf("  Prime p: %u bytes\n", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].len);
		if (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf)
			printf("  Prime q: %u bytes\n", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].len);
		break;
	case LWS_GENCRYPTO_KTY_EC:
		printf("  Key Type: EC\n");
		printf("  X coordinate: %u bytes\n", jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len);
		printf("  Y coordinate: %u bytes\n", jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
		if (jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf)
			printf("  Private key (d): %u bytes\n", jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len);
		break;
	default:
		printf("  Key Type: Unknown (%d)\n", jwk->kty);
		break;
	}

	for (i = 0; i < LWS_GENCRYPTO_MAX_KEYEL_COUNT; i++) {
		if (jwk->e[i].buf && jwk->e[i].len > 0) {
			printf("  Element[%d]: %u bytes - first 8 bytes: ", i, jwk->e[i].len);
			for (size_t j = 0; j < 8 && j < jwk->e[i].len; j++) {
				printf("%02x", jwk->e[i].buf[j]);
			}
			if (jwk->e[i].len > 8)
				printf("...");
			printf("\n");
		}
	}
}

static int
run_test_case(struct lws_context *context, const struct test_case *tc)
{
	struct lws_x509_cert *cert = NULL;
	struct lws_jwk jwk;
	char cert_full_path[512];
	char key_full_path[512];
	char key_pem[8192];
	size_t key_len;
	int ret;
	int result;

	get_full_path(tc->cert_path, cert_full_path, sizeof(cert_full_path));
	get_full_path(tc->key_path, key_full_path, sizeof(key_full_path));

	printf("\n=== Test: %s ===\n", tc->name);
	printf("Certificate: %s\n", cert_full_path);
	printf("Private Key: %s\n", key_full_path);
	if (tc->passphrase)
		printf("Passphrase: (provided)\n");
	else
		printf("Passphrase: (none)\n");

	if (load_cert_and_pubkey(cert_full_path, &cert, &jwk,
				 tc->curves, tc->rsa_min_bits) < 0) {
		printf("FAILED: Could not load certificate or public key\n");
		return -1;
	}

	if (load_file(key_full_path, key_pem, sizeof(key_pem), &key_len)) {
		printf("FAILED: Could not load private key file\n");
		lws_jwk_destroy(&jwk);
		lws_x509_destroy(&cert);
		return -1;
	}

	ret = lws_x509_jwk_privkey_pem(context, &jwk, key_pem, key_len, tc->passphrase);

	if (ret == tc->expected_result) {
		if (ret == 0) {
			if (jwk.kty == tc->expected_kty) {
				result = 0;

				if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
					if (!jwk.e[LWS_GENCRYPTO_RSA_KEYEL_D].buf ||
					    !jwk.e[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
					    !jwk.e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) {
						printf("FAILED: RSA private key elements missing\n");
						result = -1;
					}
				}

				if (result == 0 && jwk.kty == LWS_GENCRYPTO_KTY_EC) {
					if (!jwk.e[LWS_GENCRYPTO_EC_KEYEL_D].buf) {
						printf("FAILED: EC private key element missing\n");
						result = -1;
					}
				}

				if (result == 0) {
					printf("PASSED\n");
					print_jwk_privkey_info(&jwk);
				}
			} else {
				printf("FAILED: Expected key type %d, got %d\n",
				       tc->expected_kty, jwk.kty);
				result = -1;
			}
		} else {
			printf("PASSED (expected failure)\n");
			result = 0;
		}
	} else {
		printf("FAILED: Expected return %d, got %d\n",
		       tc->expected_result, ret);
		result = -1;
	}

	lws_jwk_destroy(&jwk);
	lws_x509_destroy(&cert);

	return result;
}

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int total = 0, passed = 0;
	size_t i;
	char check_path[512];

	struct test_case tests[] = {
		{
			.name = "RSA 2048-bit private key",
			.cert_path = "rsa-2048-cert.pem",
			.key_path = "rsa-2048-key.pem",
			.passphrase = NULL,
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA 4096-bit private key",
			.cert_path = "rsa-4096-cert.pem",
			.key_path = "rsa-4096-key.pem",
			.passphrase = NULL,
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA 2048-bit encrypted private key (correct passphrase)",
			.cert_path = "rsa-2048-cert.pem",
			.key_path = "rsa-2048-key-encrypted.pem",
			.passphrase = "testpass123",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA 2048-bit encrypted private key (wrong passphrase)",
			.cert_path = "rsa-2048-cert.pem",
			.key_path = "rsa-2048-key-encrypted.pem",
			.passphrase = "wrongpassword",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = -1
		},
		{
			.name = "EC P-256 private key",
			.cert_path = "ec-p256-cert.pem",
			.key_path = "ec-p256-key.pem",
			.passphrase = NULL,
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-384 private key",
			.cert_path = "ec-p384-cert.pem",
			.key_path = "ec-p384-key.pem",
			.passphrase = NULL,
			.curves = "P-384",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-521 private key",
			.cert_path = "ec-p521-cert.pem",
			.key_path = "ec-p521-key.pem",
			.passphrase = NULL,
			.curves = "P-521",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-256 encrypted private key (correct passphrase)",
			.cert_path = "ec-p256-cert.pem",
			.key_path = "ec-p256-key-encrypted.pem",
			.passphrase = "testpass123",
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-256 encrypted private key (wrong passphrase)",
			.cert_path = "ec-p256-cert.pem",
			.key_path = "ec-p256-key-encrypted.pem",
			.passphrase = "wrongpassword",
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "Mismatched key type (EC cert with RSA key)",
			.cert_path = "ec-p256-cert.pem",
			.key_path = "rsa-2048-key.pem",
			.passphrase = NULL,
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "Mismatched RSA keys (different cert/key)",
			.cert_path = "rsa-2048-cert.pem",
			.key_path = "rsa-4096-key.pem",
			.passphrase = NULL,
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = -1
		},
		{
			.name = "EC same curve different keypair (exposes length-only check bug)",
			.cert_path = "ec-p256-cert.pem",
			.key_path = "ec-p256-b-key.pem",
			.passphrase = NULL,
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
	};

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER, NULL);

	if (argc >= 2) {
		strncpy(key_dir, argv[1], sizeof(key_dir) - 1);
		key_dir[sizeof(key_dir) - 1] = '\0';
	}

	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		fprintf(stderr, "ERROR: Failed to create lws context\n");
		return 1;
	}

	printf("========================================================\n");
	printf("   X.509 Private Key PEM to JWK Conversion Test Suite   \n");
	printf("========================================================\n");
	printf("Key directory: %s\n", key_dir);
	printf("========================================================");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		get_full_path(tests[i].key_path, check_path, sizeof(check_path));
		FILE *f = fopen(check_path, "rb");
		if (!f) {
			printf("\n=== Test: %s ===\n", tests[i].name);
			printf("SKIPPED: File %s not found\n", check_path);
			continue;
		}
		fclose(f);

		total++;
		if (run_test_case(context, &tests[i]) == 0)
			passed++;
	}

	printf("\n========================================================\n");
	printf("  Results: %d/%d tests passed\n", passed, total);
	printf("========================================================\n");

	lws_context_destroy(context);

	return (passed == total) ? 0 : 1;
}
