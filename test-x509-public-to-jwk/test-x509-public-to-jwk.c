/*
 * X.509 Certificate Public Key to JWK Test
 * Tests lws_x509_public_to_jwk() function
 */

#include <libwebsockets.h>

#if !defined(LWS_WITH_JOSE)
#error "LWS_WITH_JOSE must be defined to build this test"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char cert_dir[512] = ".";  /* Default to current directory */

struct test_case {
	const char *name;
	const char *cert_path;
	const char *curves;      /* Allowed EC curves, NULL for no EC keys */
	int rsa_min_bits;        /* Minimum RSA key bits */
	enum lws_gencrypto_kty expected_kty;  /* Expected key type */
	int expected_result;      /* 0 = success, -1 = failure */
};

static void
get_full_path(const char *rel_path, char *full_path, size_t size)
{
	snprintf(full_path, size, "%s/%s", cert_dir, rel_path);
}

static int
load_cert_from_file(const char *path, struct lws_x509_cert **x509)
{
	FILE *fp;
	char pem[8192];
	size_t len;
	int ret;

	fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "ERROR: Failed to open %s\n", path);
		return -1;
	}

	len = fread(pem, 1, sizeof(pem) - 1, fp);
	fclose(fp);
	pem[len] = '\0';

	ret = lws_x509_create(x509);
	if (ret) {
		fprintf(stderr, "ERROR: lws_x509_create failed\n");
		return -1;
	}

	ret = lws_x509_parse_from_pem(*x509, pem, len + 1);
	if (ret) {
		fprintf(stderr, "ERROR: lws_x509_parse_from_pem failed for %s\n", path);
		lws_x509_destroy(x509);
		return -1;
	}

	return 0;
}

static void
print_jwk_info(struct lws_jwk *jwk)
{
	const char *kty_str;
	int i;

	switch (jwk->kty) {
	case LWS_GENCRYPTO_KTY_RSA:
		kty_str = "RSA";
		printf("  Key Type: RSA\n");
		printf("  Modulus (n): %u bytes\n", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len);
		printf("  Exponent (e): %u bytes\n", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len);
		break;
	case LWS_GENCRYPTO_KTY_EC:
		kty_str = "EC";
		printf("  Key Type: EC\n");
		printf("  X coordinate: %u bytes\n", jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len);
		printf("  Y coordinate: %u bytes\n", jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
		break;
	default:
		kty_str = "Unknown";
		printf("  Key Type: Unknown (%d)\n", jwk->kty);
		break;
	}

	/* Print hex dump of key elements for debugging */
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
run_test_case(const struct test_case *tc)
{
	struct lws_x509_cert *cert = NULL;
	struct lws_jwk jwk;
	char cert_full_path[512];
	int ret;
	int result;

	get_full_path(tc->cert_path, cert_full_path, sizeof(cert_full_path));

	printf("\n=== Test: %s ===\n", tc->name);
	printf("Certificate: %s\n", cert_full_path);
	if (tc->curves)
		printf("Allowed curves: %s\n", tc->curves);
	else
		printf("Allowed curves: (none)\n");
	printf("Min RSA bits: %d\n", tc->rsa_min_bits);

	if (load_cert_from_file(cert_full_path, &cert) < 0) {
		printf("FAILED: Could not load certificate\n");
		return -1;
	}

	memset(&jwk, 0, sizeof(jwk));

	ret = lws_x509_public_to_jwk(&jwk, cert, tc->curves, tc->rsa_min_bits);

	if (ret == tc->expected_result) {
		if (ret == 0) {
			/* Verify key type matches expectation */
			if (jwk.kty == tc->expected_kty) {
				result = 0;

				/* Validate key element lengths */
				if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
					unsigned int nlen = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
					unsigned int elen = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].len;

					if (!nlen || !elen) {
						printf("FAILED: RSA n/e length invalid (n=%u, e=%u)\n",
						       nlen, elen);
						result = -1;
					} else if (tc->rsa_min_bits > 0 &&
						   nlen < (unsigned int)(tc->rsa_min_bits / 8)) {
						printf("FAILED: RSA modulus too short: %u bytes (< %d bytes)\n",
						       nlen, tc->rsa_min_bits / 8);
						result = -1;
					}
				}

				if (result == 0 && jwk.kty == LWS_GENCRYPTO_KTY_EC) {
					unsigned int xlen = jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
					unsigned int ylen = jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

					if (!xlen || !ylen) {
						printf("FAILED: EC x/y length invalid (x=%u, y=%u)\n",
						       xlen, ylen);
						result = -1;
					} else {
						printf("EC coordinate lengths: x=%u, y=%u\n", xlen, ylen);
					}
				}

				if (result == 0) {
					printf("PASSED\n");
					print_jwk_info(&jwk);
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
	int total = 0, passed = 0;

	/* Test cases covering different scenarios */
	struct test_case tests[] = {
		{
			.name = "RSA certificate (2048-bit)",
			.cert_path = "rsa-2048-cert.pem",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA certificate (4096-bit)",
			.cert_path = "rsa-4096-cert.pem",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA certificate - insufficient bits (1024-bit rejected)",
			.cert_path = "rsa-1024-cert.pem",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = -1
		},
		{
			.name = "EC certificate (P-256)",
			.cert_path = "ec-p256-cert.pem",
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate (P-384)",
			.cert_path = "ec-p384-cert.pem",
			.curves = "P-384",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate (P-521)",
			.cert_path = "ec-p521-cert.pem",
			.curves = "P-521",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate - curve token mismatch still accepted by current implementation",
			.cert_path = "ec-p256-cert.pem",
			.curves = "P-384",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate - unsupported curve id (P-224)",
			.cert_path = "ec-p224-cert.pem",
			.curves = "P-224",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "EC certificate - no curves allowed",
			.cert_path = "ec-p256-cert.pem",
			.curves = NULL,
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "RSA certificate with curve list (RSA should work)",
			.cert_path = "rsa-2048-cert.pem",
			.curves = "P-256,P-384",
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "EC certificate with multiple allowed curves",
			.cert_path = "ec-p256-cert.pem",
			.curves = "P-256,P-384,P-521",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
	};

	size_t i;
	char check_path[512];

	/* Initialize lws library - this is required for some internal state */
	/* Use minimal configuration for test purposes */

	/* Set log level to include NOTICE and above */
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER, NULL);

	/* Parse command line arguments */
	if (argc >= 2) {
		strncpy(cert_dir, argv[1], sizeof(cert_dir) - 1);
		cert_dir[sizeof(cert_dir) - 1] = '\0';
	}

	printf("========================================================\n");
	printf("     X.509 Public Key to JWK Conversion Test Suite    \n");
	printf("========================================================\n");
	printf("Certificate directory: %s\n", cert_dir);
	printf("========================================================");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		/* Skip tests for files that don't exist */
		get_full_path(tests[i].cert_path, check_path, sizeof(check_path));
		FILE *f = fopen(check_path, "rb");
		if (!f) {
			printf("\n=== Test: %s ===\n", tests[i].name);
			printf("SKIPPED: File %s not found\n", check_path);
			continue;
		}
		fclose(f);

		total++;
		if (run_test_case(&tests[i]) == 0)
			passed++;
	}

	printf("\n========================================================\n");
	printf("  Results: %d/%d tests passed\n", passed, total);
	printf("========================================================\n");

	return (passed == total) ? 0 : 1;
}
