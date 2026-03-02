/*
 * X.509 Certificate Verification Test
 * Tests OpenHITLS implementation against OpenSSL baseline
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>

static char cert_dir[512] = ".";  /* Default to current directory */

struct test_case {
	const char *name;
	const char *cert_path;
	const char *trusted_path;
	const char *common_name;
	int expected_result;  /* 0 = success, -1 = failure */
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

static int
run_test_case(const struct test_case *tc)
{
	struct lws_x509_cert *cert = NULL;
	struct lws_x509_cert *trusted = NULL;
	char cert_full_path[512];
	char trusted_full_path[512];
	int ret;
	int result;

	get_full_path(tc->cert_path, cert_full_path, sizeof(cert_full_path));
	get_full_path(tc->trusted_path, trusted_full_path, sizeof(trusted_full_path));

	printf("\n=== Test: %s ===\n", tc->name);
	printf("Certificate: %s\n", cert_full_path);
	printf("Trusted CA: %s\n", trusted_full_path);
	if (tc->common_name)
		printf("Common Name: %s\n", tc->common_name);
	else
		printf("Common Name: (not checked)\n");

	if (load_cert_from_file(cert_full_path, &cert) < 0) {
		printf("FAILED: Could not load certificate\n");
		return -1;
	}

	if (load_cert_from_file(trusted_full_path, &trusted) < 0) {
		printf("FAILED: Could not load trusted CA\n");
		lws_x509_destroy(&cert);
		return -1;
	}

	ret = lws_x509_verify(cert, trusted, tc->common_name);

	if (ret == tc->expected_result) {
		printf("PASSED\n");
		result = 0;
	} else {
		printf("FAILED: Expected return %d, got %d\n",
		       tc->expected_result, ret);
		result = -1;
	}

	lws_x509_destroy(&cert);
	lws_x509_destroy(&trusted);

	return result;
}

int main(int argc, char **argv)
{
	int total = 0, passed = 0;
	struct test_case tests[] = {
		{
			.name = "Valid certificate signed by trusted CA (with CN check)",
			.cert_path = "server-cert.pem",
			.trusted_path = "ca-cert.pem",
			.common_name = "test.example.com",
			.expected_result = 0
		},
		{
			.name = "Valid certificate signed by trusted CA (without CN check)",
			.cert_path = "server-cert.pem",
			.trusted_path = "ca-cert.pem",
			.common_name = NULL,
			.expected_result = 0
		},
		{
			.name = "Certificate signed by wrong CA",
			.cert_path = "server-cert.pem",
			.trusted_path = "other-ca-cert.pem",
			.common_name = NULL,
			.expected_result = -1
		},
		{
			.name = "Common name mismatch",
			.cert_path = "server-cert.pem",
			.trusted_path = "ca-cert.pem",
			.common_name = "wrong.example.com",
			.expected_result = -1
		},
		{
			.name = "Valid intermediate chain (CA -> Intermediate -> Server)",
			.cert_path = "leaf-cert.pem",
			.trusted_path = "ca-cert.pem",
			.common_name = NULL,
			.expected_result = -1  /* Should fail as we don't provide intermediate */
		},
	};
	size_t i;
	char check_path[512];

	/* Parse command line arguments */
	if (argc >= 2) {
		strncpy(cert_dir, argv[1], sizeof(cert_dir) - 1);
		cert_dir[sizeof(cert_dir) - 1] = '\0';
	}

	printf("========================================================\n");
	printf("      X.509 Certificate Verification Test Suite      \n");
	printf("========================================================\n");
	printf("Certificate directory: %s\n", cert_dir);
	printf("========================================================\n");

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

		get_full_path(tests[i].trusted_path, check_path, sizeof(check_path));
		f = fopen(check_path, "rb");
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
