/*
 * X.509 Certificate Module Consistency Test
 * Tests OpenHITLS implementation against OpenSSL baseline
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>

static void
print_hex(const char *label, const uint8_t *data, int len)
{
	printf("%s (%d bytes): ", label, len);
	for (int i = 0; i < len && i < 32; i++)
		printf("%02x", data[i]);
	if (len > 32)
		printf("...");
	printf("\n");
}

static void
test_cert_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type,
	       const char *name)
{
	char big[4096];
	union lws_tls_cert_info_results *buf = (union lws_tls_cert_info_results *)big;
	int ret;

	memset(big, 0, sizeof(big));
	ret = lws_x509_info(x509, type, buf, sizeof(big) - sizeof(*buf) + sizeof(buf->ns.name));

	printf("\n=== %s ===\n", name);
	printf("Return: %d\n", ret);

	if (ret == 0) {
		switch (type) {
		case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		case LWS_TLS_CERT_INFO_VALIDITY_TO:
			printf("Time: %lld\n", (long long)buf->time);
			break;
		case LWS_TLS_CERT_INFO_USAGE:
			printf("Usage: 0x%08x\n", buf->usage);
			break;
		case LWS_TLS_CERT_INFO_COMMON_NAME:
		case LWS_TLS_CERT_INFO_ISSUER_NAME:
			printf("String: '%s' (len=%d)\n", buf->ns.name, buf->ns.len);
			break;
		case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
		case LWS_TLS_CERT_INFO_DER_RAW:
		case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID:
		case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL:
		case LWS_TLS_CERT_INFO_SUBJECT_KEY_ID:
			print_hex("Data", (uint8_t *)buf->ns.name, buf->ns.len);
			break;
		case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER:
			printf("Issuer: '%s' (len=%d)\n", buf->ns.name, buf->ns.len);
			break;
		default:
			break;
		}
	} else if (ret == 1) {
		printf("Not present\n");
	} else {
		printf("Error\n");
	}
}

int main(int argc, char **argv)
{
	struct lws_x509_cert *x509 = NULL;
	FILE *fp;
	char pem[8192];
	size_t len;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <cert.pem>\n", argv[0]);
		return 1;
	}

	printf("Certificate: %s\n\n", argv[1]);

	fp = fopen(argv[1], "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open %s\n", argv[1]);
		return 1;
	}

	len = fread(pem, 1, sizeof(pem) - 1, fp);
	fclose(fp);
	pem[len] = '\0';

	ret = lws_x509_create(&x509);
	if (ret) {
		fprintf(stderr, "ERROR: lws_x509_create failed with code %d\n", ret);
		return 1;
	}
	fprintf(stderr, "DEBUG: lws_x509_create succeeded\n");

	ret = lws_x509_parse_from_pem(x509, pem, len + 1);
	if (ret) {
		fprintf(stderr, "ERROR: lws_x509_parse_from_pem failed with code %d\n", ret);
		lws_x509_destroy(&x509);
		return 1;
	}
	fprintf(stderr, "DEBUG: lws_x509_parse_from_pem succeeded\n");

	printf("Certificate parsed successfully\n");

	test_cert_info(x509, LWS_TLS_CERT_INFO_VALIDITY_FROM, "VALIDITY_FROM");
	test_cert_info(x509, LWS_TLS_CERT_INFO_VALIDITY_TO, "VALIDITY_TO");
	test_cert_info(x509, LWS_TLS_CERT_INFO_COMMON_NAME, "COMMON_NAME");
	test_cert_info(x509, LWS_TLS_CERT_INFO_ISSUER_NAME, "ISSUER_NAME");
	test_cert_info(x509, LWS_TLS_CERT_INFO_USAGE, "USAGE");
	test_cert_info(x509, LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY, "OPAQUE_PUBLIC_KEY");
	test_cert_info(x509, LWS_TLS_CERT_INFO_DER_RAW, "DER_RAW");
	test_cert_info(x509, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID, "AUTHORITY_KEY_ID");
	test_cert_info(x509, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER, "AUTHORITY_KEY_ID_ISSUER");
	test_cert_info(x509, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL, "AUTHORITY_KEY_ID_SERIAL");
	test_cert_info(x509, LWS_TLS_CERT_INFO_SUBJECT_KEY_ID, "SUBJECT_KEY_ID");

	lws_x509_destroy(&x509);
	printf("\nTest completed\n");
	return 0;
}
