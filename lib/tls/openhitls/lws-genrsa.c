/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "private-lib-core.h"
#include "../private-lib-tls.h"

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

void
lws_genrsa_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	int n;

	for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++)
		if (el[n].buf) {
			lws_explicit_bzero(el[n].buf, el[n].len);
			lws_free_set_NULL(el[n].buf);
			el[n].len = 0;
		}
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type,
			   const uint8_t *sig, size_t sig_len)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		     enum lws_genhash_types hash_type,
		     uint8_t *sig, size_t sig_len)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}

void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
}

int
lws_genrsa_render_pkey_asn1(struct lws_genrsa_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	lwsl_err("%s: OpenHITLS RSA gencrypto not implemented\n", __func__);
	return -1;
}
