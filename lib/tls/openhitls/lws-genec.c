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
#include <hitls/crypto/crypt_algid.h>

const struct lws_ec_curves lws_ec_curves[4] = {
	{ "P-256", CRYPT_ECC_NISTP256, 32 },
	{ "P-384", CRYPT_ECC_NISTP384, 48 },
	{ "P-521", CRYPT_ECC_NISTP521, 66 },
	{ NULL, 0, 0 }
};

int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx,
		    const struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
		        const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
				  int *ss_len)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 enum lws_genhash_types hash_type, int keybits,
				 const uint8_t *sig, size_t sig_len)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type, int keybits,
			   uint8_t *sig, size_t sig_len)
{
	lwsl_err("%s: OpenHITLS EC gencrypto not implemented\n", __func__);
	return -1;
}

void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
}
