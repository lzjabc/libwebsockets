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

#include <stddef.h>
#include <stdint.h>

#include "../../core/private-lib-core.h"
#include "../private-lib-tls.h"

static void
openhitls_not_implemented(const char *func)
{
	lwsl_err("%s: OpenHITLS backend not implemented\n", func);
}

int
lws_context_init_ssl_library(struct lws_context *context,
			     const struct lws_context_creation_info *info)
{
	(void)context;
	(void)info;

	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{
	(void)context;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	(void)info;
	(void)vhost;
	(void)wsi;

	openhitls_not_implemented(__func__);

	return -1;
}

int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				    const struct lws_context_creation_info *info,
				    const char *cipher_list,
				    const char *ca_filepath,
				    const void *ca_mem,
				    unsigned int ca_mem_len,
				    const char *cert_filepath,
				    const void *cert_mem,
				    unsigned int cert_mem_len,
				    const char *private_key_filepath,
				    const void *key_mem,
				    unsigned int key_mem_len)
{
	(void)vh;
	(void)info;
	(void)cipher_list;
	(void)ca_filepath;
	(void)ca_mem;
	(void)ca_mem_len;
	(void)cert_filepath;
	(void)cert_mem;
	(void)cert_mem_len;
	(void)private_key_filepath;
	(void)key_mem;
	(void)key_mem_len;

	openhitls_not_implemented(__func__);

	return -1;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	(void)wsi;
	(void)accept_fd;

	openhitls_not_implemented(__func__);

	return 1;
}

int
lws_ssl_client_bio_create(struct lws *wsi)
{
	(void)wsi;

	openhitls_not_implemented(__func__);

	return -1;
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	(void)vhost;
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	(void)wsi;

	return NULL;
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
	(void)context;
}

void
lws_tls_session_vh_destroy(struct lws_vhost *vh)
{
	(void)vh;
}

int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh, const uint8_t *der,
				    size_t len)
{
	(void)vh;
	(void)der;
	(void)len;

	openhitls_not_implemented(__func__);

	return -1;
}

int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	(void)vhost;
	(void)wsi;
	(void)cert;
	(void)private_key;
	(void)mem_cert;
	(void)len_mem_cert;
	(void)mem_privkey;
	(void)mem_privkey_len;

	openhitls_not_implemented(__func__);

	return -1;
}

int
lws_tls_session_is_reused(struct lws *wsi)
{
	(void)wsi;

	return 0;
}

int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
			  int (*cb)(struct lws_context *,
				    struct lws_tls_session_dump *),
			  void *user)
{
	(void)vh;
	(void)host;
	(void)port;
	(void)cb;
	(void)user;

	openhitls_not_implemented(__func__);

	return -1;
}

int
lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port,
			  int (*cb)(struct lws_context *,
				    struct lws_tls_session_dump *),
			  void *user)
{
	(void)vh;
	(void)host;
	(void)port;
	(void)cb;
	(void)user;

	openhitls_not_implemented(__func__);

	return -1;
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	(void)vh;

	openhitls_not_implemented(__func__);

	return -1;
}
