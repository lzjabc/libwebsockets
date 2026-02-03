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

#include "../../core/private-lib-core.h"
#include "../private-lib-tls.h"

static void
openhitls_not_implemented(const char *func)
{
	lwsl_err("%s: OpenHITLS backend not implemented\n", func);
}

int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	openhitls_not_implemented(__func__);

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	if (!wsi->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	openhitls_not_implemented(__func__);

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	return 0;
}

int
lws_ssl_close(struct lws *wsi)
{
	if (wsi->tls.ssl)
		wsi->tls.ssl = NULL;

	__lws_ssl_remove_wsi_from_buffered_list(wsi);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	openhitls_not_implemented(__func__);

	return LWS_SSL_CAPABLE_ERROR;
}

enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	openhitls_not_implemented(__func__);
	if (errbuf)
		lws_snprintf(errbuf, len, "OpenHITLS backend not implemented");

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_get_error(struct lws *wsi, int n)
{
	return n;
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	return LWS_SSL_CAPABLE_ERROR;
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	__lws_tls_shutdown(wsi);

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	if (ebuf)
		lws_snprintf(ebuf, ebuf_len, "OpenHITLS backend not implemented");

	return -1;
}

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
	(void)ssl;
	(void)where;
	(void)ret;
}

static int
tops_fake_POLLIN_for_buffered_openhitls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_openhitls = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_openhitls,
};
