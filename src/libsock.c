/*-
 * Copyright (c) 2022 BlackhawkNest, Inc
 *
 * Author: Shawn Webb <swebb@blackhawknest.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/event.h>

#include <sys/param.h>

#include "libsock.h"

libsock_ctx_t *
libsock_ctx_new(libsock_socket_type_t socktype, int sockfd, uint64_t flags)
{
	libsock_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return (NULL);
	}

	if (pthread_mutex_init(&(ctx->lc_mtx), NULL)) {
		free(ctx);
		return (NULL);
	}

#ifdef _LIBSOCK_KQUEUE_ENABLE
	ctx->lc_kqueue = kqueue();
	if (ctx->lc_kqueue == -1) {
		pthread_mutex_destroy(&(ctx->lc_mtx));
		free(ctx);
		return (NULL);
	}
#endif

	ctx->lc_tls_config = tls_config_new();
	if (ctx->lc_tls_config == NULL) {
		pthread_mutex_destroy(&(ctx->lc_mtx));
		free(ctx);
		return (NULL);
	}

	if (tls_config_set_protocols(ctx->lc_tls_config,
	    TLS_PROTOCOL_TLSv1_3)) {
		pthread_mutex_destroy(&(ctx->lc_mtx));
		tls_config_free(ctx->lc_tls_config);
		free(ctx);
		return (NULL);
	}

	if (tls_config_set_dheparams(ctx->lc_tls_config, "auto")) {
		pthread_mutex_destroy(&(ctx->lc_mtx));
		tls_config_free(ctx->lc_tls_config);
		free(ctx);
		return (NULL);
	}

	switch (socktype) {
	case LIBSOCK_SOCKET_TYPE_CLIENT:
		ctx->lc_tls = tls_client();
		break;
	case LIBSOCK_SOCKET_TYPE_SERVER:
		ctx->lc_tls = tls_server();
		tls_config_prefer_ciphers_server(ctx->lc_tls_config);
		break;
	default:
		break;
	}

	if (ctx->lc_tls == NULL) {
		pthread_mutex_destroy(&(ctx->lc_mtx));
		tls_config_free(ctx->lc_tls_config);
		free(ctx);
		return (NULL);
	}

	ctx->lc_flags = flags;
	ctx->lc_sockfd = sockfd;
	ctx->lc_type = socktype;

	LIST_INIT(&(ctx->lc_connections));

	return (ctx);
}

bool
libsock_ctx_load_key_file(libsock_ctx_t *ctx, const char *path, char *password)
{

	if (ctx == NULL || path == NULL) {
		return (false);
	}

	if (ctx->lc_keymem != NULL) {
		tls_unload_file(ctx->lc_keymem, ctx->lc_keysz);
	}

	ctx->lc_keysz = 0;
	ctx->lc_keymem = tls_load_file(path, &(ctx->lc_keysz), password);
	if (ctx->lc_keymem == NULL || ctx->lc_keysz == 0) {
		return (false);
	}

	if (tls_config_set_key_mem(ctx->lc_tls_config, ctx->lc_keymem,
	    ctx->lc_keysz)) {
		tls_unload_file(ctx->lc_keymem, ctx->lc_keysz);
		return (false);
	}

	return (true);
}

bool
libsock_ctx_load_cert_file(libsock_ctx_t *ctx, const char *path)
{

	if (ctx == NULL || path == NULL) {
		return (false);
	}

	return (tls_config_set_cert_file(ctx->lc_tls_config, path) == 0);
}

bool
libsock_ctx_config_finalize(libsock_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (false);
	}

	return (tls_configure(ctx->lc_tls, ctx->lc_tls_config) == 0);
}

bool
libsock_ctx_lock(libsock_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (false);
	}

	return (pthread_mutex_lock(&(ctx->lc_mtx)) == 0);
}

bool
libsock_ctx_unlock(libsock_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (false);
	}

	return (pthread_mutex_unlock(&(ctx->lc_mtx)) == 0);
}

libsock_sub_connection_t *
libsock_sub_connection_new(libsock_ctx_t *ctx, uint64_t flags)
{
	libsock_sub_connection_t *conn;

	if (ctx == NULL) {
		return (NULL);
	}

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		return (NULL);
	}

	conn->lsc_ctx = ctx;
	conn->lsc_sockfd = -1;
	conn->lsc_flags = flags;

	return (conn);
}

bool
libsock_ctx_add_conn(libsock_ctx_t *ctx, libsock_sub_connection_t *conn)
{

	if (ctx == NULL || conn == NULL) {
		return (false);
	}

	if (libsock_ctx_lock(ctx) == false) {
		free(conn);
		return (false);
	}

	LIST_INSERT_HEAD(&(ctx->lc_connections), conn, lsc_entry);

	libsock_ctx_unlock(ctx);

	return (true);
}

bool
libsock_ctx_remove_conn(libsock_ctx_t *ctx, int sockfd, bool closefd)
{
	libsock_sub_connection_t *conn, *tconn;
	bool res;

	if (ctx == NULL || sockfd < 0) {
		return (false);
	}

	if (!libsock_ctx_lock(ctx)) {
		return (false);
	}

	res = true;
	LIST_FOREACH_SAFE(conn, &(ctx->lc_connections), lsc_entry, tconn) {
		if (conn->lsc_sockfd == sockfd) {
			LIST_REMOVE(conn, lsc_entry);
			libsock_sub_connection_free(&conn, closefd);
			goto end;
		}
	}

end:
	if (!libsock_ctx_unlock(ctx)) {
		return (false);
	}
	return (res);
}

void
libsock_sub_connection_free(libsock_sub_connection_t **connp, bool closefd)
{
	libsock_sub_connection_t *conn;

	if (connp == NULL || *connp == NULL) {
		return;
	}

	conn = *connp;
	if (conn->lsc_tls != NULL) {
		tls_close(conn->lsc_tls);
	}
	if (closefd && conn->lsc_sockfd >= 0) {
		close(conn->lsc_sockfd);
	}

	/*
	 * In some cases, the sockaddr_storage member in the sub
	 * connection might be considered sensitive data. As such, use
	 * explicit_bzero to zero the entire sub connection object to
	 * deter potential information disclosure attacks.
	 */
	explicit_bzero(conn, sizeof(*conn));
	free(conn);
	*connp = NULL;
}

libsock_fdset_t *
libsock_fdset_get(libsock_ctx_t *ctx)
{
	libsock_sub_connection_t *conn, *tconn;
	libsock_fdset_t *set;

	if (ctx == NULL) {
		return (NULL);
	}

	set = calloc(1, sizeof(*set));
	if (set == NULL) {
		return (NULL);
	}

	if (libsock_ctx_lock(ctx) == false) {
		free(set);
		return (NULL);
	}

	FD_ZERO(&(set->lf_set));
	LIST_FOREACH_SAFE(conn, &(ctx->lc_connections), lsc_entry, tconn) {
		FD_SET(conn->lsc_sockfd, &(set->lf_set));
		set->lf_nsock++;
	}

	if (libsock_ctx_unlock(ctx) == false) {
		free(set);
		return (NULL);
	}

	return (set);
}

void
libsock_fdset_free(libsock_fdset_t **fdsetp)
{
	libsock_fdset_t *fdset;

	if (fdsetp == NULL || fdsetp == NULL) {
		return;
	}

	fdset = *fdsetp;
	free(fdset);
	*fdsetp = NULL;
}

libsock_sub_connection_t *
libsock_sub_connection_find(libsock_ctx_t *ctx, int sockfd)
{
	libsock_sub_connection_t *conn, *tconn;

	if (ctx == NULL || sockfd < 0) {
		return (NULL);
	}

	if (!libsock_ctx_lock(ctx)) {
		return (NULL);
	}

	conn = NULL;
	LIST_FOREACH_SAFE(conn, &(ctx->lc_connections), lsc_entry, tconn) {
		if (conn->lsc_sockfd == sockfd) {
			break;
		}
	}

	libsock_ctx_unlock(ctx);
	return (conn);
}

ssize_t
libsock_sub_connection_recv(libsock_sub_connection_t *conn, void *buf,
    size_t bufsz, bool complete)
{
	ssize_t res, ret, sz;

	if (conn == NULL || buf == NULL) {
		return (-1);
	}

	if (bufsz == 0) {
		return (0);
	}

	ret = 0;
	sz = bufsz;
	while (sz > 0) {
		res = tls_read(conn->lsc_tls, buf, sz);
		if (res == -1) {
			return (ret);
		}

		if (!complete) {
			return (res);
		}

		sz -= res;
		ret += res;
		buf += res;
	}

	return (ret);
}

ssize_t
libsock_sub_connection_send(libsock_sub_connection_t *conn, const void *buf,
    size_t bufsz)
{
	ssize_t res, ret, sz;

	ret = 0;
	sz = bufsz;

	while (sz > 0) {
		res = tls_write(conn->lsc_tls, buf, sz);
		if (res == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
			continue;
		}
		if (ret == -1) {
			return (-1);
		}

		sz -= res;
		buf += res;
		ret += res;
	}

	return (ret);
}

bool
libsock_accept(libsock_ctx_t *ctx)
{
	libsock_sub_connection_t *conn;

	if (ctx == NULL) {
		return (false);
	}

	if (ctx->lc_type != LIBSOCK_SOCKET_TYPE_SERVER) {
		return (false);
	}

	conn = libsock_sub_connection_new(ctx, 0);
	if (conn == NULL) {
		return (false);
	}

	conn->lsc_sockfd = accept(ctx->lc_sockfd, &(conn->lsc_addr),
	    &(conn->lsc_addrlen));
	if (conn->lsc_sockfd < 0) {
		return (false);
	}

	if (tls_accept_socket(ctx->lc_tls, &(conn->lsc_tls),
	    conn->lsc_sockfd)) {
		return (false);
	}

	if (conn->lsc_tls == NULL) {
		/* This shouldn't happen, but let's be defensive. */
		return (false);
	}

	return (libsock_ctx_add_conn(ctx, conn));
}

bool
libsock_bind_host(libsock_ctx_t *ctx, const char *host, const char *port,
    int sockflags)
{
	struct addrinfo hints, *infop, *info;

	if (ctx == NULL || host == NULL || port == NULL) {
		return (false);
	}

	if (ctx->lc_sockfd >= 0) {
		/*
		 * We'll create a new sockfd as part of binding to a
		 * specific IP.
		 */
		return (false);
	}

	infop = NULL;
	memset(&hints, 0, sizeof(hints));
	if (getaddrinfo(host, port, NULL, &infop)) {
		return (false);
	}

	if (infop == NULL) {
		/* This shouldn't happen, but let's be defensive. */
		return (false);
	}

	sockflags |= SOCK_CLOEXEC;

	for (info = infop; info != NULL; info = info->ai_next) {
		ctx->lc_sockfd = socket(info->ai_family,
		    info->ai_socktype | sockflags,
		    info->ai_protocol);
		if (ctx->lc_sockfd < 0) {
			continue;
		}

		if (bind(ctx->lc_sockfd, info->ai_addr, info->ai_addrlen)) {
			close(ctx->lc_sockfd);
			ctx->lc_sockfd = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(infop);
	return (ctx->lc_sockfd >= 0);
}

bool
libsock_listen(libsock_ctx_t *ctx, int backlog)
{

	if (ctx == NULL || ctx->lc_sockfd < 0) {
		return (false);
	}

	return (listen(ctx->lc_sockfd, backlog) == 0);
}

#if 0
bool
libsock_bind_iface(libsock_ctx_t *ctx, const char *iface, const char *port,
    bool v4, bool v6)
{

	if (ctx == NULL || iface == NULL) {
		return (false);
	}

	return (_libsock_ad_bind_iface(ctx, iface, v4, v6));
}
#endif
