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

#ifndef _LIBSOCK_H
#define _LIBSOCK_H

#include <stdbool.h>

#include <pthread.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sys/event.h>
#include <sys/queue.h>

#include <tls.h>

#define LIBSOCK_VERSION	0

#define LIBSOCK_FLAG_PERSIST	0x1

#define LIBSOCK_SUB_CONNECTION_FLAG_TERM	0x1

#if 0
#define _LIBSOCK_KQUEUE_ENABLE
#endif

struct _libsock_ctx;

typedef enum _libsock_socket_type {
	LIBSOCK_SOCKET_TYPE_CLIENT = 0,
	LIBSOCK_SOCKET_TYPE_SERVER = 1,
} libsock_socket_type_t;

typedef struct _libsock_fdset {
	fd_set	 lf_set;
	size_t	 lf_nsock;
} libsock_fdset_t;

/*
 * libsock_sub_connection_t is only really useful in the server
 * context where there are N clients connected at any given time.
 */
typedef struct _libsock_sub_connection {
	int					 lsc_sockfd;
	uint64_t				 lsc_flags;
	struct tls				*lsc_tls;
	unsigned int				 lsc_addrlen;
	struct sockaddr				 lsc_addr;
	struct _libsock_ctx			*lsc_ctx;
	LIST_ENTRY(_libsock_sub_connection)	 lsc_entry;
} libsock_sub_connection_t;

typedef struct _libsock_ctx {
	uint64_t				 lc_version;
	uint64_t				 lc_flags;
	libsock_socket_type_t			 lc_type;
	uint64_t				 lc_private_flags;
	int					 lc_sockfd;
	int					 lc_kqueue;
	char					*lc_capath;
	char					*lc_certpath;
	char					*lc_keypath;
	uint8_t					*lc_keymem;
	size_t					 lc_keysz;
	struct tls				*lc_tls;
	struct tls_config			*lc_tls_config;
	struct timespec				 lc_ev_timeout;
	struct kevent				*lc_ev_changelist;
	pthread_mutex_t				 lc_mtx;
	LIST_HEAD(,_libsock_sub_connection)	 lc_connections;
} libsock_ctx_t;

libsock_ctx_t *libsock_ctx_new(libsock_socket_type_t, int, uint64_t);
bool libsock_ctx_lock(libsock_ctx_t *);
bool libsock_ctx_unlock(libsock_ctx_t *);
bool libsock_ctx_add_conn(libsock_ctx_t *, libsock_sub_connection_t *);
bool libsock_ctx_remove_conn(libsock_ctx_t *, int, bool, bool);
bool libsock_ctx_remove_conn_by_obj(libsock_ctx_t *,
    libsock_sub_connection_t *, bool, bool);

uint64_t libsock_ctx_get_flags(libsock_ctx_t *);
uint64_t libsock_ctx_set_flag(libsock_ctx_t *, uint64_t);
uint64_t libsock_ctx_set_flags(libsock_ctx_t *, uint64_t);
bool libsock_ctx_is_flag_set(libsock_ctx_t *, uint64_t);

bool libsock_ctx_load_key_file(libsock_ctx_t *, const char *, char *);
bool libsock_ctx_load_cert_file(libsock_ctx_t *, const char *);
bool libsock_ctx_config_finalize(libsock_ctx_t *);

libsock_fdset_t *libsock_fdset_get(libsock_ctx_t *);
void libsock_fdset_free(libsock_fdset_t **);

libsock_sub_connection_t *libsock_sub_connection_new(libsock_ctx_t *,
    uint64_t);
void libsock_sub_connection_free(libsock_sub_connection_t **, bool);
libsock_sub_connection_t *libsock_sub_connection_find(libsock_ctx_t *, int,
    bool);
ssize_t libsock_sub_connection_recv(libsock_sub_connection_t *, void *,
    size_t, bool);
ssize_t libsock_sub_connection_send(libsock_sub_connection_t *, const void *,
    size_t);

uint64_t libsock_sub_connection_get_flags(libsock_sub_connection_t *);
uint64_t libsock_sub_connection_set_flag(libsock_sub_connection_t *,
    uint64_t);
uint64_t libsock_sub_connection_set_flags(libsock_sub_connection_t *,
    uint64_t);
bool libsock_sub_connection_is_flag_set(libsock_sub_connection_t *, uint64_t);

bool libsock_bind_host(libsock_ctx_t *ctx, const char *, const char *, int);
bool libsock_accept(libsock_ctx_t *);
bool libsock_listen(libsock_ctx_t *, int);

#endif /* !_LIBSOCK_H */
