/* -*- c-basic-offset: 8 -*-
   rdesktop: A Remote Desktop Protocol client.
   Protocol services - TCP layer
   Copyright (C) Matthew Chapman <matthewc.unsw.edu.au> 1999-2008
   Copyright 2005-2011 Peter Astrand <astrand@cendio.se> for Cendio AB
   Copyright 2012-2017 Henrik Andersson <hean01@cendio.se> for Cendio AB
   Copyright 2018 Alexander Zakharov <uglym8@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WIN32
#include <unistd.h>		/* select read write close */
#include <sys/socket.h>		/* socket connect setsockopt */
#include <sys/time.h>		/* timeval */
#include <netdb.h>		/* gethostbyname */
#include <netinet/in.h>		/* sockaddr_in */
#include <netinet/tcp.h>	/* TCP_NODELAY */
#include <arpa/inet.h>		/* inet_addr */
#include <errno.h>		/* errno */
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "rdesktop.h"
#include "ssl.h"

#ifdef _WIN32
#define socklen_t int
#define TCP_CLOSE(_sck) closesocket(_sck)
#define TCP_STRERROR "tcp error"
#define TCP_BLOCKS (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define TCP_CLOSE(_sck) close(_sck)
#define TCP_STRERROR strerror(errno)
#define TCP_BLOCKS (errno == EWOULDBLOCK)
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

#ifdef WITH_SCARD
#define STREAM_COUNT 8
#else
#define STREAM_COUNT 1
#endif

#ifdef IPv6
static struct addrinfo *g_server_address = NULL;
#else
struct sockaddr_in *g_server_address = NULL;
#endif

static char *g_last_server_name = NULL;
static RD_BOOL g_ssl_initialized = False;
static SSL *g_ssl = NULL;
static SSL_CTX *g_ssl_ctx = NULL;
static int g_sock;
static RD_BOOL g_run_ui = False;
static struct stream g_in;
static struct stream g_out[STREAM_COUNT];
int g_tcp_port_rdp = TCP_PORT_RDP;

extern RD_BOOL g_exit_mainloop;
extern RD_BOOL g_network_error;
extern RD_BOOL g_reconnect_loop;

/* wait till socket is ready to write or timeout */
static RD_BOOL
tcp_can_send(int sck, int millis)
{
	fd_set wfds;
	struct timeval time;
	int sel_count;

	time.tv_sec = millis / 1000;
	time.tv_usec = (millis * 1000) % 1000000;
	FD_ZERO(&wfds);
	FD_SET(sck, &wfds);
	sel_count = select(sck + 1, 0, &wfds, 0, &time);
	if (sel_count > 0)
	{
		return True;
	}
	return False;
}

/* Initialise TCP transport data packet */
STREAM
tcp_init(uint32 maxlen)
{
	static int cur_stream_id = 0;
	STREAM result = NULL;

#ifdef WITH_SCARD
	scard_lock(SCARD_LOCK_TCP);
#endif
	result = &g_out[cur_stream_id];
	s_realloc(result, maxlen);
	s_reset(result);
	cur_stream_id = (cur_stream_id + 1) % STREAM_COUNT;
#ifdef WITH_SCARD
	scard_unlock(SCARD_LOCK_TCP);
#endif
	return result;
}

/* Send TCP transport data packet */
void
tcp_send(STREAM s)
{
	int ssl_err;
	int length = s->end - s->data;
	int sent, total = 0;

	if (g_network_error == True)
		return;

#ifdef WITH_SCARD
	scard_lock(SCARD_LOCK_TCP);
#endif
	while (total < length)
	{
		if (g_ssl)
		{
			sent = SSL_write(g_ssl, s->data + total, length - total);
			if (sent <= 0)
			{
				ssl_err = SSL_get_error(g_ssl, sent);
				if (sent < 0 && (ssl_err == SSL_ERROR_WANT_READ ||
						 ssl_err == SSL_ERROR_WANT_WRITE))
				{
					tcp_can_send(g_sock, 100);
					sent = 0;
				}
				else
				{
#ifdef WITH_SCARD
					scard_unlock(SCARD_LOCK_TCP);
#endif
					logger(Core, Error,
					       "tcp_send(), SSL_write() failed with %d: %s",
					       ssl_err, TCP_STRERROR);
					g_network_error = True;
					return;
				}
			}
		}
		else
		{
			sent = send(g_sock, s->data + total, length - total, 0);
			if (sent <= 0)
			{
				if (sent == -1 && TCP_BLOCKS)
				{
					tcp_can_send(g_sock, 100);
					sent = 0;
				}
				else
				{
#ifdef WITH_SCARD
					scard_unlock(SCARD_LOCK_TCP);
#endif
					logger(Core, Error, "tcp_send(), send() failed: %s",
					       TCP_STRERROR);
					g_network_error = True;
					return;
				}
			}
		}
		total += sent;
	}
#ifdef WITH_SCARD
	scard_unlock(SCARD_LOCK_TCP);
#endif
}

/* Receive a message on the TCP layer */
STREAM
tcp_recv(STREAM s, uint32 length)
{
	uint32 new_length, end_offset, p_offset;
	int rcvd = 0, ssl_err;

	if (g_network_error == True)
		return NULL;

	if (s == NULL)
	{
		/* read into "new" stream */
		if (length > g_in.size)
		{
			g_in.data = (uint8 *) xrealloc(g_in.data, length);
			g_in.size = length;
		}
		g_in.end = g_in.p = g_in.data;
		s = &g_in;
	}
	else
	{
		/* append to existing stream */
		new_length = (s->end - s->data) + length;
		if (new_length > s->size)
		{
			p_offset = s->p - s->data;
			end_offset = s->end - s->data;
			s->data = (uint8 *) xrealloc(s->data, new_length);
			s->size = new_length;
			s->p = s->data + p_offset;
			s->end = s->data + end_offset;
		}
	}

	while (length > 0)
	{
		if ((!g_ssl || SSL_pending(g_ssl) <= 0) && g_run_ui)
		{
			ui_select(g_sock);

			/* break out of recv, if request of exiting
			   main loop has been done */
			if (g_exit_mainloop == True)
				return NULL;
		}

		if (g_ssl)
		{
			rcvd = SSL_read(g_ssl, s->end, length);
			ssl_err = SSL_get_error(g_ssl, rcvd);

			if (ssl_err == SSL_ERROR_SSL)
			{
				if (SSL_get_shutdown(g_ssl) & SSL_RECEIVED_SHUTDOWN)
				{
					logger(Core, Error,
					       "tcp_recv(), remote peer initiated ssl shutdown");
					return NULL;
				}

				rdssl_log_ssl_errors("tcp_recv()");
				g_network_error = True;
				return NULL;
			}

			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
			{
				rcvd = 0;
			}
			else if (ssl_err != SSL_ERROR_NONE)
			{
				logger(Core, Error, "tcp_recv(), SSL_read() failed with %d: %s",
				       ssl_err, TCP_STRERROR);
				g_network_error = True;
				return NULL;
			}

		}
		else
		{
			rcvd = recv(g_sock, s->end, length, 0);
			if (rcvd < 0)
			{
				if (rcvd == -1 && TCP_BLOCKS)
				{
					rcvd = 0;
				}
				else
				{
					logger(Core, Error, "tcp_recv(), recv() failed: %s",
					       TCP_STRERROR);
					g_network_error = True;
					return NULL;
				}
			}
			else if (rcvd == 0)
			{
				logger(Core, Error, "rcp_recv(), connection closed by peer");
				return NULL;
			}
		}

		s->end += rcvd;
		length -= rcvd;
	}

	return s;
}

/* Establish a SSL/TLS 1.0 connection */
RD_BOOL
tcp_tls_connect(void)
{
	int err;
	long options;

	if (!g_ssl_initialized)
	{
		SSL_load_error_strings();
		SSL_library_init();
		g_ssl_initialized = True;
	}

	/* create process context */
	if (g_ssl_ctx == NULL)
	{
		g_ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		if (g_ssl_ctx == NULL)
		{
			logger(Core, Error,
			       "tcp_tls_connect(), SSL_CTX_new() failed to create TLS v1.0 context\n");
			goto fail;
		}

		options = 0;
#ifdef SSL_OP_NO_COMPRESSION
		options |= SSL_OP_NO_COMPRESSION;
#endif // __SSL_OP_NO_COMPRESSION
		options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
		SSL_CTX_set_options(g_ssl_ctx, options);
	}

	/* free old connection */
	if (g_ssl)
		SSL_free(g_ssl);

	/* create new ssl connection */
	g_ssl = SSL_new(g_ssl_ctx);
	if (g_ssl == NULL)
	{
		logger(Core, Error, "tcp_tls_connect(), SSL_new() failed");
		goto fail;
	}

	if (SSL_set_fd(g_ssl, g_sock) < 1)
	{
		logger(Core, Error, "tcp_tls_connect(), SSL_set_fd() failed");
		goto fail;
	}

	do
	{
		err = SSL_connect(g_ssl);
	}
	while (SSL_get_error(g_ssl, err) == SSL_ERROR_WANT_READ);

	if (err < 0)
	{
		rdssl_log_ssl_errors("tcp_tls_connect()");
		goto fail;
	}

	return True;

      fail:
	if (g_ssl)
		SSL_free(g_ssl);
	if (g_ssl_ctx)
		SSL_CTX_free(g_ssl_ctx);

	g_ssl = NULL;
	g_ssl_ctx = NULL;
	return False;
}

/* Get public key from server of TLS 1.0 connection */
RD_BOOL
tcp_tls_get_server_pubkey(STREAM s)
{
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;

	s->data = s->p = NULL;
	s->size = 0;

	if (g_ssl == NULL)
		goto out;

	cert = SSL_get_peer_certificate(g_ssl);
	if (cert == NULL)
	{
		logger(Core, Error,
		       "tcp_tls_get_server_pubkey(), SSL_get_peer_certificate() failed");
		goto out;
	}

	pkey = X509_get_pubkey(cert);
	if (pkey == NULL)
	{
		logger(Core, Error, "tcp_tls_get_server_pubkey(), X509_get_pubkey() failed");
		goto out;
	}

	s->size = i2d_PublicKey(pkey, NULL);
	if (s->size < 1)
	{
		logger(Core, Error, "tcp_tls_get_server_pubkey(), i2d_PublicKey() failed");
		goto out;
	}

	s->data = s->p = xmalloc(s->size);
	i2d_PublicKey(pkey, &s->p);
	s->p = s->data;
	s->end = s->p + s->size;

      out:
	if (cert)
		X509_free(cert);
	if (pkey)
		EVP_PKEY_free(pkey);
	return (s->size != 0);
}

/* Helper function to determine if rdesktop should resolve hostnames again or not */
static RD_BOOL
tcp_connect_resolve_hostname(const char *server)
{
	return (g_server_address == NULL ||
		g_last_server_name == NULL ||
		strcmp(g_last_server_name, server) != 0);
}

/* Establish a connection on the TCP layer

   This function tries to avoid resolving any server address twice. The
   official Windows 2008 documentation states that the windows farm name
   should be a round-robin DNS entry containing all the terminal servers
   in the farm. When connected to the farm address, if we look up the
   address again when reconnecting (for any reason) we risk reconnecting
   to a different server in the farm.
*/

RD_BOOL
tcp_connect(char *server)
{
	socklen_t option_len;
	uint32 option_value;
	int i;
	char buf[NI_MAXHOST];

#ifdef IPv6

	int n;
	struct addrinfo hints, *res, *addr;
	struct sockaddr *oldaddr;
	char tcp_port_rdp_s[10];

	if (tcp_connect_resolve_hostname(server))
	{
		snprintf(tcp_port_rdp_s, 10, "%d", g_tcp_port_rdp);

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if ((n = getaddrinfo(server, tcp_port_rdp_s, &hints, &res)))
		{
			logger(Core, Error, "tcp_connect(), getaddrinfo() failed: %s", gai_strerror(n));
			return False;
		}
	}
	else
	{
		res = g_server_address;
	}

	g_sock = -1;

	for (addr = res; addr != NULL; addr = addr->ai_next)
	{
		g_sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (g_sock < 0)
		{
			logger(Core, Debug, "tcp_connect(), socket() failed: %s", TCP_STRERROR);
			continue;
		}

		n = getnameinfo(addr->ai_addr, addr->ai_addrlen, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
		if (n != 0)
		{
			logger(Core, Error, "tcp_connect(), getnameinfo() failed: %s", gai_strerror(n));
			return False;
		}

		logger(Core, Debug, "tcp_connect(), trying %s (%s)", server, buf);

		if (connect(g_sock, addr->ai_addr, addr->ai_addrlen) == 0)
			break;

		TCP_CLOSE(g_sock);
		g_sock = -1;
	}

	if (g_sock == -1)
	{
		logger(Core, Error, "tcp_connect(), unable to connect to %s", server);
		return False;
	}

	/* Save server address for later use, if we haven't already. */

	if (g_server_address == NULL)
	{
		g_server_address = xmalloc(sizeof(struct addrinfo));
		g_server_address->ai_addr = xmalloc(sizeof(struct sockaddr_storage));
	}

	if (g_server_address != addr)
	{
		/* don't overwrite ptr to allocated sockaddr */
		oldaddr = g_server_address->ai_addr;
		memcpy(g_server_address, addr, sizeof(struct addrinfo));
		g_server_address->ai_addr = oldaddr;

		memcpy(g_server_address->ai_addr, addr->ai_addr, addr->ai_addrlen);

		g_server_address->ai_canonname = NULL;
		g_server_address->ai_next = NULL;

		freeaddrinfo(res);
	}

#else /* no IPv6 support */
	struct hostent *nslookup = NULL;

	if (tcp_connect_resolve_hostname(server))
	{
		if (g_server_address != NULL)
			xfree(g_server_address);
		g_server_address = xmalloc(sizeof(struct sockaddr_in));
		g_server_address->sin_family = AF_INET;
		g_server_address->sin_port = htons((uint16) g_tcp_port_rdp);

		if ((nslookup = gethostbyname(server)) != NULL)
		{
			memcpy(&g_server_address->sin_addr, nslookup->h_addr,
			       sizeof(g_server_address->sin_addr));
		}
		else if ((g_server_address->sin_addr.s_addr = inet_addr(server)) == INADDR_NONE)
		{
			logger(Core, Error, "tcp_connect(), unable to resolve host '%s'", server);
			return False;
		}
	}

	if ((g_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		logger(Core, Error, "tcp_connect(), socket() failed: %s", TCP_STRERROR);
		return False;
	}

	logger(Core, Debug, "tcp_connect(), trying %s (%s)",
	       server, inet_ntop(g_server_address->sin_family,
				 &g_server_address->sin_addr,
				 buf, sizeof(buf)));

	if (connect(g_sock, (struct sockaddr *) g_server_address, sizeof(struct sockaddr)) < 0)
	{
		if (!g_reconnect_loop)
			logger(Core, Error, "tcp_connect(), connect() failed: %s", TCP_STRERROR);

		TCP_CLOSE(g_sock);
		g_sock = -1;
		return False;
	}

#endif /* IPv6 */

	option_value = 1;
	option_len = sizeof(option_value);
	setsockopt(g_sock, IPPROTO_TCP, TCP_NODELAY, (void *) &option_value, option_len);
	/* receive buffer must be a least 16 K */
	if (getsockopt(g_sock, SOL_SOCKET, SO_RCVBUF, (void *) &option_value, &option_len) == 0)
	{
		if (option_value < (1024 * 16))
		{
			option_value = 1024 * 16;
			option_len = sizeof(option_value);
			setsockopt(g_sock, SOL_SOCKET, SO_RCVBUF, (void *) &option_value,
				   option_len);
		}
	}

	g_in.size = 4096;
	g_in.data = (uint8 *) xmalloc(g_in.size);

	for (i = 0; i < STREAM_COUNT; i++)
	{
		g_out[i].size = 4096;
		g_out[i].data = (uint8 *) xmalloc(g_out[i].size);
	}

	/* After successful connect: update the last server name */
	if (g_last_server_name)
		xfree(g_last_server_name);
	g_last_server_name = strdup(server);
	return True;
}

/* Disconnect on the TCP layer */
void
tcp_disconnect(void)
{
	if (g_ssl)
	{
		if (!g_network_error)
			(void) SSL_shutdown(g_ssl);
		SSL_free(g_ssl);
		g_ssl = NULL;
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
	}

	TCP_CLOSE(g_sock);
	g_sock = -1;
}

char *
tcp_get_address()
{
	static char ipaddr[32];
	struct sockaddr_in sockaddr;
	socklen_t len = sizeof(sockaddr);
	if (getsockname(g_sock, (struct sockaddr *) &sockaddr, &len) == 0)
	{
		uint8 *ip = (uint8 *) & sockaddr.sin_addr;
		sprintf(ipaddr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	}
	else
		strcpy(ipaddr, "127.0.0.1");
	return ipaddr;
}

char *
tcp_get_peer_address(void)
{
	static char peer_ipa[32];
	struct sockaddr_in sockaddr;

	socklen_t len = sizeof(sockaddr);

	if (getpeername(g_sock, (struct sockaddr *) &sockaddr, &len) == 0) {
		uint8 *ip = (uint8 *) & sockaddr.sin_addr;
		sprintf(peer_ipa, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	} else {
		strcpy(peer_ipa, "0.0.0.0");
	}

	return peer_ipa;
}

RD_BOOL
tcp_is_connected()
{
	struct sockaddr_in sockaddr;
	socklen_t len = sizeof(sockaddr);
	if (getpeername(g_sock, (struct sockaddr *) &sockaddr, &len))
		return True;
	return False;
}

/* reset the state of the tcp layer */
/* Support for Session Directory */
void
tcp_reset_state(void)
{
	int i;

	/* Clear the incoming stream */
	s_reset(&g_in);

	/* Clear the outgoing stream(s) */
	for (i = 0; i < STREAM_COUNT; i++)
	{
		s_reset(&g_out[i]);
	}
}

void
tcp_run_ui(RD_BOOL run)
{
	g_run_ui = run;
}
