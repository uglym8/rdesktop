/* -*- c-basic-offset: 8 -*-
   rdesktop: A Remote Desktop Protocol client.
   Protocol services - ISO layer
   Copyright (C) Matthew Chapman <matthewc.unsw.edu.au> 1999-2008
   Copyright 2005-2011 Peter Astrand <astrand@cendio.se> for Cendio AB
   Copyright 2012-2018 Henrik Andersson <hean01@cendio.se> for Cendio AB

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

#include "rdesktop.h"

extern RD_BOOL g_encryption;
extern RD_BOOL g_encryption_initial;
extern RDP_VERSION g_rdp_version;
extern RD_BOOL g_use_password_as_pin;

extern char *g_sc_csp_name;
extern char *g_sc_reader_name;
extern char *g_sc_card_name;
extern char *g_sc_container_name;

extern int g_num_monitors;
extern RD_BOOL g_extended_data_supported;

/* Send a self-contained ISO PDU */
static void
iso_send_msg(uint8 code)
{
	STREAM s;

	s = tcp_init(11);

	out_uint8(s, 3);	/* version */
	out_uint8(s, 0);	/* reserved */
	out_uint16_be(s, 11);	/* length */

	out_uint8(s, 6);	/* hdrlen */
	out_uint8(s, code);
	out_uint16(s, 0);	/* dst_ref */
	out_uint16(s, 0);	/* src_ref */
	out_uint8(s, 0);	/* class */

	s_mark_end(s);
	tcp_send(s);
}

static void
iso_send_connection_request(char *username, uint32 neg_proto)
{
	STREAM s;
	int length = 30 + strlen(username);

	if (g_rdp_version >= RDP_V5)
		length += 8;

	s = tcp_init(length);

	out_uint8(s, 3);	/* version */
	out_uint8(s, 0);	/* reserved */
	out_uint16_be(s, length);	/* length */

	out_uint8(s, length - 5);	/* hdrlen */
	out_uint8(s, ISO_PDU_CR);
	out_uint16(s, 0);	/* dst_ref */
	out_uint16(s, 0);	/* src_ref */
	out_uint8(s, 0);	/* class */

	out_uint8p(s, "Cookie: mstshash=", strlen("Cookie: mstshash="));
	out_uint8p(s, username, strlen(username));

	out_uint8(s, 0x0d);	/* cookie termination string: CR+LF */
	out_uint8(s, 0x0a);

	if (g_rdp_version >= RDP_V5)
	{
		/* optional RDP protocol negotiation request for RDPv5 */
		out_uint8(s, RDP_NEG_REQ);
		out_uint8(s, 0);
		out_uint16(s, 8);
		out_uint32(s, neg_proto);
	}

	s_mark_end(s);
	tcp_send(s);
}

/* Receive a message on the ISO layer, return code */
static STREAM
iso_recv_msg(uint8 * code, RD_BOOL *is_fastpath, uint8 *fastpath_hdr)
{
	STREAM s;
	uint16 length;
	uint8 version;

	s = tcp_recv(NULL, 4);
	if (s == NULL)
		return NULL;

	in_uint8(s, version); /* T.123 version or Fastpath output header */

	/* detect if this is a slow or fast path PDU */
	*fastpath_hdr = 0x00;
	*is_fastpath = False;
	if (version == T123_HEADER_VERSION)
	{
		in_uint8s(s, 1);		/* reserved */
		in_uint16_be(s, length);	/* length */
	}
	else
	{
		/* if version is not an expected T.123 version eg. 3, then this
		   stream is a fast path pdu */
		*is_fastpath = True;
		*fastpath_hdr = version;
		in_uint8(s, length); /* length1 */
		if (length & 0x80)
		{
			/* length2 is only present if the most significant bit of length1 is set */
			length &= ~0x80;
			next_be(s, length);
		}
	}

	if (length < 4)
	{
		logger(Protocol, Error, "iso_recv_msg(), bad packet header, length < 4");
		return NULL;
	}

	s = tcp_recv(s, length - 4);
	if (s == NULL)
		return NULL;

	if (*is_fastpath == True)
		return s;

	in_uint8s(s, 1);	/* hdrlen */
	in_uint8(s, *code);
	if (*code == ISO_PDU_DT)
	{
		in_uint8s(s, 1);	/* eot */
		return s;
	}
	in_uint8s(s, 5);	/* dst_ref, src_ref, class */
	return s;
}

/* Initialise ISO transport data packet */
STREAM
iso_init(int length)
{
	STREAM s;

	s = tcp_init(length + 7);
	s_push_layer(s, iso_hdr, 7);

	return s;
}

/* Send an ISO data PDU */
void
iso_send(STREAM s)
{
	uint16 length;

	s_pop_layer(s, iso_hdr);
	length = s->end - s->p;

	out_uint8(s, T123_HEADER_VERSION);	/* version */
	out_uint8(s, 0);	/* reserved */
	out_uint16_be(s, length);

	out_uint8(s, 2);	/* hdrlen */
	out_uint8(s, ISO_PDU_DT);	/* code */
	out_uint8(s, 0x80);	/* eot */

	tcp_send(s);
}

/* Receive ISO transport data packet */
STREAM
iso_recv(RD_BOOL *is_fastpath, uint8 *fastpath_hdr)
{
	STREAM s;
	uint8 code = 0;

	s = iso_recv_msg(&code, is_fastpath, fastpath_hdr);
	if (s == NULL)
		return NULL;

	if (*is_fastpath == True)
		return s;

	if (code != ISO_PDU_DT)
	{
		logger(Protocol, Error, "iso_recv(), expected ISO_PDU_DT, got 0x%x", code);
		return NULL;
	}
	return s;
}

/* Establish a connection up to the ISO layer */
RD_BOOL
iso_connect(char *server, char *username, char *domain, char *password,
	    RD_BOOL reconnect, uint32 * selected_protocol)
{
	UNUSED(reconnect);
	STREAM s;
	uint8 code;
	uint32 neg_proto;
	RD_BOOL is_fastpath;
	uint8 fastpath_hdr;

	RD_BOOL ok_to_reconnect = False;

	neg_proto = PROTOCOL_SSL;

#ifdef WITH_CREDSSP
	if (!g_use_password_as_pin)
		neg_proto |= PROTOCOL_HYBRID;
	else if (g_sc_csp_name || g_sc_reader_name || g_sc_card_name || g_sc_container_name)
		neg_proto |= PROTOCOL_HYBRID;
	else
		logger(Core, Warning,
		       "iso_connect(), missing smartcard information for SSO, disabling CredSSP");
#endif
	if (neg_proto & PROTOCOL_HYBRID)
		logger(Core, Verbose, "Connecting to server using NLA...");
	else
		logger(Core, Verbose, "Connecting to server using SSL...");

      retry:
	*selected_protocol = neg_proto;
	code = 0;

	if (!tcp_connect(server))
		return False;

	iso_send_connection_request(username, neg_proto);

	s = iso_recv_msg(&code, &is_fastpath, &fastpath_hdr);
	if (s == NULL)
		return False;

	if (code != ISO_PDU_CC)
	{
		logger(Protocol, Error, "iso_connect(), expected ISO_PDU_CC, got 0x%x", code);
		tcp_disconnect();
		return False;
	}

	if (g_rdp_version >= RDP_V5 && s_check_rem(s, 8))
	{
		/* handle RDP_NEG_REQ response */
		const char *reason = NULL;

		uint8 type = 0;
		uint8 flags = 0;
		uint32 data = 0;

		in_uint8(s, type);
		in_uint8(s, flags); /* skip flags */
		in_uint8s(s, 2); /* skip length */
		in_uint32(s, data);

		if (type == RDP_NEG_FAILURE)
		{
			switch (data)
			{
				case SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER:
					reason = "SSL with user authentication required by server";
					break;
				case SSL_NOT_ALLOWED_BY_SERVER:
					reason = "SSL not allowed by server";
					ok_to_reconnect = True;
					break;
				case SSL_CERT_NOT_ON_SERVER:
					reason = "no valid authentication certificate on server";
					ok_to_reconnect = True;
					break;
				case INCONSISTENT_FLAGS:
					reason = "inconsistent negotiation flags";
					break;
				case SSL_REQUIRED_BY_SERVER:
					reason = "SSL required by server";
					break;
				case HYBRID_REQUIRED_BY_SERVER:
					reason = "CredSSP required by server";
					break;
				default:
					reason = "unknown reason";
			}

			tcp_disconnect();

			if (ok_to_reconnect)
			{
				if (reason != NULL)
				{
					logger(Protocol, Warning,
					       "Protocol negotiation failed with reason: %s",
					       reason);
				}

				logger(Core, Notice, "Retrying with plain RDP.");

				neg_proto = PROTOCOL_RDP;

				goto retry;
			}

			logger(Core, Notice, "Failed to connect, %s.\n", reason);
			return False;
		}

		if (type != RDP_NEG_RSP)
		{
			tcp_disconnect();
			logger(Protocol, Error, "iso_connect(), expected RDP_NEG_RSP, got 0x%x",
			       type);
			return False;
		}

		if (flags & EXTENDED_CLIENT_DATA_SUPPORTED) {
			g_extended_data_supported = True;
			logger(Protocol, Debug, "Server supports Extended Client Data");
		}
		else {
			g_extended_data_supported = False;
			logger(Protocol, Debug, "Server does not support Extended Client Data");
		}

		if ((g_num_monitors > 1) && !g_extended_data_supported) {
			logger(Protocol, Warning, "Got more than 1 monitor but server does not support Extended Client Data");
			g_num_monitors = 1;
		}

		/* handle negotiation response */
		if (data == PROTOCOL_SSL)
		{
			if (!tcp_tls_connect())
			{
				/* failed to connect using cssp, let retry with plain TLS */
				logger(Core, Verbose,
				       "Failed to connect using SSL, trying with plain RDP.");
				tcp_disconnect();
				neg_proto = PROTOCOL_RDP;
				goto retry;
			}
			/* do not use encryption when using TLS */
			g_encryption = False;
			logger(Core, Notice, "Connection established using SSL.");
		}
#ifdef WITH_CREDSSP
		else if (data == PROTOCOL_HYBRID)
		{
			if (!cssp_connect(server, username, domain, password, s))
			{
				/* failed to connect using cssp, let retry with plain TLS */
				logger(Core, Verbose,
				       "Failed to connect using NLA, trying with SSL");
				tcp_disconnect();
				neg_proto = PROTOCOL_SSL;
				goto retry;
			}

			/* do not use encryption when using TLS */
			logger(Core, Notice, "Connection established using CredSSP.");
			g_encryption = False;
		}
#endif
		else if (data == PROTOCOL_RDP)
		{
			logger(Core, Notice, "Connection established using plain RDP.");
		}
		else if (data != PROTOCOL_RDP)
		{
			tcp_disconnect();
			logger(Protocol, Error,
			       "iso_connect(), unexpected protocol in negotiation response, got 0x%x",
			       data);
			return False;
		}

		*selected_protocol = data;
	}
	return True;
}

/* Disconnect from the ISO layer */
void
iso_disconnect(void)
{
	iso_send_msg(ISO_PDU_DR);
	tcp_disconnect();
}

/* reset the state to support reconnecting */
void
iso_reset_state(void)
{
	g_encryption = g_encryption_initial;
	tcp_reset_state();
}
