/* -*- c-basic-offset: 8 -*-
   rdesktop: A Remote Desktop Protocol client.

   Dynamic Channel Virtual Channel Extension (MS-RDPEDYC)

   Copyright 2017 Alexander Zakharov <uglym8@gmail.com>

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

#include <string.h>
#include <uthash.h>

#include "rdesktop.h"

#define DVC_CAPABILITY_REQUEST_PDU	0x05

#define DYNVC_CREATE_REQ 0x01
#define DYNVC_CREATE_RSP 0x01

#define DYNVC_DATA_FIRST 0x02
#define DYNVC_DATA 0x03
#define DYNVC_CLOSE 0x04
#define DYNVC_DATA_FIRST_COMPRESSED 0x06
#define DYNVC_DATA_COMPRESSED 0x07

#define DYNVC_SOFT_SYNC_REQUEST 0x08
#define DYNVC_SOFT_SYNC_RESPONSE 0x09

#define DYNVC_DATA_MAX_LEN 1590
#define DYNVC_MAX_PKT_SIZE 1600


VCHANNEL *dvc_channel = NULL;

struct dvc_listener {
	char *name;

	int chan_size;
	uint32 chanId;

	int state;
	int frag_processing;

	int (*handle_pkt)(STREAM, uint32);

	int skip;

	UT_hash_handle hh;
	UT_hash_handle hh2;
};

struct dvc_listener *dvc_list = NULL;
struct dvc_listener *id2dvc_list = NULL;

int dvc_handle_caps(STREAM s)
{
	return 0;
}

void dvc_out_channel_id(STREAM s, int chan_size, uint32 id)
{
	uint8 u8_id;
	uint16 u16_id;

	switch (chan_size) {
		case 1:
			u8_id = id;
			out_uint8(s, u8_id);
			break;
		case 2:
			u16_id = id;
			out_uint16_le(s, u16_id);
			break;
		case 4:
			out_uint32_le(s, id);
			break;
	}
}

void dvc_process(STREAM s)
{
	uint8 hdr;

	STREAM out;

	int chan_size;
	uint32 chanId;

	uint16 Version;
	uint8 cbId, Sp, Cmd;

	uint16 PriorityCharge0;
	uint16 PriorityCharge1;
	uint16 PriorityCharge2;
	uint16 PriorityCharge3;

	struct dvc_listener *entry;

	logger(Protocol, Debug, "dvc_process()");

	in_uint8(s, hdr);

	cbId = hdr & 0x3;
	Sp = (hdr >> 2) & 0x3;
	Cmd = (hdr >> 4) & 0xF;

	if (Cmd == DVC_CAPABILITY_REQUEST_PDU) {

		if (cbId != 0) {
			logger(Core, Error, "%s: Protocol violation. cbId (0x%x) MUST be 0 for DVC_CAPABILITY_REQUEST_PDU.\n", __func__, cbId);
			return;
		}

		in_uint8s(s, 1); /* Skip Pad */
		in_uint16(s, Version);

		//TODO: Make sure that cbId is 0 (It MUST be according to MS-RDPEDYC] */
		if (Version > 1) {
			in_uint16(s, PriorityCharge0);
			in_uint16(s, PriorityCharge1);
			in_uint16(s, PriorityCharge2);
			in_uint16(s, PriorityCharge3);
		}

		// TODO: Choose version we're going to support as a MIN(ours, server's)
		// TODO: Move this to separate funciton
		// Send DYNVC_CAPS_RSP
		out = channel_init(dvc_channel, 4);
		out_uint8(out, (Cmd << 4));	/* cbId and Sp MUST be set to 0 and Cmd to 0x05 */
		out_uint8(out, 0);	/* Pad, MUST be set to 0 */
		out_uint16_le(out, Version); // Version we support
		s_mark_end(out);
		channel_send(out, dvc_channel);

		return;
	}

	switch (cbId) {
		case 0:
			chan_size = 1;
			in_uint8(s, chanId);
			break;
		case 1:
			chan_size = 2;
			in_uint16_le(s, chanId);
			break;
		case 2:
			chan_size = 4;
			in_uint32_le(s, chanId);
			break;
		default:
			logger(Core, Error, "Wrong cbId value (0x%x)\n", cbId);
			//TODO send appropriate error code
	}

	if (Cmd == DYNVC_CREATE_REQ) {

		HASH_FIND_STR(dvc_list, (const char *)s->p, entry);

		out = channel_init(dvc_channel, 4 + chan_size + 1);
		out_uint8(out, (Cmd << 4) | (chan_size >> 1));

		dvc_out_channel_id(out, chan_size, chanId);

		//According to MS-RDPEDYC p.23 0 or positive value means SUCCESS and negative means error.
		// TODO: Check MS-ERREF and choose the appropriate error code

		if (entry) {
			logger(Protocol, Debug, "%s: Got registered listener for `%s` channel\n", __func__, s->p);

			if (!entry->state) {
				entry->chan_size = chan_size;
				entry->chanId = chanId;
				entry->state= 1;

				HASH_ADD(hh2, id2dvc_list, chanId, sizeof(uint32), entry);
			}

			out_uint32_le(out, RD_STATUS_SUCCESS);

		} else {
			logger(Core, Error, "%s: No registered listener for `%s` channel\n", __func__, s->p);

			out_uint32_le(out, -1);
		}

		s_mark_end(out);
		channel_send(out, dvc_channel);

		return;
	}

	// All other pkts MUST have correct (known/registered) channel ID
	HASH_FIND(hh2, id2dvc_list, &chanId, sizeof(uint32), entry);

	if (entry) {
		logger(Protocol, Debug, "%s: Got registered listener (%s) for channel id = 0x%x\n", __func__, entry->name, chanId);
	} else {
		logger(Core, Error, "%s: No registered listener for channel with id = 0x%x\n", __func__, chanId);
		// TODO: Handle this correctly
		return;
	}

	switch (Cmd) {
	case DYNVC_CLOSE:
		// TODO: Check that this channel is indeed opened
		out = channel_init(dvc_channel, 1 + chan_size);
		out_uint8(out, (Cmd << 4) | (chan_size >> 1));
		dvc_out_channel_id(out, chan_size, chanId);
		s_mark_end(out);
		channel_send(out, dvc_channel);

		entry->chan_size = 0;
		entry->chanId = 0;
		entry->state = 0;
		entry->frag_processing = 0;

		HASH_DELETE(hh2, id2dvc_list, entry);

		break;

	case DYNVC_DATA:

		entry->handle_pkt(s, chanId);

#if 0
		if (entry->frag_processing) {
			//Accumulate the data
		} else {
			// Pass the data to the lower lever listener
		}
#endif
		break;

	case DYNVC_DATA_FIRST:
		// Accumulate data here until the length bytes is gathered and only
		// after that pass it to the lower level for processing
		//entry->frag_processing = 1;

	default:
		logger(Protocol, Warning, "%s: Handling for Cmd = 0x%x is not implemented yet.\n", __func__, Cmd);
		return;
	}

	return;
}

VCHANNEL *dvc_init(void)
{
	VCHANNEL *ch = NULL;

	ch = channel_register("drdynvc", CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_COMPRESS_RDP,
			dvc_process);

	if (ch == NULL) {
		logger(Core, Error, "%s: failed to init DVC\n", __func__);
	}

	dvc_channel = ch;

	return ch;
}

int dvc_write_pkt(STREAM out, uint32 id, int len, uint8 *buf, int blen)
{
	struct dvc_listener *entry;

	int left = 0;
	int idx = 0;

	int sbytes = 0;

	HASH_FIND(hh2, id2dvc_list, &id, sizeof(id), entry);

	if (entry) {
		logger(Protocol, Debug, "%s: Got registered listener (%s) for channel id = 0x%x\n", __func__, entry->name, id);
	} else {
		logger(Core, Debug, "%s: No registered listener for channel with id = 0x%x\n", __func__, id);
		// TODO: Handle this correctly
		return -1;
	}

	if ((len > DYNVC_DATA_MAX_LEN) && ((entry->skip + len >= DYNVC_MAX_PKT_SIZE))) {

		//Begin by sending DATA_FIRST and continue with a sequence of DATA pkts
		sbytes =  DYNVC_MAX_PKT_SIZE - entry->skip;

		out_uint8p(out, buf, sbytes);
		s_mark_end(out);

		out->p -= (entry->skip + sbytes);

		channel_send(out, dvc_channel);

		// Send the rest as a series of DATA
		left = (len - sbytes);
		idx = sbytes;

		while (left) {

			entry->skip = 1 + entry->chan_size;
			sbytes =  DYNVC_MAX_PKT_SIZE - entry->skip;

			if (sbytes > left) {
				sbytes = left;
			}

			// Should be later replaced with a call to dvc_write_pkt
			out = channel_init(dvc_channel, entry->skip + sbytes);
			out_uint8(out, (DYNVC_DATA << 4) | (entry->chan_size >> 1));
			dvc_out_channel_id(out, entry->chan_size, entry->chanId);
			out_uint8p(out, &buf[idx], sbytes);
			s_mark_end(out);

			out->p -= (entry->skip + sbytes);

			channel_send(out, dvc_channel);

			idx += sbytes;
			left -= sbytes;
		}

		return 0;
	}

	out->p -= (entry->skip + len);

	channel_send(out, dvc_channel);

	// zero skip
	entry->skip = 0;

	return 0;
}

STREAM dvc_init_out_stream(uint32 id, int len, int *pass_buf)
{
	STREAM out;
	int len_bits;
	int len_bytes;

	struct dvc_listener *entry;

	HASH_FIND(hh2, id2dvc_list, &id, sizeof(id), entry);

	if (entry) {
		logger(Protocol, Debug, "%s: Got registered listener (%s) for channel id = 0x%x\n", __func__, entry->name, id);
	} else {
		logger(Core, Error, "%s: No registered listener for channel with id = 0x%x\n", __func__, id);
		return NULL;
	}

	if (len > DYNVC_DATA_MAX_LEN) {

		// It's a little bit strange but according to MS-RDPEDYC 2.2.3.1 Len maybe 0x0 meaning that Lenght is 1 bytes
		// How come?  Actually I've no the slightest idea:)
		len_bits = 0x1;
		len_bytes = 2;

		if (len > 65536) {
			len_bits = 0x2;
			len_bytes = 4;
		}

		// Init as DYNVC_DATA_FIRST
		entry->skip = (1 + entry->chan_size + len_bytes);

		out = channel_init(dvc_channel, entry->skip + len);

		out_uint8(out, (DYNVC_DATA_FIRST << 4) | (len_bits << 2) | (entry->chan_size >> 1));
		dvc_out_channel_id(out, entry->chan_size, entry->chanId);

		if (len_bytes == 2) {
			out_uint16_le(out, len);
		} else {
			out_uint32_le(out, len);
		}

		// To avoid double copy and excessive memory allocation
		// Check 2.2.3, 2.2.3.1 and 2.2.3.2
		if (len + entry->skip > DYNVC_MAX_PKT_SIZE) {
			*pass_buf = 1;
		}

		return out;
	}

	// Init as DYNVC_DATA
	entry->skip = (1 + entry->chan_size);

	out = channel_init(dvc_channel, entry->skip + len);

	out_uint8(out, (DYNVC_DATA << 4) | (entry->chan_size >> 1));
	dvc_out_channel_id(out, entry->chan_size, entry->chanId);

	return out;
}

int dvc_init_listener(char *channel, int (*handle_pkt)(STREAM, uint32))
{
	struct dvc_listener *entry;

	HASH_FIND_STR(dvc_list, channel, entry);

	if (!entry) {
		logger(Protocol, Debug, "%s: No registered listener for `%s` DVC\n", __func__, channel);

		entry = malloc(sizeof(*entry));

		if (!entry) {
			logger(Core, Error, "%s: malloc() failled\n", __func__);
			return -1;
		}

		entry->chan_size = 0;
		entry->chanId = 0;
		entry->state = 0;
		entry->frag_processing = 0;

		entry->handle_pkt = handle_pkt;
		//entry->dvc_send_pkt = dvc_write_pkt;

		entry->name = strdup(channel);
		if (!entry->name) {
			logger(Core, Error, "%s: strdup() failled\n", __func__);
			free(entry);
			return -1;
		}

		HASH_ADD_KEYPTR(hh, dvc_list, entry->name, strlen(entry->name), entry);

		return 0;

	} else {
		logger(Core, Error, "%s: Already has registered listener for `%s` DVC\n", __func__, channel);
		return 1;
	}
}
