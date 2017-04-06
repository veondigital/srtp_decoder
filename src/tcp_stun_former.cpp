#include <cassert>
#include <algorithm>

#include "tcp_stun_former.h"

TCP_STUN_Former::TCP_STUN_Former()
{
	reset_buffer();
}

void TCP_STUN_Former::reset_buffer()
{
	buf = 0;
	full_packet_size = 0;
	state = eIdle;
}

int TCP_STUN_Former::eat_buffer(const char *data, int size, int *eat_bytes)
{
	int min_bytes;

	auto EAT_BUF = [&data, &size, eat_bytes](srtp_packet_t *buf, int bytes) {
		for (auto i=0; i<bytes; ++i) {
			buf->push_back(*data++);
		}
		*eat_bytes += bytes;
		size -= bytes;
	};
	auto SKIP_BUF = [&size, eat_bytes](int bytes) {
		*eat_bytes += bytes;
		size -= bytes;
	};

	switch (state) {
	case eIdle:
		assert(buf != 0);
		buf = new srtp_packet_t(STUN_CHANNEL_HEADER_SIZE);
		state = eChannelDataDetecting;
	case eChannelDataDetecting: {
		assert(STUN_CHANNEL_HEADER_SIZE > buf->size());
		min_bytes = STUN_CHANNEL_HEADER_SIZE - buf->size();
		if (size < min_bytes) {
			EAT_BUF(buf, size);
			return eOk;
		}
		EAT_BUF(buf, min_bytes);

		auto p = buf->data();
		auto stun_hdr = reinterpret_cast<const channel_data_header *>(p);
		auto channel_mask = static_cast<uint8_t>(stun_hdr->channel_number);
		if (channel_mask & 0x40) {
			full_packet_size = STUN_CHANNEL_HEADER_SIZE + htons(stun_hdr->message_size);
			state = eDataFound;
			return eOk;
		}
		state = eStunDetecting;
		return eOk;
	}
	case eStunDetecting: {
		min_bytes = STUN_CHANNEL_HEADER_SIZE*2 - buf->size();
		if (size < min_bytes) {
			EAT_BUF(buf, size);
			return eOk;
		}
		EAT_BUF(buf, min_bytes);

		auto p = buf->data();
		auto stun_hdr = reinterpret_cast<const channel_data_header *>(p);
		auto magic_cookie = htonl(*(reinterpret_cast<uint32_t *>((char *)p + STUN_CHANNEL_HEADER_SIZE)));
		if (magic_cookie == STUN_MAGIC_COOKIE) {
			full_packet_size = STUN_HEADER_SIZE + htons(stun_hdr->message_size);
			state = eDataFound;
			return eOk;
		}
		SKIP_BUF(size);
		state = eFinished;
		return eSkip;
	}
	case eDataFound:
		min_bytes = std::min<int>({size, (int)(full_packet_size - buf->size())});
		EAT_BUF(buf, min_bytes);
		if (full_packet_size == buf->size()) {
			state = eFinished;
			return eFound;
		}
		return eOk;
	case eFinished:
		SKIP_BUF(size);
		return eSkip;
	}
	SKIP_BUF(size);
	return eSkip;
}

void TCP_STUN_Former::get_buffer(srtp_packet_t &&out_packet)
{
	out_packet = std::move(*buf);
	buf = 0;
}

