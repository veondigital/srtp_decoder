#pragma once

#include "headers.h"

class TCP_STUN_Former
{
public:
	enum Result {
		eOk,		// packet is ate, give the next or re-call eat_buffer()
		eSkip,		// packet is skipped
		eFound		// STUN packet is found
	};

public:
	// Construct the buffer
	TCP_STUN_Former();

	// Eating the buffer, return result code (see enum Result)
	int eat_buffer(const char *data, int size, int *eat_bytes);

	// Get copy of buffer
	void get_buffer(srtp_packet_t &&out_packet);

	// Fully reset the buffer
	void reset_buffer();

private:
	srtp_packet_t *buf {0};
	size_t full_packet_size {0};

	enum State {
		eIdle,
		eChannelDataDetecting,
		eStunDetecting,
		eDataFound,
		eFinished

	}	state {eIdle};
};

