#include "pcap_reader.h"
#include <cassert>

#ifndef WIN32
//FIXME
# define _DEBUG
#endif

bool is_ip_over_eth(const u_char* packet)
{
	struct ether_header *eptr;/* net/ethernet.h */

	/* lets start with the ether header... */
	eptr = (struct ether_header *)packet;

	//fprintf(stdout, "ethernet header source: %s", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
	//fprintf(stdout, " destination: %s ", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

	/* check to see if we have an ip packet */
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
		return true;
	else
		return false;
}

/* Callback function invoked by libpcap for every incoming packet */
void p_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	global_params *params = reinterpret_cast<global_params*>(param);

	static int pack_no{ 0 };
	struct tm *ltime;
	char timestr[16];

	const ip_header  *ih = NULL;
	const udp_header *uh = NULL;
	const tcp_header *th = NULL;
	const char *turn_head = NULL;

	u_int eth_hdr_size;
	u_int ip_hdr_size;
	u_int tcp_hdr_size;
	u_int const udp_hdr_size = 8;
	u_int const turn_hdr_size = 4;
	u_int tcp_data_size = 0;
	u_int udp_size = 0;
	u_int data_size = 0;

	/* unused parameter	*/
	(void)(param);
	
	++pack_no;

	/* convert the timestamp to readable format */
	time_t const tm = header->ts.tv_sec;
	ltime = localtime(&tm);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	// printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);

	eth_hdr_size = is_ip_over_eth(pkt_data) ? SIZE_ETHERNET : 0;

	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data + eth_hdr_size);
	ip_hdr_size = IP_HL(ih) * 4;

	/* determine protocol */
	switch(ih->proto) {
	case IPPROTO_UDP:
		/* retireve the position of the udp header */
		uh = (udp_header *)((u_char*)ih + ip_hdr_size);
#ifdef _DEBUG
		/* print ip addresses and udp ports */
		printf("[%d] UDP: %s.%.6d\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d  length:%d\n",
			pack_no, timestr, header->ts.tv_usec,
			ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ntohs(uh->sport),
			ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ntohs(uh->dport),
			header->len);
#endif
		udp_size = ntohs(uh->len);	// udp_size = header size(8) + data size
		turn_head = (char *)uh + udp_hdr_size;
		data_size = udp_size - udp_hdr_size;
#ifdef _DEBUG
		printf("size: eth: %d, ip: %d, udp: %d, data: %d\n", eth_hdr_size, ip_hdr_size, udp_hdr_size, data_size);
#endif
		//assert(header->len == eth_hdr_size+ip_hdr_size+udp_size);
		break;

	case IPPROTO_TCP:
		/* retireve the position of the tcp header */
		th = (tcp_header *)((u_char*)ih + ip_hdr_size);
#ifdef _DEBUG
		/* print ip addresses and tcp ports */
		printf("[%d] TCP: %s.%.6d\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d  length:%d\n",
			pack_no, timestr, header->ts.tv_usec,
			ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ntohs(th->sport),
			ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ntohs(th->dport),
			header->len);
#endif
		tcp_hdr_size = TH_OFF(th) * 4;
		tcp_data_size = header->len - (eth_hdr_size + ip_hdr_size + tcp_hdr_size);
		turn_head = (char *)th + tcp_hdr_size;
		data_size = tcp_data_size;
#ifdef _DEBUG
		printf("size: eth: %d, ip: %d, tcp: %d, data: %d\n", eth_hdr_size, ip_hdr_size, tcp_hdr_size, data_size);
#endif
		//assert(header->len == eth_hdr_size+ip_hdr_size+tcp_hdr_size+tcp_data_size);
		break;

	default:
		return;
	}

	assert(turn_head);

	auto parse_rtp =
		[header, params]
		(char *rtp_body, int rtp_size)
		{
			auto hdr = reinterpret_cast<common_rtp_hdr_t const *>(rtp_body);
			auto rtcp_hdr = reinterpret_cast<rtcp_report_hdr const *>(rtp_body);
			auto stun_hdr = reinterpret_cast<const stun_header *>(rtp_body);

			//FIXME: there are many of non-RTP protocols, it isn't enough to detect RTP by version only
			if (hdr->version == 2) {
				if (rtcp_hdr->pt == RTCP_SR_REPORT || rtcp_hdr->pt == RTCP_RR_REPORT) {
					//if (params->ssrc == ntohl(rtcp_hdr->ssrc)) {
					//	printf("skip rtcp report\n");
					//}
					printf("skip rtcp report\n\n");
					return;
				}
#ifdef _DEBUG
				printf("rtp: head, size: %d\n", rtp_size);
				printf("\tversion=%d\n", hdr->version);
				printf("\tpadding=%d\n", hdr->p);
				printf("\text=%d\n", hdr->x);
				printf("\tcc=%d\n", hdr->cc);
				printf("\tpt=%d\n", hdr->pt);
				printf("\tm=%d\n", hdr->m);
				printf("\tseq=%d\n", htons(hdr->seq));
				printf("\tts=%d\n", htonl(hdr->ts));
				printf("\tssrc=0x%x\n", htonl(hdr->ssrc));
#endif
				if (params->ssrc == ntohl(hdr->ssrc)) {
					auto seq = htons(hdr->seq);
					if (params->seq + 1 != seq) {
						printf("rtp: lost packet detected: %d - %d\n", params->seq, seq);
					}
					params->seq = seq;
					srtp_packet_t srtp_packet(rtp_body, rtp_body + rtp_size);
					params->srtp_stream.push_back(srtp_packet);
				}
				else {
					printf("rtp: alien ssrc=0x%x\n", htonl(hdr->ssrc));
				}

				streams::iterator itr = params->all_streams_info.find(htonl(hdr->ssrc));
				if (itr == params->all_streams_info.end()) {
					params->all_streams_info.insert(streams::value_type(htonl(hdr->ssrc), rtp_info(htonl(hdr->ssrc), htonl(hdr->ts), header->ts.tv_sec)));
				}
				else {
					itr->second.last_ts = htonl(hdr->ts);
					++itr->second.packets;
				}
			} else if (htonl(stun_hdr->magic_cookie) == 0x2112a442) {
				// (6)
				printf("stun: message skipped\n");
			} else {
				printf("udp: unknown, size: %d\n", rtp_size);
			}
			printf("\n");
		};

	char *rtp_body = 0;
	int   rtp_size = 0;

	// Packet can be:
	// 1. UDP (moves only one voice fragment)
	// 1.1. ChannelData TURN (ChannelMask == 0x40xx)
	// 1.1.1. RTP (1)
	// 1.2. Another TURN-message
	// 1.3. RTP (2)
	// 1.4. Something else (3)
	// 2. TCP (several PDUs may be inside)
	// 2.1. PDU is ChannelData TURN (ChannelMask == 0x40xx)
	// 2.1.1. RTP - whole packet (4)
	// 2.1.2. RTP - begin of packet (5)
	// 2.2. PDU is another TURN-message (6)
	// 2.3. PDU is rest of RTP Packet (7)
	// 2.4. Something else (8)
	for (;data_size > turn_hdr_size; data_size -= (rtp_size + turn_hdr_size), turn_head += (rtp_size + turn_hdr_size))
	{
		if (udp_size)
			printf("data size: %d\n", udp_size);
		else
			printf("data size: %d\n", data_size);

		// check if ChannelData message
		auto turn_hdr = reinterpret_cast<const channel_data_header *>(turn_head);
		auto channel_mask = static_cast<uint8_t>(turn_hdr->channel_number);

		if (channel_mask == 0x40) {
			// (1), (4), (5)
			//A.D. FIXME: turn lies (I saw it into TCP-dumps) into ChannelData.MessageLength, we need make value to be multiple 4
			rtp_size = (htons(turn_hdr->message_size) + 3) >> 2 << 2;
			rtp_body = (char *)turn_head + turn_hdr_size;

			parse_rtp(rtp_body, rtp_size);
		} else {
			if (udp_size) {
				// (2), (3)
				rtp_size = udp_size;
				rtp_body = (char *)turn_head;

				parse_rtp(rtp_body, rtp_size);
				return;
			} else {
				// really it may be TURN-message (if) or unknown message (else)
				rtp_size = htons(turn_hdr->message_size);
				rtp_body = (char*)turn_head + turn_hdr_size;

				uint32_t magic_cookie = htonl(*(reinterpret_cast<uint32_t *>(rtp_body)));
				//printf("stun: magic cookie: 0x%x\n", magic_cookie);
				if (magic_cookie == 0x2112a442) {
					// (6)
					printf("stun: message %d bytes skipped\n", rtp_size);
					rtp_size += 16;
				} else {
					// (7)
					printf("unknown: message skipped\n");
					return;
				}
			}
		}
		//printf("rest of data size: %d\n\n", data_size - rtp_size - turn_hdr_size);
	}
}

bool read_pcap(std::string const& file, global_params& params)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;

	/* Open the capture file */
	if ((fp = pcap_open_offline(file.c_str(), errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s: %s\n", file.c_str(), errbuf);
		return false;
	}

	std::string packet_filter = params.filter.empty() ? "udp" : params.filter;
	u_int netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(fp, &fcode, packet_filter.c_str(), 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_close(fp);
		return  false;
	}

	//set the filter
	if (pcap_setfilter(fp, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_close(fp);
		return  false;
	}

	//work
	pcap_loop(fp, 0, &p_handler, (u_char*)(&params));

	pcap_close(fp);
	return true;
}

