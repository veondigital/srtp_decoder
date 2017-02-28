#include "pcap_reader.h"
#include <cassert>

//FIXME
#define _DEBUG

bool is_ip_over_eth(const u_char* packet)
{
	struct ether_header *eptr;  /* net/ethernet.h */

	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;

	//fprintf(stdout, "ethernet header source: %s", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
	// fprintf(stdout, " destination: %s ", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

	/* check to see if we have an ip packet */
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
		return true;
	else
		return false;
}

/* Callback function invoked by libpcap for every incoming packet */
void p_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	global_params* params = reinterpret_cast<global_params*>(param);

	struct tm *ltime;
	char timestr[16];

	const ip_header  *ih = NULL;
	const udp_header *uh = NULL;
	const tcp_header *th = NULL;
	const char *turn_body = NULL;

	u_int eth_hdr_size;
	u_int ip_hdr_size;
	u_int tcp_hdr_size;
	u_int const udp_hdr_size = 8;
	u_int const turn_hdr_size = 4;
	u_int tcp_data_size = 0;
	u_int udp_size = 0;

	/*
	* unused parameter
	*/
	(void)(param);

	/* convert the timestamp to readable format */
	ltime = localtime(&header->ts.tv_sec);
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
		printf("UDP: %s.%.6d\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d  length:%d\n",
			timestr, header->ts.tv_usec,
			ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ntohs(uh->sport),
			ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ntohs(uh->dport),
			header->len);
#endif
		udp_size = ntohs(uh->len);
		turn_body = (char *)uh + udp_hdr_size;
		printf("eth: %d, ip: %d, udp: %d, turn: %d\n", eth_hdr_size, ip_hdr_size, udp_size, udp_size - udp_hdr_size);
		//assert(header->len == eth_hdr_size+ip_hdr_size+udp_size);
		break;

	case IPPROTO_TCP:
		/* retireve the position of the tcp header */
		th = (tcp_header *)((u_char*)ih + ip_hdr_size);
#ifdef _DEBUG
		/* print ip addresses and tcp ports */
		printf("TCP: %s.%.6d\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d  length:%d\n",
			timestr, header->ts.tv_usec,
			ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ntohs(th->sport),
			ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ntohs(th->dport),
			header->len);
#endif
		tcp_hdr_size = TH_OFF(th) * 4;
		tcp_data_size = header->len - (eth_hdr_size + ip_hdr_size + tcp_hdr_size);
		turn_body = (char *)th + tcp_hdr_size;
		printf("eth: %d, ip: %d, tcp: %d, turn: %d\n", eth_hdr_size, ip_hdr_size, tcp_hdr_size, tcp_data_size);
		//assert(header->len == eth_hdr_size+ip_hdr_size+tcp_hdr_size+tcp_data_size);
		if (tcp_data_size <= 4) {
			return;
		}
		break;

	default:
		return;
	}

	assert(turn_body);
	channel_data_header *turn_hdr = (channel_data_header *)turn_body;

	int   rtp_size = 0;
	char *rtp_body = 0;

	uint8_t channel_mask = static_cast<uint8_t>(turn_hdr->channel_number);
	if (channel_mask == 0x40)
	{
		if (udp_size) {
			rtp_size = udp_size - udp_hdr_size - turn_hdr_size;
			rtp_body = (char*)uh + udp_hdr_size + turn_hdr_size;
		} else if (tcp_data_size) {
			rtp_size = tcp_data_size - turn_hdr_size;
			rtp_body = (char*)th + tcp_hdr_size + turn_hdr_size;
		} else {
			assert(0);
			return;
		}
		printf("eth: %d, ip: %d, tcp: %d, turn: %d, rtp: %d\n", eth_hdr_size, ip_hdr_size, tcp_hdr_size, ntohs(turn_hdr->message_size), rtp_size);
		//assert(rtp_size == ntohs(turn_hdr->message_size));
	}
	else if (udp_size)
	{
		rtp_size = udp_size - udp_hdr_size;
		rtp_body = (char*)uh + udp_hdr_size;
		printf("rtp: %d\n", rtp_size);
	}
	else
	{
		return;
	}

	common_rtp_hdr_t *hdr = (common_rtp_hdr_t *)rtp_body;
	bool is_rtp = hdr->version == 2;

	if (is_rtp)
	{
		if (params->ssrc == ntohl(hdr->ssrc))
		{
			srtp_packet_t srtp_packet(rtp_body, rtp_body + rtp_size);
			params->srtp_stream.push_back(srtp_packet);
			printf("rtp: ssrc: 0x%x, seq: %d found\n", ntohl(hdr->ssrc), ntohs(hdr->seq));
		}
		else
		{
			printf("rtp: ssrc: 0x%x, seq: %d ignored\n", ntohl(hdr->ssrc), ntohs(hdr->seq));
		}
	}

	// TO DO RTCP
	// Oy vey iz mir https://tools.ietf.org/html/rfc5761#page-4 
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
		return  false;
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

	pcap_loop(fp, 0, &p_handler, (u_char*)(&params));

	pcap_close(fp);
	return  true;
}

