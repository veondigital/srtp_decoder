#!/bin/bash

PCAP_FILENAME=wifi-tcp_to_3g_2_coturn_dump

SSRC_A=0x34837DE1
SSRC_B=0x34837DE3
SSTP_A=YTU4OTQ5NGM2YjJiZTgxMmQ4MDgyZmQ4MThkZWE3
SSTP_B=NmMwNTZkMjBjM2VhY2NhZTAyNzViYzJjOGFhNjA1

ALG=AES_CM_128_HMAC_SHA1_80

../.build/srtp_decoder -vl ${PCAP_FILENAME}_a.pcap ${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true 2>&1 > ${PCAP_FILENAME}_a.log
../.build/srtp_decoder -vl ${PCAP_FILENAME}_b.pcap ${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true 2>&1 > ${PCAP_FILENAME}_b.log
