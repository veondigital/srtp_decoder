#!/bin/bash

PCAP_FILENAME=udp_call_02_03_client

SSRC_A=0x1C065362
SSRC_B=0x1C065364
SSTP_A=NjZiYTBmY2FmOGE2ZGU3MmVlMzM4ZDQ0OGVhMTI0
SSTP_B=YTEzNjhhMTNmNWUxMjljZTg3MTEyNWQ2YTE2ODQ2

ALG=AES_CM_128_HMAC_SHA1_80

test -f output || mkdir output

../build/srtp_decoder -l ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true 2>&1 >${PCAP_FILENAME}_A.log
../build/srtp_decoder -l ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true 2>&1 >${PCAP_FILENAME}_B.log

