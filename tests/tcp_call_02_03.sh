#!/bin/bash

PCAP_FILENAME=tcp_call_02_03_client_s1

SSRC_A=0x1C090D13
SSRC_B=0x1C090D15
SSTP_A=ODQ3ODIxYTE1NTIxZDVhMGRmNjNiODMwN2M3ODdk
SSTP_B=ZDExYzU2MjgxMDU1OGZhYzE2MTI4MTRlODZlMzlm

ALG=AES_CM_128_HMAC_SHA1_80

test -f output || mkdir output

../build/srtp_decoder ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true tcp 2>&1 > z_log_a.txt
../build/srtp_decoder ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true tcp 2>&1 > z_log_b.txt


