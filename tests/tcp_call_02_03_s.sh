#!/bin/bash

PCAP_FILENAME_A=tcp_call_02_03_client_s1
PCAP_FILENAME_B=tcp_call_02_03_client_s2

SSRC_A=0x1C090D13
SSRC_B=0x1C090D15
SSTP_A=ODQ3ODIxYTE1NTIxZDVhMGRmNjNiODMwN2M3ODdk
SSTP_B=ZDExYzU2MjgxMDU1OGZhYzE2MTI4MTRlODZlMzlm

ALG=AES_CM_128_HMAC_SHA1_80

test -f output || mkdir output

../build/srtp_decoder ${PCAP_FILENAME_A}.pcap ./output/${PCAP_FILENAME_A}.opus ${SSRC_A} ${SSTP_A} ${ALG} true tcp 2>&1 > ${PCAP_FILENAME_A}.log
../build/srtp_decoder ${PCAP_FILENAME_B}.pcap ./output/${PCAP_FILENAME_B}.opus ${SSRC_B} ${SSTP_B} ${ALG} true tcp 2>&1 > ${PCAP_FILENAME_B}.log

