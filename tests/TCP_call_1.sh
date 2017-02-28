#!/bin/bash

PCAP_FILENAME=TCP_call_1

SSRC_A=11EA8136
SSRC_B=11EA8138
SSTP_A=MzU4YTNmNmFlMGNkMGI5ODU1NjdkMWZlYjVhYzFk
SSTP_B=ZDc5YzZiYjRkMzI0MjQwZTdkMzFhOGI5ZTIxN2Fk

ALG=AES_CM_128_HMAC_SHA1_80

test -f output || mkdir output

../build/srtp_decoder ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true tcp 2>&1 > z_log_a.txt
../build/srtp_decoder ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true tcp 2>&1 > z_log_b.txt


