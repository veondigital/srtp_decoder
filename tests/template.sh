#!/bin/bash

PCAP_FILENAME=<filename>

SSRC_A=<ssrc_a>
SSRC_B=<ssrc_b>
SSTP_A=<sstp_a>
SSTP_B=<sstp_b>

ALG=AES_CM_128_HMAC_SHA1_80

test -d output || mkdir output

../build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true 2>&1 > ${PCAP_FILENAME}_A.log
../build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true 2>&1 > ${PCAP_FILENAME}_B.log


