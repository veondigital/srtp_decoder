#!/bin/bash

PCAP_FILENAME=wifi-tcp_to_3g

SSRC_A=0x3482B39F
SSRC_B=0x3482B3A1
SSTP_A=ZGRjMTA4OWRkYWJmMGJhM2YxZWQ1MjExODJmMTVl
SSTP_B=ZmVlOWQwMGJhNDIxMzcyZmVlM2U0NTllMmZiMzM4

ALG=AES_CM_128_HMAC_SHA1_80

test -d output || mkdir output

../build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true 2>&1 > ${PCAP_FILENAME}_A.log
../build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true 2>&1 > ${PCAP_FILENAME}_B.log
