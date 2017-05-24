#!/bin/bash

PCAP_FILENAME=wifi-tcp_to_3g

SSRC_A=0x3482B39F
SSRC_B=0x3482B3A1
SSTP_A=ZGRjMTA4OWRkYWJmMGJhM2YxZWQ1MjExODJmMTVl
SSTP_B=ZmVlOWQwMGJhNDIxMzcyZmVlM2U0NTllMmZiMzM4

ALG=AES_CM_128_HMAC_SHA1_80

../cmake-build-debug/srtp_decoder -l -f ${PCAP_FILENAME}.pcap

../cmake-build-debug/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_A.opus -s ${SSRC_A} -k ${SSTP_A} -r ${ALG} -c true 2>&1 > ${PCAP_FILENAME}_A.log

../cmake-build-debug/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_B.opus -s ${SSRC_B} -k ${SSTP_B} -r ${ALG} -c true 2>&1 > ${PCAP_FILENAME}_B.log
