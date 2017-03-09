#!/bin/bash

PCAP_FILENAME=WebRTC_PCMA_p2p_SDES_Call_1

SSRC_A=0xD092D296
SSRC_B=0x522B93AB
SSTP_A=7SYMKhu8sVMhCr4VXh+ZqkteB01QgqDSgLr4L9iU
SSTP_B=bhn3DDDcf7GhHEnFkGLW9V223XncT60nJrTQK06x

ALG=AES_CM_128_HMAC_SHA1_80

test -d output || mkdir output

../build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_A.pcma ${SSRC_A} ${SSTP_A} ${ALG} false 2>&1 > ${PCAP_FILENAME}_A.log
../build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_B.pcma ${SSRC_B} ${SSTP_B} ${ALG} false 2>&1 > ${PCAP_FILENAME}_B.log


