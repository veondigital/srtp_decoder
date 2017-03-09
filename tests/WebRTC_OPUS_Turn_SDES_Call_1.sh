#!/bin/bash

PCAP_FILENAME=WebRTC_OPUS_Turn_SDES_Call_1

SSRC_A=0x2D830E96
SSRC_B=0x2C2E32D2
SSTP_A=MRARr6H9Q9EBF9/VdqYFb8o5M0QOQTur0cuEC1b1
SSTP_B=tI9aHhxruvAz5BXk3k2VNNhOPbSATt5kxFOudCGR

ALG=AES_CM_128_HMAC_SHA1_80

../build/srtp_decoder ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true 2>&1 1>${PCAP_FILENAME}_A.log
../build/srtp_decoder ${PCAP_FILENAME}.pcap ./output/${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true 2>&1 1>${PCAP_FILENAME}_B.log
