#!/bin/bash

PCAP_FILENAME=webrtc_opus_p2p

SSRC_A=0x20C23467
SSRC_B=0x2C2E32D2
SSTP_A=FfLxRxclZ/lNM/g5MNSZgmvAUzR/pgSIVyOHUHji
SSTP_B=tI9aHhxruvAz5BXk3k2VNNhOPbSATt5kxFOudCGR

ALG=AES_CM_128_HMAC_SHA1_80

../.build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ${PCAP_FILENAME}_A.opus ${SSRC_A} ${SSTP_A} ${ALG} true 2>&1 > ${PCAP_FILENAME}_A.log
../.build/srtp_decoder -vl ${PCAP_FILENAME}.pcap ${PCAP_FILENAME}_B.opus ${SSRC_B} ${SSTP_B} ${ALG} true 2>&1 > ${PCAP_FILENAME}_B.log

