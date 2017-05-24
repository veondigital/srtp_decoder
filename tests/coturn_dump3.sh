#!/bin/bash

PCAP_FILE="./coturn_dump3"

SSRC_A="274DA398"
SSRC_B="274DA39A"
SSTP_A="NjU4ZDRiMjI1MmEyMDgxYzU3MmFmZTA5ZTI5MDZk"
SSTP_B="YzA0NmZhYTgwMDJmODcwYmFmNDhjOWI2ODhhZDdj"

../cmake-build-debug/srtp_decoder -l -v -f ${PCAP_FILE}.pcap -e "tcp or udp" -s ${SSRC_A} 2>&1 > ${PCAP_FILE}.txt

../cmake-build-debug/srtp_decoder -v -f ${PCAP_FILE}.pcap -o ${PCAP_FILE}_A.payload -s ${SSRC_A} -k ${SSTP_A} -r AES_CM_128_HMAC_SHA1_80 -c true -e "tcp" 2>&1 > ${PCAP_FILE}_A.txt
#./bin/opus_demo -d 48000 1 ayload ${PCAP_FILE}_A.pcm

#../cmake-build-debug/srtp_decoder -f ${PCAP_FILE}.pcap -o ${PCAP_FILE}_B.payload -s ${SSRC_B} -k ${SSTP_B} -r AES_CM_128_HMAC_SHA1_80 -c true
#./bin/opus_demo -d 48000 1 ${PCAP_FILE}_B.payload ${PCAP_FILE}_B.pcm
