#!/bin/bash

ALG=AES_CM_128_HMAC_SHA1_80

test -f output || mkdir output

../build/srtp_decoder ./WebRTC_OPUS_Turn_SDES_Call_1.pcap ./output/WebRTC_OPUS_Turn_SDES_Call_1_A.opus 0x2D830E96 MRARr6H9Q9EBF9/VdqYFb8o5M0QOQTur0cuEC1b1 ${ALG} true
../build/srtp_decoder ./WebRTC_OPUS_Turn_SDES_Call_1.pcap ./output/WebRTC_OPUS_Turn_SDES_Call_1_B.opus 0x2C2E32D2 tI9aHhxruvAz5BXk3k2VNNhOPbSATt5kxFOudCGR ${ALG} true


