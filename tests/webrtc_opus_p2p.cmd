set PCAP_FILENAME=webrtc_opus_p2p

set SSRC_A=0x20C23467
set SSRC_B=0x2C2E32D2
set SSTP_A=FfLxRxclZ/lNM/g5MNSZgmvAUzR/pgSIVyOHUHji
set SSTP_B=tI9aHhxruvAz5BXk3k2VNNhOPbSATt5kxFOudCGR

set ALG=AES_CM_128_HMAC_SHA1_80

..\win32_vs15\Debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_A.opus %SSRC_A% %SSTP_A% %ALG% true 2>&1 >%PCAP_FILENAME%_A.log
..\win32_vs15\Debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_B.opus %SSRC_B% %SSTP_B% %ALG% true 2>&1 >%PCAP_FILENAME%_B.log

