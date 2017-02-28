set PCAP_FILENAME=tcp_call_02_03_client

set SSRC_A=0x1C090D13
set SSRC_B=0x1C090D15
set SSTP_A=ODQ3ODIxYTE1NTIxZDVhMGRmNjNiODMwN2M3ODdk
set SSTP_B=ZDExYzU2MjgxMDU1OGZhYzE2MTI4MTRlODZlMzlm

set ALG=AES_CM_128_HMAC_SHA1_80

..\win32_vs15\Debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_A.opus %SSRC_A% %SSTP_A% %ALG% true 2>&1 >%PCAP_FILENAME%_A.log
..\win32_vs15\Debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_B.opus %SSRC_B% %SSTP_B% %ALG% true 2>&1 >%PCAP_FILENAME%_B.log
