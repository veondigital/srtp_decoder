set PCAP_FILENAME=udp_call_02_03_client

set SSRC_A=0x1C065362
set SSRC_B=0x1C065364
set SSTP_A=NjZiYTBmY2FmOGE2ZGU3MmVlMzM4ZDQ0OGVhMTI0
set SSTP_B=YTEzNjhhMTNmNWUxMjljZTg3MTEyNWQ2YTE2ODQ2

set ALG=AES_CM_128_HMAC_SHA1_80

..\win32_vs15\Debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_A.opus %SSRC_A% %SSTP_A% %ALG% true 2>&1 >%PCAP_FILENAME%_A.log
..\win32_vs15\Debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_B.opus %SSRC_B% %SSTP_B% %ALG% true 2>&1 >%PCAP_FILENAME%_B.log
