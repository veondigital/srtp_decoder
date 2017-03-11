set PCAP_FILENAME=wifi-tcp_to_3g_2_coturn_dump

set SSRC_A=0x34837DE1
set SSRC_B=0x34837DE3
set SSTP_A=YTU4OTQ5NGM2YjJiZTgxMmQ4MDgyZmQ4MThkZWE3
set SSTP_B=NmMwNTZkMjBjM2VhY2NhZTAyNzViYzJjOGFhNjA1

set ALG=AES_CM_128_HMAC_SHA1_80

..\win32_vs15\debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_A.opus %SSRC_A% %SSTP_A% %ALG% true 2>&1 > %PCAP_FILENAME%_A.log
..\win32_vs15\debug\srtp_decoder.exe -vl %PCAP_FILENAME%.pcap %PCAP_FILENAME%_B.opus %SSRC_B% %SSTP_B% %ALG% true 2>&1 > %PCAP_FILENAME%_B.log
