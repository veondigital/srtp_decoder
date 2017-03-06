set PCAP_FILENAME_A=tcp_call_02_03_client_s1
set PCAP_FILENAME_B=tcp_call_02_03_client_s2

set SSRC_A=0x1C090D13
set SSRC_B=0x1C090D15
set SSTP_A=ODQ3ODIxYTE1NTIxZDVhMGRmNjNiODMwN2M3ODdk
set SSTP_B=ZDExYzU2MjgxMDU1OGZhYzE2MTI4MTRlODZlMzlm

set ALG=AES_CM_128_HMAC_SHA1_80

..\win32_vs15\Debug\srtp_decoder.exe %PCAP_FILENAME_A%.pcap ..\output\%PCAP_FILENAME_A%.opus %SSRC_A% %SSTP_A% %ALG% true tcp true 2>%PCAP_FILENAME_A%.err 1>%PCAP_FILENAME_A%.log
..\win32_vs15\Debug\srtp_decoder.exe %PCAP_FILENAME_B%.pcap ..\output\%PCAP_FILENAME_B%.opus %SSRC_B% %SSTP_B% %ALG% true tcp true 2>%PCAP_FILENAME_B%.err 1>%PCAP_FILENAME_B%.log
