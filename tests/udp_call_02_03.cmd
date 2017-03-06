set PCAP_FILENAME_A=udp_call_02_03_client
set PCAP_FILENAME_B=udp_call_02_03_client

set SSRC_A=0x1C065362
set SSRC_B=0x1C065364
set SSTP_A=NjZiYTBmY2FmOGE2ZGU3MmVlMzM4ZDQ0OGVhMTI0
set SSTP_B=YTEzNjhhMTNmNWUxMjljZTg3MTEyNWQ2YTE2ODQ2

set ALG=AES_CM_128_HMAC_SHA1_80

..\win32_vs15\Debug\srtp_decoder.exe %PCAP_FILENAME_A%.pcap ..\output\%PCAP_FILENAME_A%.opus %SSRC_A% %SSTP_A% %ALG% true udp true 2>%PCAP_FILENAME_A%.err 1>%PCAP_FILENAME_A%.log
..\win32_vs15\Debug\srtp_decoder.exe %PCAP_FILENAME_B%.pcap ..\output\%PCAP_FILENAME_B%.opus %SSRC_B% %SSTP_B% %ALG% true udp true 2>%PCAP_FILENAME_B%.err 1>%PCAP_FILENAME_B%.log
