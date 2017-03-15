*SRTP decoder decodes WebRTC media streams and writes decoded payload into the
file*

*This tool:*
------------

-   decodes pcap (Packet Capture) formatted file

-   extracts RTP packets

-   filters packets by SSRC

-   decodes secure

-   write payload to output file

RTP can be packed in different way.
Supports stream: WebRTC, Regular SRTP, Turn Extensions.

Supports transport protocol: UDP and TCP

To store opus packets in a file, you need some kind of container format that
stores the packet boundaries. I am using https://www.opus-codec.org simple
container format.
Option: container[true/false] - switches on/off this feature.

### *Usage:*

srtp_decoder[.exe] [-lv] input_file output_file ssrc key sha container

\* input - input pcap file path (Not pcapng!!!, just pcap)

\* output - output pcm file path

\* ssrc - RTP stream identifier https://tools.ietf.org/html/rfc3550\#page-59 hex
with 0x prefix

\* sha - crypto suite name https://tools.ietf.org/html/rfc4568\#page-16

\* container - true/false see feature description above

Options:

\* -v \| --verbose - Print detail information about packets into stdout

\* -l \| --list - Show all rtp streams (experimental option)

### *Compiling:*

Linux/MAC

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ bash
git clone https://github.com/SteppeChange/srtp_decoder.git
cd srtp_decoder
git submodule init
git submodule update

cd docopt
mkdir build
cd build
cmake ..
make

cd ..
mkdir build
cd build
cmake ..
make

export PATH=`pwd`:"$PATH"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows (Visual Studio Community 2013/2015)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ bash
git clone https://github.com/SteppeChange/srtp_decoder.git
cd srtp_decoder
git submodule init
git submodule update

unzip .\win32_vs15\WpdPack_4_1_2.zip

.\prepare_build_win.cmd
.\libsrtp\srtp.sln

.\prepare_build_win.cmd
.\win32_vs15\srtp_decoder.sln
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

### *Prerequrements linux/mac*

install libsrtp (https://github.com/cisco/libsrtp or https://github.com/dozeo/libsrtp)
install libpcap

### *Prerequrements windows*

libsrtp https://github.com/cisco/libsrtp
winpcap https://www.winpcap.org/devel.htm

### *How to play pcm*

http://www.audacityteam.org/
File-\>Import-\>Raw data-\> A-Law:Little-Endian:1 Channel(Mono):0:100:8000Hz

### *How to play OPUS*

https://www.opus-codec.org
curl http://downloads.xiph.org/releases/opus/opus-1.1.3.tar.gz -o opus.tar.gz
tar -xvf ./opus.tar.gz
cd opus-1.1.3/
./configure
make

use opus_demo for converting OPUS payload to PCM:
./opus_demo -d 48000 1 payloadfile pcmfile

play pcmfile by audacity
File-\>Import-\>Raw data-\> PCM 16 bit 48000Hz

### *SDES/DTLS srtp*

TO DO How to extract SEDS key/crypto from SDP
TO DO How to extract DTLS key/crypto from browser logs
