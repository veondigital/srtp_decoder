// srtp_decoder.cpp : Defines the entry point for the console application.
//

#include "srtp_decoder.h"
#include "decoder.h"
#include "base64.h"
#include "pcap.h"

#include <string>
#include <iostream>
#include <cassert>

#include "docopt/docopt.h"
#include "pcap_reader.h"

// example key_params: "YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2"
static bool ParseKeyParams(const std::string& key_params, uint8_t* key, int len)
{
	// Fail if base64 decode fails, or the key is the wrong size.
	std::string key_b64(key_params), key_str;
	if (!Base64::Decode(key_b64, Base64::DO_STRICT, &key_str, NULL) ||
			static_cast<int>(key_str.size()) != len) {
		std::cerr << "ERROR: Bad master key encoding, cant unbase64" << std::endl;
		throw std::runtime_error("SRTP fails");
		return false;
	}
	memcpy(key, key_str.c_str(), len);
	return true;
}

static int SrtpCryptoSuiteFromName(const std::string& crypto_suite)
{
	if (crypto_suite == CS_AES_CM_128_HMAC_SHA1_32)
		return SRTP_AES128_CM_SHA1_32;
	if (crypto_suite == CS_AES_CM_128_HMAC_SHA1_80)
		return SRTP_AES128_CM_SHA1_80;
	return SRTP_INVALID_CRYPTO_SUITE;
}

static void int_to_char(unsigned int i, unsigned char ch[4])
{
	ch[0] = i >> 24;
	ch[1] = (i >> 16) & 0xFF;
	ch[2] = (i >> 8) & 0xFF;
	ch[3] = i & 0xFF;
}

static const char USAGE[] =
R"(srtp_decoder

    Usage:
        srtp_decoder [-v] <input_tcpdump_pcap_path> <output_decoded_payload_path> <ssrc_into_rtp_hex_format> <Base64_master_key> <sha_Crypto_Suite> <container>
        srtp_decoder [-v] -l <input_tcpdump_pcap_path>
        srtp_decoder (-h | --help)
        srtp_decoder --version

    Options:
        -l --list     Show all rtp streams information.
        -v --verbose  Verbose output.
        -h --help     Show this screen.
        --version     Show version.

    Examples:
        srtp_decoder ./tests/pcma.pcap ./tests/pcma.payload 0xdeadbeef aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz AES_CM_128_HMAC_SHA1_80 false
        srtp_decoder ./tests/webrtc_opus_p2p.pcap ./tests/output/webrtc_opus_p2p.payload 0x20C23467 FfLxRxclZ/lNM/g5MNSZgmvAUzR/pgSIVyOHUHji AES_CM_128_HMAC_SHA1_80 true
)";

int main(int argc, char* argv[])
{
	std::map<std::string, docopt::value> args = docopt::docopt(USAGE, { argv + 1, argv + argc }, true, VERSION);
#ifdef _DEBUG
	for (auto const& arg : args) {
		std::cout << arg.first << ": " << arg.second << std::endl;
	}
	std::cout << std::endl;
#endif
	global_params params;
	params.filter = "udp or tcp";
	params.verbose = false;

	auto get_arg = [&args](const char *name) {
		if (args[name])
			return args[name].asString();
		return std::string("");
	};

	std::string input_path = get_arg("<input_tcpdump_pcap_path>");
	std::string output_path = get_arg("<output_decoded_payload_path>");
	std::string ssrc_str = get_arg("<ssrc_into_rtp_hex_format>");
	std::string keyBase64 = get_arg("<Base64_master_key>");
	std::string sha = get_arg("<sha_Crypto_Suite>");
	params.ssrc = strtoul(ssrc_str.c_str(), 0, 16);
	bool container = false;
	if (args["<container>"])
		container = args["<container>"].asString() == std::string("true");
	bool show_all_streams_info = false;
	show_all_streams_info = args["--list"].asBool();
	params.verbose = args["--verbose"].asBool();

	std::cout << "pcap file: " << input_path << std::endl;
	std::cout << "payload file: " << output_path << std::endl;
	std::cout << "32-bit SSRC identifier: 0x" << std::hex << params.ssrc << std::dec << std::endl;
	std::cout << "AES Base64 crypto key: " << keyBase64 << std::endl;
	std::cout << "crypto-suite: " << sha << std::endl;
	std::cout << "payload packaging: " << (container ? "true" : "false") << std::endl;
	std::cout << "tcpdump filter expression: " << params.filter << std::endl;
	std::cout << std::endl;

	try {
		if (!read_pcap(input_path, params)) {
			return 1;
		}
#ifdef DETECT_ALL_RTP_STREAMS
		if (show_all_streams_info) {
			// produce CSV-file
			std::string csv_path = input_path;
			auto pos = csv_path.find_last_of('.');
			if (pos != csv_path.npos) {
				csv_path.replace(pos+1, csv_path.npos, "csv");
			} else {
				csv_path.append(".csv");
			}
			do {
				FILE *csv_file = fopen(csv_path.c_str(), "wt");
				if (!csv_file) {
					std::cerr << "Can't open file: " << csv_path << std::endl;
					break;
				}
				fprintf(csv_file, "begin_timestamp,end_timestamp,ssrc,src_addr,dest_addr,proto,rtp_type,packets\n");
				if (params.verbose)
					std::cout << "=== RTP STREAMS INFO ===" << std::endl;
				for (auto &ri : params.srtp_streams) {
					if (ri.second.packets == 1)
						continue;
# ifdef WIN32
					fprintf(csv_file, "%llu,%llu,0x%x,%d.%d.%d.%d:%d,%d.%d.%d.%d:%d,%s,%d,%d\n",
# else
					fprintf(csv_file, "%lu,%lu,0x%x,%d.%d.%d.%d:%d,%d.%d.%d.%d:%d,%s,%d,%d\n",
# endif
						ri.second.first_ts, ri.second.last_ts, ri.second.ssrc,
						ri.second.src_addr.byte1, ri.second.src_addr.byte2, ri.second.src_addr.byte3, ri.second.src_addr.byte4, ri.second.src_port,
						ri.second.dst_addr.byte1, ri.second.dst_addr.byte2, ri.second.dst_addr.byte3, ri.second.dst_addr.byte4, ri.second.dst_port,
						ri.second.udp ? "udp" : "tcp", ri.second.pt, ri.second.packets);

					if (params.verbose) {
# ifdef WIN32
						printf("Found %06d RTP packets: ssrc: 0x%x, first_ts: %llu, last_ts: %llu\n",
# else
						printf("Found %06d RTP packets: ssrc: 0x%x, first_ts: %lu, last_ts: %lu\n",
# endif
								ri.second.packets, ri.second.ssrc, ri.second.first_ts, ri.second.last_ts);
					}
				}
				fclose(csv_file);
				if (params.verbose)
					std::cout << "=== RTP STREAMS INFO ===" << std::endl << std::endl;

				std::cout << "Output file produced: " << csv_path << std::endl;
			} while (false);

			return 0;
		}
#endif

#ifdef WIN32
		printf("Found %lu RTP packets: ssrc: 0x%x, first_ts: %llu, last_ts: %llu\n",
#else
		printf("Found %lu RTP packets: ssrc: 0x%x, first_ts: %lu, last_ts: %lu\n",
#endif
			params.srtp_stream.size(), params.ssrc, params.first_ts, params.last_ts);

		SrtpSession srtp_decoder;
		srtp_decoder.Init();
		uint8_t recv_key[SRTP_MASTER_KEY_LEN];
		bool res = ParseKeyParams(keyBase64, recv_key, sizeof(recv_key));
		if (res) {
			res = srtp_decoder.SetRecv(SrtpCryptoSuiteFromName(sha), recv_key, sizeof(recv_key));
		}

		std::ofstream payload_file(output_path.c_str(), std::ofstream::out | std::ofstream::binary);
		auto count = 0;

		for (auto &i: params.srtp_stream) {
			int rtp_length = 0;
			unsigned char *srtp_buffer = i.data();
			int length = i.size();

			bool res = srtp_decoder.UnprotectRtp(srtp_buffer, length, &rtp_length);
			if (!res) {
				common_rtp_hdr_t *hdr = (common_rtp_hdr_t *)srtp_buffer;
				std::cerr << " - seq=" << htons(hdr->seq) << std::endl;
				continue;
			}

			common_rtp_hdr_t *hdr = (common_rtp_hdr_t *)srtp_buffer;
			int rtp_header_size = sizeof(common_rtp_hdr_t);
			unsigned char* payload = srtp_buffer + rtp_header_size;
			if (params.verbose)
				std::cout << "decrypt packet - seq=" << htons(hdr->seq) << std::endl;
			// has extension 
			if (hdr->x) {
				// If the X bit in the RTP header is one, a variable - length header
				// extension MUST be appended to the RTP header, following the CSRC list if present.
				common_rtp_hdr_ex_t* hdr_ex = (common_rtp_hdr_ex_t *)payload;
				payload += sizeof(common_rtp_hdr_ex_t);

				// calculate extensions RFC5285
				int number_of_extensions = htons(hdr_ex->extension_len);
				for (int n = 0; n < number_of_extensions; n++) {
					rtp_hdr_ex5285_t* h5285 = (rtp_hdr_ex5285_t*)payload;
					payload += sizeof(rtp_hdr_ex5285_t) + h5285->extension_len;
				}

				// There are as many
				// extension elements as fit into the length as indicated in the RTP
				// header extension length.Since this length is signaled in full 32 -
				// bit words, padding bytes are used to pad to a 32 - bit boundary.
				int extension_size = payload - srtp_buffer;
				int padding = extension_size % 4;
				payload += padding;
			}

			rtp_header_size = payload - srtp_buffer;
			++count;
			size_t frame_size = rtp_length - rtp_header_size;

			if (container) {
				unsigned char sz[4];
				int_to_char(frame_size, sz);
				payload_file.write(reinterpret_cast<char*>(&sz[0]), 4);
				int_to_char(0, sz);
				payload_file.write(reinterpret_cast<char*>(&sz[0]), 4);
			}
			// The array may contain null characters, which are also copied without stopping the copying process.
			payload_file.write(reinterpret_cast<char*>(payload), frame_size);
		}
		payload_file.close();
		std::cout << "Wrote " << count << " payload chunks" << std::endl << std::endl;
		srtp_decoder.Terminate();
	}
	catch (std::exception const& err) {
		std::cerr << "Terminate: " << err.what() << std::endl;
		return 1;
	}
	return 0;
}

