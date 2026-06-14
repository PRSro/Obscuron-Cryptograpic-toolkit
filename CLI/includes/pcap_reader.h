#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <string>
#include <vector>
#include <cstdint>

struct PcapPacket {
    std::vector<uint8_t> data;
};

struct TlsRecord {
    uint8_t content_type;
    uint16_t version;
    std::vector<uint8_t> fragment;
};

struct TlsSession {
    std::vector<uint8_t> client_random;
    std::vector<uint8_t> server_random;
    std::vector<uint8_t> master_key;
    uint16_t cipher_suite;
};

bool read_pcap(const std::string &path, std::vector<PcapPacket> &packets, std::string &error);
bool extract_tls_records(const std::vector<PcapPacket> &packets, std::vector<TlsRecord> &records, std::string &error);
bool extract_tls_sessions(const std::vector<PcapPacket> &packets, std::vector<TlsSession> &sessions, std::string &error);
bool load_keylog(const std::string &path, std::vector<TlsSession> &sessions, std::string &error);
bool tls_decrypt_application_data(const std::vector<TlsRecord> &records, const TlsSession &session, std::string &output, std::string &error);

#endif
