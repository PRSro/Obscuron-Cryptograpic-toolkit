#include "../includes/pcap_reader.h"
#include "../includes/modern_ciphers.h"
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>

static bool hex_to_raw(const std::string &hex, std::vector<uint8_t> &out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        if (sscanf(hex.c_str() + i, "%02x", &byte) != 1) return false;
        out.push_back((uint8_t)byte);
    }
    return true;
}

struct PcapGlobalHeader {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

bool read_pcap(const std::string &path, std::vector<PcapPacket> &packets, std::string &error) {
    packets.clear();
    std::ifstream f(path, std::ios::binary);
    if (!f) { error = "Cannot open " + path; return false; }

    PcapGlobalHeader gh;
    f.read((char*)&gh, sizeof(gh));
    if (!f) { error = "Truncated pcap global header"; return false; }

    bool swap = false;
    if (gh.magic == 0xd4c3b2a1) swap = true;
    else if (gh.magic != 0xa1b2c3d4) { error = "Not a pcap file"; return false; }

    while (true) {
        PcapPacketHeader ph;
        f.read((char*)&ph, sizeof(ph));
        if (!f) break;

        uint32_t incl_len = ph.incl_len;
        if (swap) {
            uint8_t *p = (uint8_t*)&incl_len;
            incl_len = (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
        }
        if (incl_len > 65535) break;

        std::vector<uint8_t> buf(incl_len);
        f.read((char*)buf.data(), incl_len);
        if (!f) break;

        PcapPacket pkt;
        pkt.data = std::move(buf);
        packets.push_back(std::move(pkt));
    }
    return true;
}

// Skip Ethernet header (14 bytes), parse IPv4, skip IP hdr, parse TCP
static bool extract_tcp_payload(const std::vector<uint8_t> &pkt, std::vector<uint8_t> &payload) {
    payload.clear();
    if (pkt.size() < 14) return false;

    size_t off = 14;
    uint16_t ethertype = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (ethertype == 0x8100) { // VLAN
        off += 4;
        if (off + 2 > pkt.size()) return false;
        ethertype = ((uint16_t)pkt[off - 2] << 8) | pkt[off - 1];
    }
    if (ethertype != 0x0800) return false; // IPv4 only

    if (off + 20 > pkt.size()) return false;
    uint8_t ip_ver_ihl = pkt[off];
    uint8_t ihl = ip_ver_ihl & 0x0F;
    size_t ip_hdr_len = ihl * 4;
    if (ip_hdr_len < 20 || off + ip_hdr_len > pkt.size()) return false;

    uint8_t protocol = pkt[off + 9];
    if (protocol != 6) return false; // TCP only

    size_t tcp_off = off + ip_hdr_len;
    if (tcp_off + 20 > pkt.size()) return false;
    uint8_t data_offset = (pkt[tcp_off + 12] >> 4) & 0x0F;
    size_t tcp_hdr_len = data_offset * 4;
    if (tcp_hdr_len < 20 || tcp_off + tcp_hdr_len > pkt.size()) return false;

    size_t data_start = tcp_off + tcp_hdr_len;
    if (data_start >= pkt.size()) return false;
    payload.assign(pkt.begin() + data_start, pkt.end());
    return true;
}

bool extract_tls_records(const std::vector<PcapPacket> &packets, std::vector<TlsRecord> &records, std::string &error) {
    records.clear();
    if (packets.empty()) { error = "No packets provided"; return false; }
    for (const auto &pkt : packets) {
        std::vector<uint8_t> tcp_payload;
        if (!extract_tcp_payload(pkt.data, tcp_payload)) continue;
        if (tcp_payload.empty()) continue;

        size_t off = 0;
        while (off + 5 <= tcp_payload.size()) {
            uint8_t ct = tcp_payload[off];
            // TLS content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=AppData
            if (ct < 20 || ct > 23) break;

            uint16_t version = ((uint16_t)tcp_payload[off+1] << 8) | tcp_payload[off+2];
            uint16_t length  = ((uint16_t)tcp_payload[off+3] << 8) | tcp_payload[off+4];
            if (off + 5 + length > tcp_payload.size()) break;

            TlsRecord rec;
            rec.content_type = ct;
            rec.version = version;
            rec.fragment.assign(tcp_payload.begin() + off + 5, tcp_payload.begin() + off + 5 + length);
            records.push_back(rec);
            off += 5 + length;
        }
    }
    return !records.empty();
}

bool extract_tls_sessions(const std::vector<PcapPacket> &packets, std::vector<TlsSession> &sessions, std::string &error) {
    std::vector<TlsRecord> records;
    if (!extract_tls_records(packets, records, error)) return false;

    for (const auto &rec : records) {
        if (rec.content_type != 22) continue; // Handshake
        const auto &frag = rec.fragment;
        if (frag.empty()) continue;

        // Handshake header: type(1) + length(3)
        size_t off = 0;
        while (off + 4 <= frag.size()) {
            uint8_t hs_type = frag[off];
            uint32_t hs_len = ((uint32_t)frag[off+1] << 16) | ((uint32_t)frag[off+2] << 8) | frag[off+3];
            if (off + 4 + hs_len > frag.size()) break;

            if (hs_type == 1 && hs_len >= 38) { // ClientHello
                TlsSession sess;
                uint32_t random_offset = off + 4 + 2; // skip client_version (2)
                if (random_offset + 32 > frag.size()) break;
                sess.client_random.assign(frag.begin() + random_offset, frag.begin() + random_offset + 32);
                sessions.push_back(sess);
            } else if (hs_type == 2 && hs_len >= 38) { // ServerHello
                if (sessions.empty()) { off += 4 + hs_len; continue; }
                TlsSession &sess = sessions.back();
                uint32_t random_offset = off + 4 + 2; // skip server_version (2)
                if (random_offset + 32 > frag.size()) break;
                sess.server_random.assign(frag.begin() + random_offset, frag.begin() + random_offset + 32);
                // Skip random + session_id + cipher_suite
                uint32_t cipher_off = random_offset + 32;
                if (cipher_off + 1 > frag.size()) break;
                uint8_t sess_id_len = frag[cipher_off];
                uint32_t suite_off = cipher_off + 1 + sess_id_len;
                if (suite_off + 2 > frag.size()) break;
                sess.cipher_suite = ((uint16_t)frag[suite_off] << 8) | frag[suite_off + 1];
            }
            off += 4 + hs_len;
        }
    }

    // Remove sessions with no server_random
    sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
        [](const TlsSession &s) { return s.server_random.empty(); }), sessions.end());
    return !sessions.empty();
}

bool load_keylog(const std::string &path, std::vector<TlsSession> &sessions, std::string &error) {
    std::ifstream f(path);
    if (!f) { error = "Cannot open " + path; return false; }

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;

        // CLIENT_RANDOM <hex_64> <hex_96>
        if (line.find("CLIENT_RANDOM ") != 0) continue;

        std::string rest = line.substr(14);
        std::stringstream ss(rest);
        std::string client_rand_hex, master_key_hex;
        ss >> client_rand_hex >> master_key_hex;
        if (client_rand_hex.size() != 64 || master_key_hex.size() != 96) continue;

        std::vector<uint8_t> cr, mk;
        if (!hex_to_raw(client_rand_hex, cr) || cr.size() != 32) continue;
        if (!hex_to_raw(master_key_hex, mk) || mk.size() != 48) continue;

        TlsSession sess;
        sess.client_random = cr;
        sess.master_key = mk;
        sessions.push_back(sess);
    }
    return !sessions.empty();
}

// TLS 1.2 PRF using P_SHA256
static void tls_prf(const std::vector<uint8_t> &secret,
                    const std::string &label,
                    const std::vector<uint8_t> &seed,
                    size_t out_len,
                    std::vector<uint8_t> &output)
{
    std::string secret_str((const char*)secret.data(), secret.size());
    std::string seed_str((const char*)seed.data(), seed.size());
    std::string label_str = label;
    std::string label_seed_str = label_str + seed_str;

    output.clear();
    std::string a_str = label_seed_str;
    while (output.size() < out_len) {
        // A(i) = HMAC_SHA256(secret, A(i-1))
        std::string a_hex;
        hmac_sha256(a_str, secret_str, a_hex);
        a_str = from_hex(a_hex);

        // HMAC_SHA256(secret, A(i) + seed)
        std::string block_hex;
        hmac_sha256(a_str + label_seed_str, secret_str, block_hex);
        std::string block_raw = from_hex(block_hex);
        output.insert(output.end(), block_raw.begin(), block_raw.end());
    }
    output.resize(out_len);
}

// Derive key block from master_secret + client_random + server_random
// AES-128-CBC with SHA256:  client_write_MAC(32) + server_write_MAC(32) + client_write_key(16) + server_write_key(16) + client_write_IV(16) + server_write_IV(16) = 128 bytes
// AES-256-CBC with SHA256:  client_write_MAC(32) + server_write_MAC(32) + client_write_key(32) + server_write_key(32) + client_write_IV(16) + server_write_IV(16) = 160 bytes
static bool derive_keys(const TlsSession &session,
                        std::vector<uint8_t> &client_key,
                        std::vector<uint8_t> &server_key,
                        std::vector<uint8_t> &client_iv,
                        std::vector<uint8_t> &server_iv,
                        size_t key_len, size_t iv_len,
                        std::string &error)
{
    if (session.master_key.empty()) {
        error = "No master key available";
        return false;
    }
    if (session.client_random.empty() || session.server_random.empty()) {
        error = "Missing client or server random";
        return false;
    }

    std::vector<uint8_t> seed = session.server_random;
    seed.insert(seed.end(), session.client_random.begin(), session.client_random.end());
    size_t mac_len = 32; // SHA-256 MAC length
    size_t block_len = mac_len * 2 + key_len * 2 + iv_len * 2;

    std::vector<uint8_t> key_block;
    tls_prf(session.master_key, "key expansion", seed, block_len, key_block);

    size_t off = 0;
    // Skip MAC keys
    off += mac_len * 2;
    // Read client write key
    client_key.assign(key_block.begin() + off, key_block.begin() + off + key_len);
    off += key_len;
    // Read server write key
    server_key.assign(key_block.begin() + off, key_block.begin() + off + key_len);
    off += key_len;
    // Read IVs
    client_iv.assign(key_block.begin() + off, key_block.begin() + off + iv_len);
    off += iv_len;
    server_iv.assign(key_block.begin() + off, key_block.begin() + off + iv_len);
    return true;
}

// Remove TLS CBC padding (PKCS#7)
static std::string strip_pkcs7_padding(const std::string &data) {
    if (data.empty()) return data;
    uint8_t pad = (uint8_t)data.back();
    if (pad == 0 || pad > 16) return data;
    // Verify all padding bytes
    for (int i = 0; i < pad; i++) {
        if ((uint8_t)data[data.size() - 1 - i] != pad) return data;
    }
    return data.substr(0, data.size() - pad);
}

bool tls_decrypt_application_data(const std::vector<TlsRecord> &records,
                                   const TlsSession &session,
                                   std::string &output,
                                   std::string &error)
{
    output.clear();

    // Determine cipher suite parameters
    size_t key_len = 16, iv_len = 16;
    bool is_gcm = false;
    switch (session.cipher_suite) {
        case 0x002F: // TLS_RSA_WITH_AES_128_CBC_SHA
        case 0x0033: // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        case 0x003C: // TLS_RSA_WITH_AES_128_CBC_SHA256
            key_len = 16; iv_len = 16; is_gcm = false; break;
        case 0x0035: // TLS_RSA_WITH_AES_256_CBC_SHA
        case 0x003D: // TLS_RSA_WITH_AES_256_CBC_SHA256
            key_len = 32; iv_len = 16; is_gcm = false; break;
        case 0x009C: // TLS_RSA_WITH_AES_128_GCM_SHA256
        case 0x009D: // TLS_RSA_WITH_AES_256_GCM_SHA384
            key_len = 16; iv_len = 4; is_gcm = true; break;
        default:
            // Default to AES-128-CBC
            key_len = 16; iv_len = 16; break;
    }

    std::vector<uint8_t> client_key, server_key, client_iv, server_iv;
    if (!derive_keys(session, client_key, server_key, client_iv, server_iv,
                     key_len, iv_len, error))
        return false;

    if (is_gcm) {
        // TLS 1.2 AES-GCM: nonce = implicit_nonce(4) + explicit_nonce(8)
        for (const auto &rec : records) {
            if (rec.content_type != 23) continue;
            if (rec.fragment.size() < 8 + 16) continue;

            std::string ct_raw((const char*)rec.fragment.data() + 8,
                               rec.fragment.size() - 8 - 16);
            std::string tag_raw((const char*)rec.fragment.data() + rec.fragment.size() - 16, 16);
            std::string explicit_nonce((const char*)rec.fragment.data(), 8);

            // AES-GCM nonce = client_iv(4) || explicit_nonce(8)
            std::string nonce((const char*)client_iv.data(), 4);
            nonce += explicit_nonce;

            // Use CTR mode for AES-GCM (CTR decrypt = encrypt in AES-GCM)
            std::string plaintext;
            aes_decrypt(ct_raw,
                        std::string((const char*)client_key.data(), client_key.size()),
                        nonce, 2, plaintext, false);
            output += plaintext;
        }
        return !output.empty();
    }

    // CBC mode
    for (const auto &rec : records) {
        if (rec.content_type != 23) continue;
        if (rec.fragment.size() < 16) continue;

        std::string ct((const char*)rec.fragment.data(), rec.fragment.size());
        std::string plaintext;
        if (!aes_decrypt(ct,
                         std::string((const char*)client_key.data(), client_key.size()),
                         std::string((const char*)client_iv.data(), client_iv.size()),
                         1, plaintext, false))
        {
            // Try server key
            if (!aes_decrypt(ct,
                             std::string((const char*)server_key.data(), server_key.size()),
                             std::string((const char*)server_iv.data(), server_iv.size()),
                             1, plaintext, false))
                continue;
        }
        // Strip MAC and padding
        if (plaintext.size() < 32) continue; // need at least HMAC-SHA256 (32)
        plaintext = strip_pkcs7_padding(plaintext);
        if (plaintext.size() < 32) continue;
        plaintext.resize(plaintext.size() - 32); // strip MAC
        output += plaintext;
    }
    return !output.empty();
}
