#include "../includes/register_handlers.h"
#include "../includes/modern_ciphers.h"
#include "../includes/pcap_reader.h"
#include <fstream>

void register_tls_handlers(HandlerMap &map) {
    map["tls-fingerprint"] = [](const Context &ctx) {
        TlsFingerprint fp = tls_fingerprint(ctx.input);
        std::cout << "Version:       " << fp.version << "\n";
        std::cout << "Key Exchange:  " << fp.key_exchange << "\n";
        std::cout << "Cipher:        " << fp.cipher << "\n";
        std::cout << "MAC:           " << fp.mac << "\n";
        if (fp.key_bits > 0) std::cout << "Key Bits:      " << fp.key_bits << "\n";
        std::cout << "PEM:           " << (fp.is_pem ? "yes" : "no") << "\n";
        std::cout << "DER:           " << (fp.is_der ? "yes" : "no") << "\n";
        if (fp.has_pkcs1_padding) std::cout << "PKCS#1:        yes\n";
        if (!fp.risk_flags.empty()) {
            std::cout << "Risk Flags:    \n";
            for (const auto &rf : fp.risk_flags)
                std::cout << "  - " << rf << "\n";
        }
        if (!fp.suggested_attack.empty())
            std::cout << "Suggested:     " << fp.suggested_attack << "\n";
    };

    map["parse-cert"] = [](const Context &ctx) {
        CertInfo ci = parse_certificate(ctx.input);
        if (ci.subject_cn.empty() && ci.subject_o.empty() && ci.serial_hex.empty()) {
            std::cout << "Unable to parse certificate (unsupported format)\n";
            return;
        }
        std::cout << "Subject CN:    " << ci.subject_cn << "\n";
        std::cout << "Subject O:     " << ci.subject_o << "\n";
        std::cout << "Issuer:        " << ci.issuer << "\n";
        std::cout << "Valid From:    " << ci.valid_from << "\n";
        std::cout << "Valid Until:   " << ci.valid_until << "\n";
        std::cout << "Serial:        " << ci.serial_hex << "\n";
        std::cout << "Pubkey Algo:   " << ci.pubkey_algo << "\n";
        if (ci.pubkey_bits > 0) std::cout << "Pubkey Bits:   " << ci.pubkey_bits << "\n";
        std::cout << "SHA-256 FP:    " << ci.sha256_fingerprint << "\n";
        std::cout << "Self-Signed:   " << (ci.is_self_signed ? "yes" : "no") << "\n";
        if (!ci.modulus_hex.empty())
            std::cout << "Modulus:       " << ci.modulus_hex << "\n";
        if (!ci.exponent_hex.empty())
            std::cout << "Exponent:      " << ci.exponent_hex << "\n";
        if (!ci.san_entries.empty()) {
            std::cout << "SAN Entries:\n";
            for (const auto &san : ci.san_entries)
                std::cout << "  - " << san << "\n";
        }
        if (!ci.key_usage.empty()) {
            std::cout << "Key Usage:\n";
            for (const auto &ku : ci.key_usage)
                std::cout << "  - " << ku << "\n";
        }
    };

    map["tls-decode"] = [](const Context &ctx) {
        std::string pcap_path = ctx.input;
        std::string keylog_path = ctx.opt_flag("--keylog", "");

        std::vector<PcapPacket> packets;
        std::vector<TlsRecord> records;
        std::vector<TlsSession> sessions;
        std::string error;

        if (!read_pcap(pcap_path, packets, error)) {
            std::cerr << "pcap error: " << error << "\n";
            return;
        }
        std::cout << "Packets: " << packets.size() << "\n";

        if (!keylog_path.empty()) {
            std::vector<TlsSession> kl;
            if (load_keylog(keylog_path, kl, error))
                sessions = kl;
            else
                std::cerr << "keylog warning: " << error << "\n";
        }

        if (!extract_tls_records(packets, records, error)) {
            std::cerr << "tls error: " << error << "\n";
            return;
        }
        std::cout << "TLS records: " << records.size() << "\n";

        std::vector<TlsSession> hs_sessions;
        if (extract_tls_sessions(packets, hs_sessions, error))
            std::cout << "Handshakes: " << hs_sessions.size() << "\n";

        // Merge keylog master keys into handshake sessions
        for (auto &hs : hs_sessions) {
            for (const auto &kl : sessions) {
                if (kl.client_random == hs.client_random)
                    hs.master_key = kl.master_key;
            }
        }

        int app_data = 0, decrypted = 0;
        for (auto &sess : hs_sessions) {
            if (sess.master_key.empty()) continue;
            std::string output;
            if (tls_decrypt_application_data(records, sess, output, error)) {
                std::cout << "--- Decrypted " << output.size() << " bytes ---\n";
                bool printable = true;
                for (unsigned char ch : output) {
                    if (ch < 32 && ch != '\n' && ch != '\r' && ch != '\t') {
                        printable = false; break;
                    }
                }
                if (printable) std::cout << output << "\n";
                else std::cout << "(hex) " << to_hex((const uint8_t*)output.data(), output.size()) << "\n";
                decrypted++;
            }
        }
        if (decrypted == 0)
            std::cout << "No application data decrypted. Provide --keylog with matching session keys.\n";
    };
}
