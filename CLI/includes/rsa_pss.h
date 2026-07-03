#ifndef RSA_PSS_H
#define RSA_PSS_H

#include <string>

bool rsa_pss_keygen(int bits,
                    std::string &n_hex, std::string &e_hex, std::string &d_hex,
                    std::string &error);

bool rsa_pss_sign(const std::string &message,
                  const std::string &n_hex, const std::string &d_hex,
                  int salt_len,
                  std::string &sig_hex,
                  std::string &error);

bool rsa_pss_verify(const std::string &message,
                    const std::string &n_hex, const std::string &e_hex,
                    const std::string &sig_hex,
                    int salt_len,
                    bool &valid,
                    std::string &error);

#endif
