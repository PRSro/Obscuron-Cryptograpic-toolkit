#ifndef EDDSA_H
#define EDDSA_H

#include <string>

bool ed25519_keygen(std::string &priv_hex, std::string &pub_hex,
                    std::string &error);

bool ed25519_sign(const std::string &message,
                  const std::string &priv_hex,
                  std::string &sig_hex,
                  std::string &error);

bool ed25519_verify(const std::string &message,
                    const std::string &pub_hex,
                    const std::string &sig_hex,
                    bool &valid,
                    std::string &error);

#endif
