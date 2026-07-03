#ifndef ECDSA_H
#define ECDSA_H

#include <string>

bool ecdsa_keygen(const std::string &curve_name,
                  std::string &d_hex,
                  std::string &Qx_hex, std::string &Qy_hex,
                  std::string &error);

bool ecdsa_sign(const std::string &message,
                const std::string &d_hex,
                const std::string &curve_name,
                std::string &r_hex, std::string &s_hex,
                std::string &error);

bool ecdsa_verify(const std::string &message,
                  const std::string &Qx_hex, const std::string &Qy_hex,
                  const std::string &r_hex, const std::string &s_hex,
                  const std::string &curve_name,
                  bool &valid,
                  std::string &error);

#endif
