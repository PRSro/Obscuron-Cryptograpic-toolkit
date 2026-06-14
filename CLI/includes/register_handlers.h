#pragma once
#include "context.h"

void register_basic_handlers(HandlerMap &map);
void register_essential_handlers(HandlerMap &map);
void register_historical_handlers(HandlerMap &map);
void register_standard_handlers(HandlerMap &map);
void register_outdated_handlers(HandlerMap &map);
void register_modern_handlers(HandlerMap &map);
void register_bruteforce_handlers(HandlerMap &map);
void register_bytes_handlers(HandlerMap &map);
void register_detector_handlers(HandlerMap &map);
void register_rsa_handlers(HandlerMap &map);
void register_attack_handlers(HandlerMap &map);
void register_tls_handlers(HandlerMap &map);
void chain_handler(const HandlerMap &map, const Context &ctx);

HandlerMap register_all_handlers();
