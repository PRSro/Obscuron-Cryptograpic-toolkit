#include "../includes/register_handlers.h"

HandlerMap register_all_handlers() {
    HandlerMap map;
    register_basic_handlers(map);
    register_essential_handlers(map);
    register_historical_handlers(map);
    register_standard_handlers(map);
    register_outdated_handlers(map);
    register_modern_handlers(map);
    register_bruteforce_handlers(map);
    register_bytes_handlers(map);
    register_detector_handlers(map);
    register_rsa_handlers(map);
    register_attack_handlers(map);
    register_tls_handlers(map);
    return map;
}
