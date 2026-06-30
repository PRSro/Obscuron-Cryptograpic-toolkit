#include "../../CLI/includes/plugin_api.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *op_names[] = {"XorByte", "EchoUpper"};
static const char *op_descs[] = {
    "XOR each byte with a fixed key (param1 = key value 0-255)",
    "Echo input back in UPPERCASE"
};

static const char* get_name(int i) {
    if (i >= 0 && i < 2) return op_names[i];
    return NULL;
}

static const char* get_desc(int i) {
    if (i >= 0 && i < 2) return op_descs[i];
    return NULL;
}

static char* execute_xor(const char *input, int key_byte) {
    size_t len = strlen(input);
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; ++i)
        out[i] = input[i] ^ (unsigned char)key_byte;
    out[len] = '\0';
    return out;
}

static char* execute_echo_upper(const char *input) {
    size_t len = strlen(input);
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; ++i)
        out[i] = (input[i] >= 'a' && input[i] <= 'z') ? input[i] - 32 : input[i];
    out[len] = '\0';
    return out;
}

static char* execute(const char *op, const char *input,
                     const char *key, const char *iv,
                     int param1, int param2, int encrypt,
                     char **error_msg)
{
    (void)key; (void)iv; (void)param2; (void)encrypt;

    if (strcmp(op, "XorByte") == 0) {
        return execute_xor(input, param1);
    }
    if (strcmp(op, "EchoUpper") == 0) {
        return execute_echo_upper(input);
    }

    if (error_msg) {
        *error_msg = strdup("Unknown operation");
    }
    return NULL;
}

static void free_string(char *s) { free(s); }

ObscuronPluginV1 obscuron_plugin_v1 = {
    .api_version = OBSCURON_PLUGIN_API_VERSION,
    .name = "XOR Demo Plugin",
    .description = "Simple XOR cipher and EchoUpper operations",
    .category = "Plugins",
    .author = "Obscuron",
    .version_str = "1.0",
    .operation_count = 2,
    .get_operation_name = get_name,
    .get_operation_description = get_desc,
    .execute = execute,
    .free_string = free_string,
};
