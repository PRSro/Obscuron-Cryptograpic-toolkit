#ifndef OBSCURON_PLUGIN_API_H
#define OBSCURON_PLUGIN_API_H

#ifdef __cplusplus
extern "C" {
#endif

#define OBSCURON_PLUGIN_API_VERSION 1
#define OBSCURON_PLUGIN_SYMBOL "obscuron_plugin_v1"

typedef struct {
    int api_version;
    const char *name;
    const char *description;
    const char *category;
    const char *author;
    const char *version_str;

    int operation_count;

    const char* (*get_operation_name)(int index);
    const char* (*get_operation_description)(int index);

    char* (*execute)(const char *operation_name,
                     const char *input,
                     const char *key,
                     const char *iv,
                     int param1,
                     int param2,
                     int encrypt,
                     char **error_msg);

    void (*free_string)(char *str);

} ObscuronPluginV1;

#ifdef __cplusplus
}
#endif

#endif
