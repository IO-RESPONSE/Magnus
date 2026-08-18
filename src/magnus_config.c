#include "magnus_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void
magnus_config_set_error(char *error, size_t error_capacity, int line_number,
                        const char *format, ...)
{
    char detail[192];
    va_list args;
    if (error == NULL || error_capacity == 0) return;
    va_start(args, format);
    vsnprintf(detail, sizeof(detail), format, args);
    va_end(args);
    if (line_number > 0) {
        snprintf(error, error_capacity, "line %d: %s", line_number, detail);
    } else {
        snprintf(error, error_capacity, "%s", detail);
    }
}

static char *
magnus_config_trim(char *text)
{
    char *end;
    while (*text == ' ' || *text == '\t') text++;
    end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t'
                          || end[-1] == '\r' || end[-1] == '\n')) {
        end--;
    }
    *end = '\0';
    return text;
}

static bool
magnus_config_parse_uint(const char *text, unsigned long minimum,
                         unsigned long maximum, unsigned long *out)
{
    char *end;
    unsigned long value;
    if (text == NULL || *text == '\0') return false;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value < minimum || value > maximum)
        return false;
    *out = value;
    return true;
}

static bool
magnus_config_parse_double(const char *text, double *out)
{
    char *end;
    double value;
    if (text == NULL || *text == '\0') return false;
    errno = 0;
    value = strtod(text, &end);
    if (errno != 0 || *end != '\0' || !(value > 0.0)) return false;
    *out = value;
    return true;
}

static bool
magnus_config_file_exists(const char *path)
{
    struct stat metadata;
    return stat(path, &metadata) == 0 && S_ISREG(metadata.st_mode);
}

static bool
magnus_config_parse_upstream(const char *value, magnus_config_upstream_t *out)
{
    char spec[96];
    char *saveptr = NULL;
    char *address;
    char *port_text;
    char *weight_text;
    unsigned long port;
    unsigned long weight = 1;
    struct in_addr probe;

    if (strlen(value) >= sizeof(spec)) return false;
    strcpy(spec, value);
    address = strtok_r(spec, ":", &saveptr);
    port_text = strtok_r(NULL, ":", &saveptr);
    weight_text = strtok_r(NULL, ":", &saveptr);
    if (address == NULL || port_text == NULL) return false;
    if (inet_pton(AF_INET, address, &probe) != 1) return false;
    if (!magnus_config_parse_uint(port_text, 1, 65535, &port)) return false;
    if (weight_text != NULL
        && !magnus_config_parse_uint(weight_text, 1, 1000, &weight))
        return false;
    if (strlen(address) >= sizeof(out->address)) return false;
    strcpy(out->address, address);
    out->port = (unsigned) port;
    out->weight = (unsigned) weight;
    return true;
}

magnus_config_result_t
magnus_config_load(const char *path, magnus_config_t *config, char *error,
                   size_t error_capacity)
{
    FILE *file;
    char line[512];
    int line_number = 0;
    bool port_seen = false;

    memset(config, 0, sizeof(*config));
    if (error != NULL && error_capacity > 0) error[0] = '\0';

    file = fopen(path, "r");
    if (file == NULL) {
        magnus_config_set_error(error, error_capacity, 0,
                                "cannot open '%s': %s", path, strerror(errno));
        return MAGNUS_CONFIG_ERROR;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *cursor;
        char *key;
        char *value;
        char *equals;

        line_number++;
        if (strlen(line) == sizeof(line) - 1 && line[sizeof(line) - 2] != '\n') {
            magnus_config_set_error(error, error_capacity, line_number,
                                    "line too long");
            fclose(file);
            return MAGNUS_CONFIG_ERROR;
        }
        cursor = magnus_config_trim(line);
        if (*cursor == '\0' || *cursor == '#') continue;

        equals = strchr(cursor, '=');
        if (equals == NULL) {
            magnus_config_set_error(error, error_capacity, line_number,
                                    "expected 'key = value'");
            fclose(file);
            return MAGNUS_CONFIG_ERROR;
        }
        *equals = '\0';
        key = magnus_config_trim(cursor);
        value = magnus_config_trim(equals + 1);
        if (*key == '\0') {
            magnus_config_set_error(error, error_capacity, line_number,
                                    "empty key");
            fclose(file);
            return MAGNUS_CONFIG_ERROR;
        }

        if (strcmp(key, "port") == 0) {
            unsigned long port;
            if (!magnus_config_parse_uint(value, 1, 65535, &port)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'port' must be 1-65535, got '%s'",
                                        value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->port = (unsigned) port;
            port_seen = true;
        } else if (strcmp(key, "root") == 0) {
            struct stat metadata;
            if (*value == '\0' || strlen(value) >= sizeof(config->root)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'root' path too long or empty");
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (stat(value, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'root' is not a directory: '%s'",
                                        value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            strcpy(config->root, value);
            config->has_root = true;
        } else if (strcmp(key, "tls_cert") == 0 || strcmp(key, "tls_key") == 0) {
            char *field = strcmp(key, "tls_cert") == 0 ? config->tls_cert
                                                        : config->tls_key;
            if (*value == '\0' || strlen(value) >= MAGNUS_CONFIG_PATH_MAX) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'%s' path too long or empty", key);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (!magnus_config_file_exists(value)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'%s' file not found: '%s'", key,
                                        value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            strcpy(field, value);
        } else if (strcmp(key, "upstream") == 0) {
            magnus_config_upstream_t upstream;
            if (config->upstream_count == MAGNUS_CONFIG_MAX_UPSTREAMS) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "too many 'upstream' entries "
                                        "(max %d)", MAGNUS_CONFIG_MAX_UPSTREAMS);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (!magnus_config_parse_upstream(value, &upstream)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'upstream' must be "
                                        "ipv4:port[:weight], got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->upstreams[config->upstream_count++] = upstream;
        } else if (strcmp(key, "rate_limit_rps") == 0) {
            if (!magnus_config_parse_double(value, &config->rate_limit_rps)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'rate_limit_rps' must be a "
                                        "positive number, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->has_rate_limit = true;
        } else if (strcmp(key, "rate_limit_burst") == 0) {
            if (!magnus_config_parse_double(value, &config->rate_limit_burst)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'rate_limit_burst' must be a "
                                        "positive number, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
        } else {
            magnus_config_set_error(error, error_capacity, line_number,
                                    "unknown key '%s'", key);
            fclose(file);
            return MAGNUS_CONFIG_ERROR;
        }
    }
    fclose(file);

    if (!port_seen) {
        magnus_config_set_error(error, error_capacity, 0,
                                "'port' is required");
        return MAGNUS_CONFIG_ERROR;
    }
    if ((config->tls_cert[0] != '\0') != (config->tls_key[0] != '\0')) {
        magnus_config_set_error(error, error_capacity, 0,
                                "'tls_cert' and 'tls_key' must be given "
                                "together");
        return MAGNUS_CONFIG_ERROR;
    }
    config->has_tls = config->tls_cert[0] != '\0';
    if (config->rate_limit_burst > 0.0 && !config->has_rate_limit) {
        magnus_config_set_error(error, error_capacity, 0,
                                "'rate_limit_burst' requires "
                                "'rate_limit_rps'");
        return MAGNUS_CONFIG_ERROR;
    }
    if (config->has_rate_limit && config->rate_limit_burst == 0.0) {
        config->rate_limit_burst = config->rate_limit_rps;
    }
    return MAGNUS_CONFIG_OK;
}

uint64_t
magnus_config_hash(const magnus_config_t *config)
{
    uint64_t value = UINT64_C(1469598103934665603);
    const unsigned char *bytes = (const unsigned char *) config;
    size_t index;
    for (index = 0; index < sizeof(*config); index++) {
        value ^= bytes[index];
        value *= UINT64_C(1099511628211);
    }
    return value;
}
