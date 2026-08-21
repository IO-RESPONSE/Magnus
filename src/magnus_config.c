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

/* Lenient on purpose: rejects what is clearly not hostname syntax at all
 * (empty, too long, an empty label, a stray character outside
 * alphanumeric/hyphen/dot, a leading/trailing hyphen or dot) but does not
 * attempt full RFC 1123 compliance -- unlike an IP literal, "does this
 * name actually resolve" cannot be verified at config-parse time anyway
 * (see magnus_dns.h), so this only exists to catch obvious typos, not to
 * be the authority on validity. */
bool
magnus_config_looks_like_hostname(const char *text)
{
    size_t length = strlen(text);
    size_t label_length = 0;
    if (length == 0 || length > 253) return false;
    if (text[0] == '.' || text[0] == '-'
        || text[length - 1] == '.' || text[length - 1] == '-')
        return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char) text[i];
        if (c == '.') {
            if (label_length == 0) return false;
            label_length = 0;
            continue;
        }
        if (!isalnum(c) && c != '-') return false;
        label_length++;
        if (label_length > 63) return false;
    }
    return true;
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
    bool is_hostname;

    if (strlen(value) >= sizeof(spec)) return false;
    strcpy(spec, value);
    address = strtok_r(spec, ":", &saveptr);
    port_text = strtok_r(NULL, ":", &saveptr);
    weight_text = strtok_r(NULL, ":", &saveptr);
    if (address == NULL || port_text == NULL) return false;
    is_hostname = inet_pton(AF_INET, address, &probe) != 1;
    if (is_hostname && !magnus_config_looks_like_hostname(address)) return false;
    if (!magnus_config_parse_uint(port_text, 1, 65535, &port)) return false;
    if (weight_text != NULL
        && !magnus_config_parse_uint(weight_text, 1, 1000, &weight))
        return false;
    if (strlen(address) >= sizeof(out->address)) return false;
    strcpy(out->address, address);
    out->is_hostname = is_hostname;
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
    config->access_log_enabled = true;
    config->access_log_sample = 1;
    strcpy(config->health_check_path, "/");
    config->health_check_expected_status = 200;
    config->health_check_interval_seconds = 5;
    config->health_check_timeout_seconds = 2;
    config->health_check_failure_threshold = 3;
    config->health_check_cooldown_seconds = 5;
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
        } else if (strcmp(key, "grpc_upstream") == 0) {
            magnus_config_upstream_t upstream;
            if (config->grpc_upstream_count == MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "too many 'grpc_upstream' entries "
                                        "(max %d)",
                                        MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (!magnus_config_parse_upstream(value, &upstream)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'grpc_upstream' must be "
                                        "ipv4:port[:weight], got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (upstream.is_hostname) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'grpc_upstream' must be a literal "
                                        "IPv4 address, not a hostname (got "
                                        "'%s') -- DNS resolution is not yet "
                                        "supported for gRPC upstreams",
                                        upstream.address);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->grpc_upstreams[config->grpc_upstream_count++] = upstream;
        } else if (strcmp(key, "stream_listen") == 0) {
            unsigned long stream_port;
            if (!magnus_config_parse_uint(value, 1, 65535, &stream_port)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'stream_listen' must be 1-65535, "
                                        "got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->stream_listen_port = (unsigned) stream_port;
            config->has_stream_listen = true;
        } else if (strcmp(key, "stream_upstream") == 0) {
            magnus_config_upstream_t upstream;
            if (config->stream_upstream_count == MAGNUS_CONFIG_MAX_UPSTREAMS) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "too many 'stream_upstream' entries "
                                        "(max %d)", MAGNUS_CONFIG_MAX_UPSTREAMS);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (!magnus_config_parse_upstream(value, &upstream)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'stream_upstream' must be "
                                        "ipv4:port[:weight], got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (upstream.is_hostname) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'stream_upstream' must be a literal "
                                        "IPv4 address, not a hostname (got "
                                        "'%s') -- DNS resolution is not yet "
                                        "supported for the L4 stream cluster",
                                        upstream.address);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->stream_upstreams[config->stream_upstream_count++] = upstream;
        } else if (strcmp(key, "stream_lb_policy") == 0) {
            if (strcmp(value, "round_robin") == 0) {
                config->stream_lb_policy = MAGNUS_LB_ROUND_ROBIN;
            } else if (strcmp(value, "least_conn") == 0) {
                config->stream_lb_policy = MAGNUS_LB_LEAST_CONN;
            } else if (strcmp(value, "ip_hash") == 0) {
                config->stream_lb_policy = MAGNUS_LB_IP_HASH;
            } else {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'stream_lb_policy' must be "
                                        "'round_robin', 'least_conn', or "
                                        "'ip_hash', got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
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
        } else if (strcmp(key, "access_log") == 0) {
            if (strcmp(value, "on") == 0) {
                config->access_log_enabled = true;
            } else if (strcmp(value, "off") == 0) {
                config->access_log_enabled = false;
            } else {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'access_log' must be 'on' or "
                                        "'off', got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
        } else if (strcmp(key, "lb_policy") == 0) {
            if (strcmp(value, "round_robin") == 0) {
                config->lb_policy = MAGNUS_LB_ROUND_ROBIN;
            } else if (strcmp(value, "least_conn") == 0) {
                config->lb_policy = MAGNUS_LB_LEAST_CONN;
            } else if (strcmp(value, "ip_hash") == 0) {
                config->lb_policy = MAGNUS_LB_IP_HASH;
            } else {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'lb_policy' must be 'round_robin', "
                                        "'least_conn', or 'ip_hash', got '%s'",
                                        value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
        } else if (strcmp(key, "health_check_path") == 0) {
            if (*value != '/' || strlen(value) >= sizeof(config->health_check_path)
                || strpbrk(value, " \t\r\n") != NULL) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'health_check_path' must start "
                                        "with '/' and contain no whitespace, "
                                        "got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            strcpy(config->health_check_path, value);
        } else if (strcmp(key, "health_check_expected_status") == 0) {
            unsigned long status;
            if (!magnus_config_parse_uint(value, 100, 599, &status)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'health_check_expected_status' "
                                        "must be 100-599, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->health_check_expected_status = (unsigned) status;
        } else if (strcmp(key, "health_check_interval_seconds") == 0) {
            unsigned long seconds;
            if (!magnus_config_parse_uint(value, 1, 3600, &seconds)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'health_check_interval_seconds' "
                                        "must be 1-3600, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->health_check_interval_seconds = (unsigned) seconds;
        } else if (strcmp(key, "health_check_timeout_seconds") == 0) {
            unsigned long seconds;
            if (!magnus_config_parse_uint(value, 1, 3600, &seconds)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'health_check_timeout_seconds' "
                                        "must be 1-3600, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->health_check_timeout_seconds = (unsigned) seconds;
        } else if (strcmp(key, "health_check_failure_threshold") == 0) {
            unsigned long count;
            if (!magnus_config_parse_uint(value, 1, 1000, &count)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'health_check_failure_threshold' "
                                        "must be 1-1000, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->health_check_failure_threshold = (unsigned) count;
        } else if (strcmp(key, "health_check_cooldown_seconds") == 0) {
            unsigned long seconds;
            if (!magnus_config_parse_uint(value, 1, 86400, &seconds)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'health_check_cooldown_seconds' "
                                        "must be 1-86400, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->health_check_cooldown_seconds = (unsigned) seconds;
        } else if (strcmp(key, "access_log_sample") == 0) {
            unsigned long sample;
            if (!magnus_config_parse_uint(value, 1, 1000000, &sample)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'access_log_sample' must be a "
                                        "positive integer, got '%s'", value);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->access_log_sample = (unsigned) sample;
        } else if (strcmp(key, "admin_socket") == 0) {
            if (*value == '\0' || strlen(value) >= sizeof(config->admin_socket)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'admin_socket' path too long or "
                                        "empty");
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            strcpy(config->admin_socket, value);
            config->has_admin_socket = true;
        } else if (strcmp(key, "route") == 0) {
            char route_error[128];
            if (config->route_count == MAGNUS_CONFIG_MAX_ROUTES) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "too many 'route' entries (max %d)",
                                        MAGNUS_CONFIG_MAX_ROUTES);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            if (!magnus_route_parse(value,
                                    &config->routes[config->route_count],
                                    route_error, sizeof(route_error))) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'route': %s", route_error);
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            config->route_count++;
        } else if (strcmp(key, "trusted_proxies") == 0) {
            char spec[512];
            char *saveptr = NULL;
            char *token;
            if (strlen(value) >= sizeof(spec)) {
                magnus_config_set_error(error, error_capacity, line_number,
                                        "'trusted_proxies' list too long");
                fclose(file);
                return MAGNUS_CONFIG_ERROR;
            }
            strcpy(spec, value);
            for (token = strtok_r(spec, ",", &saveptr); token != NULL;
                 token = strtok_r(NULL, ",", &saveptr)) {
                char *cidr_text = magnus_config_trim(token);
                struct in_addr network;
                unsigned prefix_length;
                if (*cidr_text == '\0') continue;
                if (config->trusted_proxy_count == MAGNUS_CONFIG_MAX_TRUSTED_PROXIES) {
                    magnus_config_set_error(error, error_capacity, line_number,
                                            "too many 'trusted_proxies' entries "
                                            "(max %d)",
                                            MAGNUS_CONFIG_MAX_TRUSTED_PROXIES);
                    fclose(file);
                    return MAGNUS_CONFIG_ERROR;
                }
                if (!magnus_route_parse_cidr(cidr_text, &network, &prefix_length)) {
                    magnus_config_set_error(error, error_capacity, line_number,
                                            "'trusted_proxies': invalid CIDR '%s'",
                                            cidr_text);
                    fclose(file);
                    return MAGNUS_CONFIG_ERROR;
                }
                config->trusted_proxies[config->trusted_proxy_count].network = network;
                config->trusted_proxies[config->trusted_proxy_count].prefix_length = prefix_length;
                config->trusted_proxy_count++;
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
    if (config->upstream_count == 0) {
        for (size_t index = 0; index < config->route_count; index++) {
            if (config->routes[index].action == MAGNUS_ROUTE_ACTION_PROXY) {
                magnus_config_set_error(error, error_capacity, 0,
                                        "a 'route' with action=proxy needs "
                                        "at least one 'upstream'");
                return MAGNUS_CONFIG_ERROR;
            }
        }
    }
    if (config->grpc_upstream_count == 0) {
        for (size_t index = 0; index < config->route_count; index++) {
            if (config->routes[index].action == MAGNUS_ROUTE_ACTION_GRPC) {
                magnus_config_set_error(error, error_capacity, 0,
                                        "a 'route' with action=grpc needs "
                                        "at least one 'grpc_upstream'");
                return MAGNUS_CONFIG_ERROR;
            }
        }
    }
    if (config->has_stream_listen && config->stream_upstream_count == 0) {
        magnus_config_set_error(error, error_capacity, 0,
                                "'stream_listen' needs at least one "
                                "'stream_upstream'");
        return MAGNUS_CONFIG_ERROR;
    }
    if (!config->has_stream_listen && config->stream_upstream_count > 0) {
        magnus_config_set_error(error, error_capacity, 0,
                                "'stream_upstream' needs 'stream_listen'");
        return MAGNUS_CONFIG_ERROR;
    }
    if (config->has_stream_listen && config->stream_listen_port == config->port) {
        magnus_config_set_error(error, error_capacity, 0,
                                "'stream_listen' must differ from 'port'");
        return MAGNUS_CONFIG_ERROR;
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
