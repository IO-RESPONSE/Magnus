#ifndef MAGNUS_CONFIG_H
#define MAGNUS_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAGNUS_CONFIG_MAX_UPSTREAMS 16
#define MAGNUS_CONFIG_PATH_MAX 256

typedef struct {
    char address[64];
    unsigned port;
    unsigned weight;
} magnus_config_upstream_t;

/* The full, validated shape of a magnus data-plane config file. Every
 * field here has already passed magnus_config_load()'s schema check --
 * callers never need to re-validate ranges or cross-field constraints
 * (e.g. tls_cert/tls_key both-or-neither) themselves. */
typedef struct {
    unsigned port;
    bool has_root;
    char root[MAGNUS_CONFIG_PATH_MAX];
    bool has_tls;
    char tls_cert[MAGNUS_CONFIG_PATH_MAX];
    char tls_key[MAGNUS_CONFIG_PATH_MAX];
    size_t upstream_count;
    magnus_config_upstream_t upstreams[MAGNUS_CONFIG_MAX_UPSTREAMS];
    bool has_rate_limit;
    double rate_limit_rps;
    double rate_limit_burst;
} magnus_config_t;

typedef enum {
    MAGNUS_CONFIG_OK = 0,
    MAGNUS_CONFIG_ERROR
} magnus_config_result_t;

/* Parses and strictly validates the config file at `path`:
 *   - unknown keys are rejected (no silently-ignored typos)
 *   - every value is range/format checked (port, ipv4:port[:weight],
 *     file existence for root/tls_cert/tls_key, tls_cert and tls_key must
 *     be given together, rate_limit_burst requires rate_limit_rps)
 *   - `port` is required
 *
 * On success returns MAGNUS_CONFIG_OK with `config` fully populated. On
 * failure returns MAGNUS_CONFIG_ERROR and writes a human-readable reason
 * (including the offending line number where applicable) into `error`;
 * `config`'s contents are unspecified in this case and must not be used. */
magnus_config_result_t magnus_config_load(const char *path,
                                          magnus_config_t *config,
                                          char *error, size_t error_capacity);

/* A stable (not cryptographic) content fingerprint of a validated config,
 * used for audit trail and generation tracking. Two configs that parse to
 * the same field values hash the same regardless of comment/whitespace
 * differences in the source file. */
uint64_t magnus_config_hash(const magnus_config_t *config);

#endif
