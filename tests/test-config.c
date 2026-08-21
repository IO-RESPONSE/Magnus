#include "magnus_config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char scratch_dir[] = "/tmp/magnus-config-test-XXXXXX";

static void
write_file(const char *path, const char *content)
{
    FILE *file = fopen(path, "w");
    assert(file != NULL);
    fputs(content, file);
    fclose(file);
}

static char *
path_in_scratch(const char *name)
{
    static char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s/%s", scratch_dir, name);
    return buffer;
}

int
main(void)
{
    magnus_config_t config;
    char error[192];
    char *config_path;
    char *cert_path;
    char *key_path;

    assert(mkdtemp(scratch_dir) != NULL);
    config_path = path_in_scratch("magnus.conf");
    cert_path = path_in_scratch("server.crt");
    key_path = path_in_scratch("server.key");
    write_file(cert_path, "not a real cert\n");
    write_file(key_path, "not a real key\n");

    /* minimal valid config: just a port */
    write_file(config_path, "port = 8080\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.port == 8080);
    assert(!config.has_root);
    assert(!config.has_tls);
    assert(config.upstream_count == 0);
    assert(!config.has_rate_limit);
    assert(config.access_log_enabled);
    assert(config.access_log_sample == 1);
    assert(!config.has_admin_socket);
    assert(config.lb_policy == MAGNUS_LB_ROUND_ROBIN);
    assert(strcmp(config.health_check_path, "/") == 0);
    assert(config.health_check_expected_status == 200);
    assert(config.health_check_interval_seconds == 5);
    assert(config.health_check_timeout_seconds == 2);
    assert(config.health_check_failure_threshold == 3);
    assert(config.health_check_cooldown_seconds == 5);
    assert(!config.has_stream_listen);
    assert(config.stream_upstream_count == 0);
    assert(config.stream_lb_policy == MAGNUS_LB_ROUND_ROBIN);
    assert(config.sni_route_count == 0);
    assert(!config.has_udp_listen);
    assert(config.udp_upstream_count == 0);
    assert(config.udp_lb_policy == MAGNUS_LB_ROUND_ROBIN);
    assert(config.udp_session_idle_seconds == 30);
    assert(config.udp_max_sessions == 1024);

    /* full config: comments, blank lines, all fields */
    {
        char content[1024];
        snprintf(content, sizeof(content),
            "# a comment\n"
            "\n"
            "port = 9090\n"
            "root = %s\n"
            "tls_cert = %s\n"
            "tls_key = %s\n"
            "upstream = 10.0.0.1:8001:2\n"
            "upstream = 10.0.0.2:8002\n"
            "rate_limit_rps = 50\n"
            "rate_limit_burst = 100\n"
            "access_log = off\n"
            "access_log_sample = 20\n"
            "lb_policy = least_conn\n"
            "health_check_path = /healthz\n"
            "health_check_expected_status = 204\n"
            "health_check_interval_seconds = 10\n"
            "health_check_timeout_seconds = 3\n"
            "health_check_failure_threshold = 5\n"
            "health_check_cooldown_seconds = 30\n"
            "stream_listen = 9091\n"
            "stream_upstream = 10.0.1.1:6000:2\n"
            "stream_upstream = 10.0.1.2:6000\n"
            "stream_lb_policy = ip_hash\n"
            "stream_sni_route = a.example.com 10.0.2.1:7000\n"
            "stream_sni_route = a.example.com 10.0.2.2:7000\n"
            "stream_sni_route = *.b.example.com 10.0.2.3:7000:3\n"
            "udp_listen = 9092\n"
            "udp_upstream = 10.0.3.1:9000:2\n"
            "udp_upstream = 10.0.3.2:9000\n"
            "udp_lb_policy = least_conn\n"
            "udp_session_idle_seconds = 60\n"
            "udp_max_sessions = 256\n"
            "admin_socket = %s/admin.sock\n",
            scratch_dir, cert_path, key_path, scratch_dir);
        write_file(config_path, content);
    }
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.port == 9090);
    assert(config.has_root && strcmp(config.root, scratch_dir) == 0);
    assert(!config.access_log_enabled);
    assert(config.access_log_sample == 20);
    assert(config.has_admin_socket);
    assert(config.has_tls);
    assert(strcmp(config.tls_cert, cert_path) == 0);
    assert(strcmp(config.tls_key, key_path) == 0);
    assert(config.upstream_count == 2);
    assert(strcmp(config.upstreams[0].address, "10.0.0.1") == 0);
    assert(!config.upstreams[0].is_hostname);
    assert(config.upstreams[0].port == 8001);
    assert(config.upstreams[0].weight == 2);
    assert(config.upstreams[1].weight == 1);
    assert(config.has_rate_limit);
    assert(config.rate_limit_rps == 50.0);
    assert(config.rate_limit_burst == 100.0);
    assert(config.lb_policy == MAGNUS_LB_LEAST_CONN);
    assert(strcmp(config.health_check_path, "/healthz") == 0);
    assert(config.health_check_expected_status == 204);
    assert(config.health_check_interval_seconds == 10);
    assert(config.health_check_timeout_seconds == 3);
    assert(config.health_check_failure_threshold == 5);
    assert(config.health_check_cooldown_seconds == 30);
    assert(config.has_stream_listen);
    assert(config.stream_listen_port == 9091);
    assert(config.stream_upstream_count == 2);
    assert(strcmp(config.stream_upstreams[0].address, "10.0.1.1") == 0);
    assert(config.stream_upstreams[0].port == 6000);
    assert(config.stream_upstreams[0].weight == 2);
    assert(config.stream_upstreams[1].weight == 1);
    assert(config.stream_lb_policy == MAGNUS_LB_IP_HASH);
    assert(config.sni_route_count == 2);
    assert(strcmp(config.sni_routes[0].pattern, "a.example.com") == 0);
    assert(config.sni_routes[0].upstream_count == 2);
    assert(strcmp(config.sni_routes[0].upstreams[0].address, "10.0.2.1") == 0);
    assert(config.sni_routes[0].upstreams[0].port == 7000);
    assert(strcmp(config.sni_routes[0].upstreams[1].address, "10.0.2.2") == 0);
    assert(strcmp(config.sni_routes[1].pattern, "*.b.example.com") == 0);
    assert(config.sni_routes[1].upstream_count == 1);
    assert(config.sni_routes[1].upstreams[0].weight == 3);
    assert(config.has_udp_listen);
    assert(config.udp_listen_port == 9092);
    assert(config.udp_upstream_count == 2);
    assert(strcmp(config.udp_upstreams[0].address, "10.0.3.1") == 0);
    assert(config.udp_upstreams[0].port == 9000);
    assert(config.udp_upstreams[0].weight == 2);
    assert(config.udp_upstreams[1].weight == 1);
    assert(config.udp_lb_policy == MAGNUS_LB_LEAST_CONN);
    assert(config.udp_session_idle_seconds == 60);
    assert(config.udp_max_sessions == 256);

    /* stream_listen/stream_upstream: each requires the other, the port
     * must differ from the main listener, a hostname is rejected (same
     * restriction as grpc_upstream), and stream_lb_policy takes the same
     * values lb_policy does. */
    write_file(config_path, "port = 8080\nstream_listen = 9091\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "stream_listen") != NULL);
    write_file(config_path, "port = 8080\nstream_upstream = 10.0.0.1:6000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "stream_upstream") != NULL);
    write_file(config_path,
        "port = 8080\nstream_listen = 8080\nstream_upstream = 10.0.0.1:6000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "stream_listen") != NULL);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = backend.internal:6000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = 10.0.0.1:6000\nstream_lb_policy = least_conn\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.stream_lb_policy == MAGNUS_LB_LEAST_CONN);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = 10.0.0.1:6000\nstream_lb_policy = fastest\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "stream_lb_policy") != NULL);

    /* stream_sni_route: requires stream_listen, "<pattern> <endpoint>"
     * shape, a hostname-shaped pattern (with or without a leading `*.`),
     * a literal IPv4 endpoint (same restriction as stream_upstream), and
     * two lines sharing a pattern accumulate into that pattern's own
     * cluster rather than being rejected as a duplicate. */
    write_file(config_path,
        "port = 8080\nstream_sni_route = example.com 10.0.0.1:6000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "stream_sni_route") != NULL);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = 10.0.0.1:6000\n"
        "stream_sni_route = example.com\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = 10.0.0.1:6000\n"
        "stream_sni_route = -bad..pattern 10.0.0.2:6000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = 10.0.0.1:6000\n"
        "stream_sni_route = example.com backend.internal:6000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = 10.0.0.1:6000\n"
        "stream_sni_route = example.com 10.0.0.2:6000 extra-token\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path,
        "port = 8080\nstream_listen = 9091\n"
        "stream_upstream = 10.0.0.1:6000\n"
        "stream_sni_route = example.com 10.0.0.2:6000\n"
        "stream_sni_route = example.com 10.0.0.3:6000\n"
        "stream_sni_route = *.example.com 10.0.0.4:6000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.sni_route_count == 2);
    assert(strcmp(config.sni_routes[0].pattern, "example.com") == 0);
    assert(config.sni_routes[0].upstream_count == 2);
    assert(strcmp(config.sni_routes[1].pattern, "*.example.com") == 0);
    assert(config.sni_routes[1].upstream_count == 1);

    /* udp_listen/udp_upstream: each requires the other (no "must differ
     * from port" restriction, unlike stream_listen -- UDP and TCP share
     * no port namespace), a hostname endpoint is rejected, and
     * udp_lb_policy/udp_session_idle_seconds/udp_max_sessions each
     * validate their own range. */
    write_file(config_path, "port = 8080\nudp_listen = 9092\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "udp_listen") != NULL);
    write_file(config_path, "port = 8080\nudp_upstream = 10.0.0.1:9000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "udp_upstream") != NULL);
    write_file(config_path,
        "port = 8080\nudp_listen = 8080\nudp_upstream = 10.0.0.1:9000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.udp_listen_port == 8080);
    write_file(config_path,
        "port = 8080\nudp_listen = 9092\n"
        "udp_upstream = backend.internal:9000\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path,
        "port = 8080\nudp_listen = 9092\n"
        "udp_upstream = 10.0.0.1:9000\nudp_lb_policy = ip_hash\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.udp_lb_policy == MAGNUS_LB_IP_HASH);
    write_file(config_path,
        "port = 8080\nudp_listen = 9092\n"
        "udp_upstream = 10.0.0.1:9000\nudp_lb_policy = fastest\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "udp_lb_policy") != NULL);
    write_file(config_path,
        "port = 8080\nudp_listen = 9092\n"
        "udp_upstream = 10.0.0.1:9000\nudp_session_idle_seconds = 0\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "udp_session_idle_seconds") != NULL);
    write_file(config_path,
        "port = 8080\nudp_listen = 9092\n"
        "udp_upstream = 10.0.0.1:9000\nudp_max_sessions = 0\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "udp_max_sessions") != NULL);
    write_file(config_path,
        "port = 8080\nudp_listen = 9092\n"
        "udp_upstream = 10.0.0.1:9000\nudp_max_sessions = 4097\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);

    /* health_check_*: malformed/out-of-range values rejected. */
    write_file(config_path, "port = 8080\nhealth_check_path = no-leading-slash\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "health_check_path") != NULL);
    write_file(config_path, "port = 8080\nhealth_check_path = /has space\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path, "port = 8080\nhealth_check_expected_status = 99\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "health_check_expected_status") != NULL);
    write_file(config_path, "port = 8080\nhealth_check_expected_status = 600\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path, "port = 8080\nhealth_check_interval_seconds = 0\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "health_check_interval_seconds") != NULL);
    write_file(config_path, "port = 8080\nhealth_check_timeout_seconds = 0\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path, "port = 8080\nhealth_check_failure_threshold = 0\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path, "port = 8080\nhealth_check_cooldown_seconds = 0\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);

    /* lb_policy: every recognized value, and an invalid one rejected. */
    write_file(config_path, "port = 8080\nlb_policy = round_robin\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.lb_policy == MAGNUS_LB_ROUND_ROBIN);
    write_file(config_path, "port = 8080\nlb_policy = ip_hash\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.lb_policy == MAGNUS_LB_IP_HASH);
    write_file(config_path, "port = 8080\nlb_policy = fastest\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "lb_policy") != NULL);

    /* missing port */
    write_file(config_path, "root = /tmp\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "port") != NULL);

    /* unknown key, reported with a line number */
    write_file(config_path, "port = 8080\nfooo = bar\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "line 2") != NULL);
    assert(strstr(error, "fooo") != NULL);

    /* malformed line */
    write_file(config_path, "port 8080\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);

    /* root pointing at a nonexistent directory */
    write_file(config_path, "port = 8080\nroot = /no/such/dir/at/all\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "root") != NULL);

    /* tls_cert without tls_key */
    {
        char content[512];
        snprintf(content, sizeof(content), "port = 8080\ntls_cert = %s\n",
                 cert_path);
        write_file(config_path, content);
    }
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "tls_cert") != NULL);

    /* malformed upstream */
    write_file(config_path, "port = 8080\nupstream = not-an-endpoint\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);

    /* upstream hostname (1c): accepted, flagged as such, resolved
     * asynchronously at runtime -- see magnus_dns.h -- not here. */
    write_file(config_path, "port = 8080\nupstream = backend.internal:8001\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_OK);
    assert(config.upstream_count == 1);
    assert(strcmp(config.upstreams[0].address, "backend.internal") == 0);
    assert(config.upstreams[0].is_hostname);
    assert(config.upstreams[0].port == 8001);

    /* obviously-invalid hostname syntax is still rejected up front --
     * "does this actually resolve" is deferred to runtime, but "is this
     * even hostname-shaped" is not. */
    write_file(config_path, "port = 8080\nupstream = -bad..host:8001\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    write_file(config_path, "port = 8080\nupstream = has space:8001\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);

    /* rate_limit_burst without rate_limit_rps */
    write_file(config_path, "port = 8080\nrate_limit_burst = 10\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "rate_limit") != NULL);

    /* access_log must be exactly on/off */
    write_file(config_path, "port = 8080\naccess_log = sometimes\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);
    assert(strstr(error, "access_log") != NULL);

    /* access_log_sample must be a positive integer */
    write_file(config_path, "port = 8080\naccess_log_sample = 0\n");
    assert(magnus_config_load(config_path, &config, error, sizeof(error))
           == MAGNUS_CONFIG_ERROR);

    /* file that does not exist at all */
    assert(magnus_config_load(path_in_scratch("missing.conf"), &config,
                              error, sizeof(error)) == MAGNUS_CONFIG_ERROR);

    /* hashing: identical content hashes identically, different content
     * (even just the port) hashes differently */
    {
        magnus_config_t a;
        magnus_config_t b;
        magnus_config_t c;
        write_file(config_path, "port = 8080\n");
        assert(magnus_config_load(config_path, &a, error, sizeof(error))
               == MAGNUS_CONFIG_OK);
        assert(magnus_config_load(config_path, &b, error, sizeof(error))
               == MAGNUS_CONFIG_OK);
        write_file(config_path, "port = 8081\n");
        assert(magnus_config_load(config_path, &c, error, sizeof(error))
               == MAGNUS_CONFIG_OK);
        assert(magnus_config_hash(&a) == magnus_config_hash(&b));
        assert(magnus_config_hash(&a) != magnus_config_hash(&c));
    }

    unlink(config_path);
    unlink(cert_path);
    unlink(key_path);
    rmdir(scratch_dir);
    return 0;
}
