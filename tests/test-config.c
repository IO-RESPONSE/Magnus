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
    assert(config.upstreams[0].port == 8001);
    assert(config.upstreams[0].weight == 2);
    assert(config.upstreams[1].weight == 1);
    assert(config.has_rate_limit);
    assert(config.rate_limit_rps == 50.0);
    assert(config.rate_limit_burst == 100.0);

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
