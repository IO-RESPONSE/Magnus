/* magnusctl -- thin CLI for magnusd.
 *
 * `check` validates a config file standalone (magnus_config.c, no running
 * magnusd needed -- the "nginx -t" pattern). `reload`, `status`, and
 * `shutdown` are one-line commands sent over magnusd's Unix domain
 * control socket; see src/magnusd.c and src/magnusd_protocol.h. */

#include "magnus_config.h"
#include "magnusd_protocol.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void
magnusctl_usage(const char *program)
{
    fprintf(stderr,
            "usage: %s check <config-path>\n"
            "       %s reload --socket <path> --config <path> "
            "[<new-content-path>]\n"
            "       %s status --socket <path>\n"
            "       %s shutdown --socket <path>\n",
            program, program, program, program);
    exit(2);
}

static int
magnusctl_connect(const char *socket_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {0};
    if (fd < 0) return -1;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, socket_path);
    if (connect(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Sends `command` (without a trailing newline) to magnusd at
 * `socket_path`, reads one response line into `response`, and returns
 * true on success (connection + round trip completed; the response
 * itself may still start with REJECTED/ROLLED_BACK/ERROR -- callers
 * check that). */
static bool
magnusctl_command(const char *socket_path, const char *command,
                  char *response, size_t response_capacity)
{
    int fd = magnusctl_connect(socket_path);
    char line[64];
    size_t length = 0;
    ssize_t written;

    if (fd < 0) {
        fprintf(stderr, "magnusctl: cannot connect to '%s': %s\n",
                socket_path, strerror(errno));
        return false;
    }
    snprintf(line, sizeof(line), "%s\n", command);
    written = send(fd, line, strlen(line), MSG_NOSIGNAL);
    if (written < 0 || (size_t) written != strlen(line)) {
        close(fd);
        return false;
    }
    while (length + 1 < response_capacity) {
        char byte;
        ssize_t received = recv(fd, &byte, 1, 0);
        if (received <= 0) break;
        if (byte == '\n') break;
        response[length++] = byte;
    }
    response[length] = '\0';
    close(fd);
    return true;
}

static int
magnusctl_check(int argc, char **argv)
{
    magnus_config_t config;
    char error[192];
    if (argc != 3) magnusctl_usage(argv[0]);
    if (magnus_config_load(argv[2], &config, error, sizeof(error))
        != MAGNUS_CONFIG_OK) {
        fprintf(stderr, "magnusctl: check: %s\n", error);
        return 1;
    }
    printf("OK: %s valid, port=%u, %zu upstream(s), generation=%016llx\n",
           argv[2], config.port, config.upstream_count,
           (unsigned long long) magnus_config_hash(&config));
    return 0;
}

static const char *
magnusctl_find_flag(int argc, char **argv, const char *name)
{
    for (int index = 0; index + 1 < argc; index++) {
        if (strcmp(argv[index], name) == 0) return argv[index + 1];
    }
    return NULL;
}

static int
magnusctl_reload(int argc, char **argv)
{
    const char *socket_path = magnusctl_find_flag(argc, argv, "--socket");
    const char *config_path = magnusctl_find_flag(argc, argv, "--config");
    const char *stage_path = NULL;
    char response[256];
    static char previous_content[65536];
    bool staged_over_config = false;

    /* skip "reload" (argv[1]) and every --flag/value pair; whatever single
     * argument is left over is the optional staged-content path. */
    for (int index = 2; index < argc; index++) {
        if (strcmp(argv[index], "--socket") == 0
            || strcmp(argv[index], "--config") == 0) {
            index++;
            continue;
        }
        stage_path = argv[index];
    }
    if (socket_path == NULL) magnusctl_usage(argv[0]);

    if (stage_path != NULL) {
        magnus_config_t staged;
        char error[192];
        FILE *previous;
        FILE *source;
        FILE *dest;
        int byte;
        if (config_path == NULL) magnusctl_usage(argv[0]);
        if (magnus_config_load(stage_path, &staged, error, sizeof(error))
            != MAGNUS_CONFIG_OK) {
            fprintf(stderr, "magnusctl: reload: staged config invalid: %s\n",
                    error);
            return 1;
        }
        /* Snapshot whatever is live at config_path *before* overwriting it,
         * so a REJECTED/ROLLED_BACK response below can put it back --
         * otherwise the on-disk file would claim a config magnusd never
         * actually applied, out of step with what magnus is really
         * running. */
        previous_content[0] = '\0';
        previous = fopen(config_path, "r");
        if (previous != NULL) {
            size_t read_length = fread(previous_content, 1,
                                       sizeof(previous_content) - 1, previous);
            previous_content[read_length] = '\0';
            fclose(previous);
        }
        source = fopen(stage_path, "r");
        dest = source != NULL ? fopen(config_path, "w") : NULL;
        if (source == NULL || dest == NULL) {
            fprintf(stderr, "magnusctl: reload: cannot stage '%s' into "
                            "'%s': %s\n", stage_path, config_path,
                    strerror(errno));
            if (source != NULL) fclose(source);
            return 1;
        }
        while ((byte = fgetc(source)) != EOF) fputc(byte, dest);
        fclose(source);
        fclose(dest);
        staged_over_config = true;
    }

    if (!magnusctl_command(socket_path, MAGNUSD_CMD_RELOAD, response,
                           sizeof(response))) {
        fprintf(stderr, "magnusctl: reload: no response from magnusd\n");
        if (staged_over_config) {
            FILE *restore = fopen(config_path, "w");
            if (restore != NULL) {
                fputs(previous_content, restore);
                fclose(restore);
            }
        }
        return 1;
    }
    printf("%s\n", response);
    if (staged_over_config && strncmp(response, "OK", 2) != 0) {
        FILE *restore = fopen(config_path, "w");
        if (restore != NULL) {
            fputs(previous_content, restore);
            fclose(restore);
        } else {
            fprintf(stderr, "magnusctl: reload: warning: could not restore "
                            "'%s' after a %s response\n", config_path,
                    response);
        }
    }
    return strncmp(response, "OK", 2) == 0 ? 0 : 1;
}

static int
magnusctl_status(int argc, char **argv)
{
    const char *socket_path = magnusctl_find_flag(argc, argv, "--socket");
    char response[256];
    if (socket_path == NULL) magnusctl_usage(argv[0]);
    if (!magnusctl_command(socket_path, MAGNUSD_CMD_STATUS, response,
                           sizeof(response))) {
        fprintf(stderr, "magnusctl: status: no response from magnusd\n");
        return 1;
    }
    printf("%s\n", response);
    return strncmp(response, "OK", 2) == 0 ? 0 : 1;
}

static int
magnusctl_shutdown(int argc, char **argv)
{
    const char *socket_path = magnusctl_find_flag(argc, argv, "--socket");
    char response[256];
    if (socket_path == NULL) magnusctl_usage(argv[0]);
    if (!magnusctl_command(socket_path, MAGNUSD_CMD_SHUTDOWN, response,
                           sizeof(response))) {
        fprintf(stderr, "magnusctl: shutdown: no response from magnusd\n");
        return 1;
    }
    printf("%s\n", response);
    return strncmp(response, "OK", 2) == 0 ? 0 : 1;
}

int
main(int argc, char **argv)
{
    if (argc < 2) magnusctl_usage(argv[0]);
    if (strcmp(argv[1], "check") == 0) return magnusctl_check(argc, argv);
    if (strcmp(argv[1], "reload") == 0) return magnusctl_reload(argc, argv);
    if (strcmp(argv[1], "status") == 0) return magnusctl_status(argc, argv);
    if (strcmp(argv[1], "shutdown") == 0) return magnusctl_shutdown(argc, argv);
    magnusctl_usage(argv[0]);
    return 2;
}
