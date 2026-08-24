/* magnusd -- control-plane supervisor for the magnus data plane.
 *
 * Owns one magnus child process and the config file it reads. Validates
 * every config before it is ever written into place or signaled to the
 * running child (magnus_config.c, the same schema/validator magnus itself
 * links), keeps the last successfully-applied config as a rollback point,
 * and automatically reverts to it -- reverting the file and, if the child
 * did not survive, restarting magnus from it -- whenever a reload fails
 * its post-apply health check. Every start/reload/rollback is appended to
 * an audit log. A tiny line-based protocol over a Unix domain socket
 * (magnusd_protocol.h) is how magnusctl drives check/reload/status/
 * drain (roadmap 5d-1, Runtime API expansion)/upgrade (roadmap 5e-1,
 * zero-downtime binary upgrade)/shutdown.
 *
 * magnusd and magnusctl are assumed to run on the same host and see the
 * same filesystem as the magnus child they supervise -- this is the
 * control plane for one data-plane instance, not a distributed system. */

#include "magnus_config.h"
#include "magnusd_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAGNUSD_STARTUP_HEALTH_TIMEOUT_MS 5000
#define MAGNUSD_RELOAD_HEALTH_TIMEOUT_MS 5000
#define MAGNUSD_HEALTH_POLL_INTERVAL_MS 200
#define MAGNUSD_POLL_TIMEOUT_MS 2000

static char magnusd_config_path[MAGNUS_CONFIG_PATH_MAX];
static char magnusd_rollback_path[MAGNUS_CONFIG_PATH_MAX];
static char magnusd_magnus_binary[MAGNUS_CONFIG_PATH_MAX];
static char magnusd_socket_path[MAGNUS_CONFIG_PATH_MAX];
/* Roadmap 5e-1 (zero-downtime binary upgrade): derived once, at
 * startup, from magnusd_socket_path -- passed to *every* child
 * magnusd_spawn_child() ever spawns (via --upgrade-socket) so a
 * running instance is always ready to hand its listener fd off to a
 * successor, and reused as the --inherit-fd source when
 * magnusd_upgrade() spawns that successor. See src/magnus.c's own
 * magnus_upgrade_listener/magnus_upgrade_receive_listener() doc
 * comments for the actual handoff mechanism this path is used for. */
static char magnusd_upgrade_socket_path[MAGNUS_CONFIG_PATH_MAX];
static char magnusd_audit_log_path[MAGNUS_CONFIG_PATH_MAX];
static pid_t magnusd_child_pid = -1;
static unsigned magnusd_port;
static uint64_t magnusd_current_hash;
static time_t magnusd_applied_at;
static char magnusd_last_action[16] = "none";
static char magnusd_last_result[16] = "none";
static volatile sig_atomic_t magnusd_running = 1;
static volatile sig_atomic_t magnusd_child_reaped;

static void
magnusd_signal_handler(int signal_number)
{
    if (signal_number == SIGCHLD) {
        magnusd_child_reaped = 1;
    } else {
        magnusd_running = 0;
    }
}

static void
magnusd_audit(const char *action, uint64_t config_hash, const char *result,
             const char *detail)
{
    FILE *file = fopen(magnusd_audit_log_path, "a");
    struct passwd *user;
    time_t now = time(NULL);
    if (file == NULL) return;
    user = getpwuid(getuid());
    fprintf(file, "ts=%lld actor=%s action=%s config_hash=%016llx result=%s",
            (long long) now, user != NULL ? user->pw_name : "unknown", action,
            (unsigned long long) config_hash, result);
    if (detail != NULL && detail[0] != '\0') fprintf(file, " detail=\"%s\"", detail);
    fprintf(file, "\n");
    fclose(file);
}

static char *
magnusd_read_file(const char *path)
{
    FILE *file = fopen(path, "r");
    char *buffer;
    long size;
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return NULL; }
    buffer = malloc((size_t) size + 1);
    if (buffer == NULL) { fclose(file); return NULL; }
    if (size > 0 && fread(buffer, 1, (size_t) size, file) != (size_t) size) {
        free(buffer);
        fclose(file);
        return NULL;
    }
    buffer[size] = '\0';
    fclose(file);
    return buffer;
}

static bool
magnusd_write_file_atomic(const char *path, const char *content)
{
    char tmp_path[MAGNUS_CONFIG_PATH_MAX + 16];
    int fd;
    FILE *file;
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp-XXXXXX", path)
        >= (int) sizeof(tmp_path)) return false;
    fd = mkstemp(tmp_path);
    if (fd < 0) return false;
    file = fdopen(fd, "w");
    if (file == NULL) {
        close(fd);
        unlink(tmp_path);
        return false;
    }
    if (fputs(content, file) == EOF || fflush(file) != 0) {
        fclose(file);
        unlink(tmp_path);
        return false;
    }
    fclose(file);
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return false;
    }
    return true;
}

static bool
magnusd_check_health(unsigned port, int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    struct timeval timeout;
    static const char request[] =
        "GET /healthz HTTP/1.0\r\nHost: magnusd\r\nConnection: close\r\n\r\n";
    char response[64];
    ssize_t received;
    bool ok = false;

    if (fd < 0) return false;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t) port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(fd, (struct sockaddr *) &address, sizeof(address)) == 0
        && send(fd, request, strlen(request), MSG_NOSIGNAL) > 0) {
        received = recv(fd, response, sizeof(response) - 1, 0);
        if (received > 0) {
            response[received] = '\0';
            ok = strncmp(response, "HTTP/1.1 200", 12) == 0
                || strncmp(response, "HTTP/1.0 200", 12) == 0;
        }
    }
    close(fd);
    return ok;
}

static bool
magnusd_child_alive(void)
{
    int status;
    pid_t result;
    if (magnusd_child_pid <= 0) return false;
    result = waitpid(magnusd_child_pid, &status, WNOHANG);
    /* result == pid: reaped it just now, it exited. result < 0 (ECHILD in
     * particular): nothing to wait for -- most likely already reaped out
     * from under us, e.g. if SIGCHLD's disposition was inherited as
     * SIG_IGN, which makes the kernel auto-reap on exit and turns every
     * later waitpid() into ECHILD instead of ever reporting the exit
     * status. Either way the child is gone; only a genuine "still
     * running" (result == 0) counts as alive. */
    if (result == magnusd_child_pid || result < 0) {
        magnusd_child_pid = -1;
        return false;
    }
    return true;
}

/* Polls magnusd_check_health() every MAGNUSD_HEALTH_POLL_INTERVAL_MS until
 * it succeeds or `total_timeout_ms` of *real* wall-clock time has elapsed.
 * This must actually sleep between attempts: a connect() to a port
 * nothing is listening on yet (the common case right after fork(), before
 * the child has finished starting) fails immediately rather than
 * blocking, so a loop that paced itself by counting iterations instead of
 * measuring real time would burn through its entire "timeout" in
 * microseconds and never give the child a real chance to come up --
 * exactly the bug this comment used to not exist for. */
static bool
magnusd_wait_healthy(int total_timeout_ms)
{
    struct timespec started;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &started);
    for (;;) {
        if (!magnusd_child_alive()) return false;
        if (magnusd_check_health(magnusd_port, MAGNUSD_HEALTH_POLL_INTERVAL_MS))
            return true;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - started.tv_sec) * 1000
            + (now.tv_nsec - started.tv_nsec) / 1000000 >= total_timeout_ms)
            return false;
        usleep((useconds_t) MAGNUSD_HEALTH_POLL_INTERVAL_MS * 1000);
    }
}

/* fd the child dup2()s its inherited ready-pipe write end to before
 * exec -- see magnus_ready_fd's own doc comment (src/magnus.c) for
 * what it signals and why. dup2()'s own POSIX guarantee that the
 * *resulting* descriptor never carries FD_CLOEXEC (regardless of
 * whether the source fd did) is what lets this survive the exec()
 * call right after it without any extra fcntl() dance. */
#define MAGNUSD_CHILD_READY_FD 3

/* Roadmap 5e-1: every spawned child always gets --upgrade-socket (see
 * that global's own doc comment) -- an ordinary reload/restart never
 * uses it for anything (nothing ever connects to it unless a real
 * UPGRADE later asks the child to hand its fd off), so this is a pure
 * capability grant with no behavior change for every other spawn
 * reason this function already serves. `binary` and `inherit_from`
 * let magnusd_upgrade() below reuse this same helper for its own,
 * different kind of spawn (a possibly-different binary path, and a
 * source to receive the listener fd from instead of binding fresh);
 * `ready_write_fd` (-1 for every ordinary caller) is the write end of
 * a pipe only magnusd_upgrade() creates -- see its own doc comment for
 * why an upgrade's own health confirmation needs this and plain
 * start/reload do not. */
static bool
magnusd_spawn_child_from(const char *binary, const char *inherit_from,
                         int ready_write_fd)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (ready_write_fd >= 0
            && dup2(ready_write_fd, MAGNUSD_CHILD_READY_FD) < 0)
            _exit(127);
        if (inherit_from != NULL) {
            if (ready_write_fd >= 0) {
                char ready_fd_text[16];
                snprintf(ready_fd_text, sizeof(ready_fd_text), "%d",
                        MAGNUSD_CHILD_READY_FD);
                execl(binary, binary, "--config", magnusd_config_path,
                     "--upgrade-socket", magnusd_upgrade_socket_path,
                     "--inherit-fd", inherit_from, "--ready-fd",
                     ready_fd_text, (char *) NULL);
            } else {
                execl(binary, binary, "--config", magnusd_config_path,
                     "--upgrade-socket", magnusd_upgrade_socket_path,
                     "--inherit-fd", inherit_from, (char *) NULL);
            }
        } else {
            execl(binary, binary, "--config", magnusd_config_path,
                 "--upgrade-socket", magnusd_upgrade_socket_path,
                 (char *) NULL);
        }
        _exit(127);
    }
    magnusd_child_pid = pid;
    return true;
}

static bool
magnusd_spawn_child(void)
{
    return magnusd_spawn_child_from(magnusd_magnus_binary, NULL, -1);
}

static void
magnusd_stop_child(void)
{
    if (magnusd_child_pid <= 0) return;
    kill(magnusd_child_pid, SIGTERM);
    for (int attempt = 0; attempt < 25; attempt++) {
        int status;
        if (waitpid(magnusd_child_pid, &status, WNOHANG) == magnusd_child_pid) {
            magnusd_child_pid = -1;
            return;
        }
        usleep(100000);
    }
    kill(magnusd_child_pid, SIGKILL);
    waitpid(magnusd_child_pid, NULL, 0);
    magnusd_child_pid = -1;
}

/* Re-validates whatever is currently at magnusd_config_path and, if valid,
 * applies it: SIGHUPs the running child (or spawns one if it is not
 * currently alive) and waits for the post-apply health check. On any
 * failure -- invalid config, health check timeout, or the child not
 * surviving -- reverts magnusd_config_path back to the last known good
 * content and, if the child died, restarts it from that reverted config.
 * Always logs the outcome to the audit log. Writes a short human-readable
 * result into `response` (protocol response line, without the trailing
 * newline). */
static void
magnusd_reload(char *response, size_t response_capacity)
{
    magnus_config_t config;
    char error[192];
    char *previous_content;

    if (magnus_config_load(magnusd_config_path, &config, error, sizeof(error))
        != MAGNUS_CONFIG_OK) {
        magnusd_audit("reload", 0, "rejected", error);
        snprintf(response, response_capacity, "REJECTED %s", error);
        return;
    }
    if (config.port != magnusd_port) {
        magnusd_audit("reload", magnus_config_hash(&config), "rejected",
                      "port change requires magnusd restart");
        snprintf(response, response_capacity, "REJECTED port change "
                "requires a magnusd restart (running on %u)", magnusd_port);
        return;
    }

    previous_content = magnusd_read_file(magnusd_rollback_path);
    if (previous_content == NULL) previous_content = strdup("");

    if (magnusd_child_alive()) {
        kill(magnusd_child_pid, SIGHUP);
    } else if (!magnusd_spawn_child()) {
        magnusd_audit("reload", magnus_config_hash(&config), "rejected",
                      "failed to spawn magnus");
        snprintf(response, response_capacity, "REJECTED failed to spawn magnus");
        free(previous_content);
        return;
    }

    if (magnusd_wait_healthy(MAGNUSD_RELOAD_HEALTH_TIMEOUT_MS)) {
        uint64_t hash = magnus_config_hash(&config);
        magnusd_write_file_atomic(magnusd_rollback_path, "");
        {
            char *current = magnusd_read_file(magnusd_config_path);
            if (current != NULL) {
                magnusd_write_file_atomic(magnusd_rollback_path, current);
                free(current);
            }
        }
        magnusd_current_hash = hash;
        magnusd_applied_at = time(NULL);
        strcpy(magnusd_last_action, "reload");
        strcpy(magnusd_last_result, "ok");
        magnusd_audit("reload", hash, "ok", NULL);
        snprintf(response, response_capacity, "OK %016llx",
                (unsigned long long) hash);
        free(previous_content);
        return;
    }

    /* health check failed: revert the file, and if the child did not
     * survive the attempt, restart it from the reverted (last-good)
     * config so the data plane keeps serving. */
    magnusd_write_file_atomic(magnusd_config_path, previous_content);
    free(previous_content);
    if (!magnusd_child_alive()) {
        magnusd_spawn_child();
        magnusd_wait_healthy(MAGNUSD_RELOAD_HEALTH_TIMEOUT_MS);
    }
    strcpy(magnusd_last_action, "reload");
    strcpy(magnusd_last_result, "rolled_back");
    magnusd_audit("reload", magnus_config_hash(&config), "rolled_back",
                  "post-apply health check failed");
    snprintf(response, response_capacity,
            "ROLLED_BACK post-apply health check failed");
}

/* Roadmap 5d-1 (Runtime API expansion): tells the running magnus child
 * to stop accepting new client connections (SIGUSR1) while continuing
 * to serve every connection already in flight -- see magnusd_protocol.h's
 * own MAGNUSD_CMD_DRAIN doc comment for how this differs from RELOAD/
 * SHUTDOWN. Fire-and-forget from magnusd's own side: whether/how many
 * connections are still in flight is the data plane's own concern to
 * report (via /healthz turning 503 and the new magnus_draining /metrics
 * gauge, src/magnus.c), not anything magnusd itself tracks -- the same
 * "magnusd supervises the process, the process reports its own traffic
 * state" division magnusd_reload()'s own post-apply health check
 * already has. A no-op (still reports OK) if the child is not alive at
 * all -- draining a process that is not running is trivially already
 * true, the same reasoning magnusd_reload()'s own child-not-alive
 * branch spawns fresh rather than treating as an error. */
/* Roadmap 5e-1: polls the read end of the readiness pipe magnusd_
 * upgrade() below creates for exactly this one spawn attempt, until
 * either the new child writes its one ready byte (true), the pipe
 * hits EOF because the child's own copy of the write end already
 * closed without ever writing -- crashed, exited, or exec() itself
 * failed, all indistinguishable here and all equally "not ready"
 * (false) -- or `timeout_ms` elapses with neither (false). This is
 * what actually solves the problem magnusd_wait_healthy()'s own
 * shared-port /healthz poll cannot during an upgrade specifically: a
 * pipe only one specific child ever holds the write end of is
 * unambiguous about *which* process answered, where the port is not
 * (see magnus_ready_fd's own doc comment, src/magnus.c, for the real
 * bug this codebase found and fixed by adding it). */
static bool
magnusd_wait_ready_pipe(int read_fd, int timeout_ms)
{
    struct pollfd poll_fd = { .fd = read_fd, .events = POLLIN, .revents = 0 };
    int ready = poll(&poll_fd, 1, timeout_ms);
    char byte;
    ssize_t n;
    if (ready <= 0) return false;
    n = read(read_fd, &byte, 1);
    return n == 1;
}

/* Roadmap 5e-1 (zero-downtime binary upgrade): replaces the running
 * magnus child with a fresh process -- `binary_arg` (possibly a new
 * build at a different path; empty means "the currently configured
 * binary path, re-executed") inheriting the live listener fd from the
 * still-running old child via src/magnus.c's own --upgrade-socket/
 * --inherit-fd handoff, rather than binding a brand-new socket of its
 * own. Never touches the old child until the new one is *proven*
 * healthy -- via a dedicated readiness pipe (magnusd_wait_ready_pipe()
 * above) unique to this one spawn attempt, NOT magnusd_reload()'s own
 * shared-port magnusd_wait_healthy(), which cannot safely disambiguate
 * "the new process is up" from "the old process, deliberately still
 * alive and still serving throughout this whole window, is still
 * answering" -- the old child keeps serving every bit of live traffic
 * the entire time regardless, so a broken new binary (crashes on
 * start, fails its own startup validation, exec() itself failing,
 * whatever) is simply killed and discarded, leaving the old one
 * completely unaffected and never having stopped accepting connections
 * for even a moment. Only once ready does this send the old child the
 * exact same drain signal (SIGUSR1) `magnusctl drain` already does
 * (roadmap 5d-1) -- letting it finish its own in-flight work and exit
 * on its own (magnus.c's own "draining with zero active connections
 * exits" logic), rather than this function waiting around for that
 * itself. This is the "review of the existing SIGHUP-reload atomicity
 * guarantees" the roadmap's own Phase 5 intro asked for, applied here:
 * the same "never commit to the risky action until success is
 * confirmed" discipline magnusd_reload()'s own rollback logic already
 * has, adapted for "swap the whole process" instead of "swap the
 * config a running process reads" -- and, as it turned out, needing a
 * strictly *stronger* confirmation mechanism than reload ever did,
 * for a reason genuinely specific to swapping the whole process while
 * the old one stays alive throughout. */
static void
magnusd_upgrade(const char *binary_arg, char *response,
                size_t response_capacity)
{
    const char *binary = (binary_arg != NULL && binary_arg[0] != '\0')
        ? binary_arg : magnusd_magnus_binary;
    pid_t old_pid;
    int ready_pipe[2];
    bool ready;

    if (!magnusd_child_alive()) {
        magnusd_audit("upgrade", magnusd_current_hash, "rejected",
                      "no running child to upgrade from");
        snprintf(response, response_capacity,
                "REJECTED no running child to upgrade from");
        return;
    }
    old_pid = magnusd_child_pid;

    if (pipe(ready_pipe) < 0) {
        magnusd_audit("upgrade", magnusd_current_hash, "rejected",
                      "failed to create readiness pipe");
        snprintf(response, response_capacity,
                "REJECTED failed to create readiness pipe");
        return;
    }

    if (!magnusd_spawn_child_from(binary, magnusd_upgrade_socket_path,
                                  ready_pipe[1])) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        magnusd_audit("upgrade", magnusd_current_hash, "rejected",
                      "failed to spawn new binary");
        snprintf(response, response_capacity,
                "REJECTED failed to spawn new binary");
        magnusd_child_pid = old_pid; /* spawn_child_from() only ever
            * overwrites this on a successful fork(); a failed one
            * leaves it at whatever fork() itself did not touch, but
            * setting it back explicitly here is cheap insurance
            * against ever silently losing track of the still-healthy
            * old child over a plain fork() failure. */
        return;
    }
    /* The write end now lives on in the child's own fd table (dup2()'d
     * there before exec, magnusd_spawn_child_from()'s own doc comment)
     * -- this parent-side copy must close immediately, not just once
     * ready_pipe reading is done, or magnusd_wait_ready_pipe() below
     * would never see EOF for a child that dies without ever writing
     * (this process's own lingering copy would keep the pipe's write
     * end alive regardless of the child's own fate). */
    close(ready_pipe[1]);

    ready = magnusd_wait_ready_pipe(ready_pipe[0], MAGNUSD_RELOAD_HEALTH_TIMEOUT_MS);
    close(ready_pipe[0]);

    if (!ready) {
        pid_t failed_pid = magnusd_child_pid;
        if (failed_pid > 0) {
            kill(failed_pid, SIGKILL);
            waitpid(failed_pid, NULL, 0);
        }
        magnusd_child_pid = old_pid; /* the old child was never asked
            * to do anything and is still the one actually serving
            * traffic -- restore supervision to it. */
        strcpy(magnusd_last_action, "upgrade");
        strcpy(magnusd_last_result, "rejected");
        magnusd_audit("upgrade", magnusd_current_hash, "rejected",
                      "new binary did not become ready");
        snprintf(response, response_capacity,
                "REJECTED new binary did not become ready "
                "(old pid=%d still serving)", (int) old_pid);
        return;
    }

    /* The new child is healthy and already sharing the listener fd --
     * only now is it safe to tell the old one to stop taking new work. */
    kill(old_pid, SIGUSR1);
    magnusd_applied_at = time(NULL);
    strcpy(magnusd_last_action, "upgrade");
    strcpy(magnusd_last_result, "ok");
    {
        char detail[64];
        snprintf(detail, sizeof(detail), "old_pid=%d new_pid=%d",
                (int) old_pid, (int) magnusd_child_pid);
        magnusd_audit("upgrade", magnusd_current_hash, "ok", detail);
    }
    snprintf(response, response_capacity,
            "OK old_pid=%d new_pid=%d draining old",
            (int) old_pid, (int) magnusd_child_pid);
}

static void
magnusd_drain(char *response, size_t response_capacity)
{
    if (!magnusd_child_alive()) {
        strcpy(magnusd_last_action, "drain");
        strcpy(magnusd_last_result, "ok");
        magnusd_audit("drain", magnusd_current_hash, "ok", "child not running");
        snprintf(response, response_capacity, "OK not running");
        return;
    }
    kill(magnusd_child_pid, SIGUSR1);
    strcpy(magnusd_last_action, "drain");
    strcpy(magnusd_last_result, "ok");
    magnusd_audit("drain", magnusd_current_hash, "ok", NULL);
    snprintf(response, response_capacity, "OK draining");
}

static int
magnusd_create_socket(const char *path)
{
    int fd;
    struct sockaddr_un address = {0};
    if (strlen(path) >= sizeof(address.sun_path)) return -1;
    unlink(path);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, path);
    if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0
        || listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static ssize_t
magnusd_read_line(int fd, char *buffer, size_t capacity)
{
    size_t length = 0;
    while (length + 1 < capacity) {
        char byte;
        ssize_t received = recv(fd, &byte, 1, 0);
        if (received <= 0) break;
        if (byte == '\n') break;
        buffer[length++] = byte;
    }
    buffer[length] = '\0';
    return (ssize_t) length;
}

/* Returns true if magnusd should exit after handling this client
 * (SHUTDOWN was requested). */
static bool
magnusd_handle_client(int client)
{
    /* Roadmap 5e-1: large enough to also carry UPGRADE's own optional
     * "<command> <new-binary-path>" argument -- every other command
     * here is still a bare keyword, this is the first (and, by design,
     * only) one with a wire-level argument at all. */
    char line[MAGNUS_CONFIG_PATH_MAX + 16];
    char *command;
    char *argument;
    char response[320];
    bool stop = false;

    magnusd_read_line(client, line, sizeof(line));
    argument = strchr(line, ' ');
    if (argument != NULL) {
        *argument = '\0';
        argument++;
    }
    command = line;
    if (strcmp(command, MAGNUSD_CMD_STATUS) == 0) {
        snprintf(response, sizeof(response),
                "OK pid=%d config_hash=%016llx applied_at=%lld "
                "last_action=%s last_result=%s port=%u",
                (int) magnusd_child_pid, (unsigned long long) magnusd_current_hash,
                (long long) magnusd_applied_at, magnusd_last_action,
                magnusd_last_result, magnusd_port);
    } else if (strcmp(command, MAGNUSD_CMD_RELOAD) == 0) {
        magnusd_reload(response, sizeof(response));
    } else if (strcmp(command, MAGNUSD_CMD_DRAIN) == 0) {
        magnusd_drain(response, sizeof(response));
    } else if (strcmp(command, MAGNUSD_CMD_UPGRADE) == 0) {
        magnusd_upgrade(argument, response, sizeof(response));
    } else if (strcmp(command, MAGNUSD_CMD_SHUTDOWN) == 0) {
        strcpy(response, "OK shutting down");
        stop = true;
    } else {
        snprintf(response, sizeof(response), "ERROR unknown command");
    }

    {
        size_t length = strlen(response);
        response[length] = '\n';
        send(client, response, length + 1, MSG_NOSIGNAL);
    }
    close(client);
    return stop;
}

static void
magnusd_usage(const char *program)
{
    fprintf(stderr,
            "usage: %s --config <path> --magnus-binary <path> "
            "--socket <path> --audit-log <path>\n", program);
    exit(2);
}

/* See magnus.c's magnus_ensure_standard_fds() for the full story: an
 * inherited fd 0 that *looks* valid at startup (e.g. a pipe end) can still
 * be invalidated later by an unrelated event on its other end, and the
 * next unrelated open() elsewhere then silently lands on it -- this is
 * exactly what surfaced as a magnus reload's new root fd ending up on 0.
 * magnusd forks the very process that bit, and does its own file I/O
 * throughout its life too, so fd 0 is unconditionally pinned to our own
 * /dev/null rather than trusting whatever was inherited. stdout/stderr
 * are left alone when already valid (used for logging); only a genuine
 * gap there is filled. */
static void
magnusd_ensure_standard_fds(void)
{
    int placeholder = open("/dev/null", O_RDWR);
    if (placeholder < 0) return;
    if (placeholder != 0) {
        dup2(placeholder, 0);
        close(placeholder);
    }
    for (int fd = 1; fd <= 2; fd++) {
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
            int opened = open("/dev/null", O_RDWR);
            if (opened >= 0 && opened != fd) close(opened);
        }
    }
}

int
main(int argc, char **argv)
{
    magnus_config_t config;
    char error[192];
    int listener;

    magnusd_ensure_standard_fds();

    /* Reset SIGCHLD to its default disposition before anything forks: an
     * inherited SIG_IGN would make the kernel auto-reap the child on
     * exit, turning every later waitpid() into ECHILD and hiding a crash
     * (magnusd_child_alive() treats that defensively too, but starting
     * from a known-good disposition avoids depending on that). */
    signal(SIGCHLD, SIG_DFL);

    for (int index = 1; index + 1 < argc; index += 2) {
        if (strcmp(argv[index], "--config") == 0) {
            if (strlen(argv[index + 1]) >= sizeof(magnusd_config_path))
                magnusd_usage(argv[0]);
            strcpy(magnusd_config_path, argv[index + 1]);
        } else if (strcmp(argv[index], "--magnus-binary") == 0) {
            if (strlen(argv[index + 1]) >= sizeof(magnusd_magnus_binary))
                magnusd_usage(argv[0]);
            strcpy(magnusd_magnus_binary, argv[index + 1]);
        } else if (strcmp(argv[index], "--socket") == 0) {
            if (strlen(argv[index + 1]) >= sizeof(magnusd_socket_path))
                magnusd_usage(argv[0]);
            strcpy(magnusd_socket_path, argv[index + 1]);
        } else if (strcmp(argv[index], "--audit-log") == 0) {
            if (strlen(argv[index + 1]) >= sizeof(magnusd_audit_log_path))
                magnusd_usage(argv[0]);
            strcpy(magnusd_audit_log_path, argv[index + 1]);
        } else {
            magnusd_usage(argv[0]);
        }
    }
    if (magnusd_config_path[0] == '\0' || magnusd_magnus_binary[0] == '\0'
        || magnusd_socket_path[0] == '\0' || magnusd_audit_log_path[0] == '\0')
        magnusd_usage(argv[0]);
    if (snprintf(magnusd_rollback_path, sizeof(magnusd_rollback_path),
                "%s.last-good", magnusd_config_path)
        >= (int) sizeof(magnusd_rollback_path)) {
        fprintf(stderr, "magnusd: config path too long\n");
        return 2;
    }
    if (snprintf(magnusd_upgrade_socket_path,
                sizeof(magnusd_upgrade_socket_path), "%s.upgrade",
                magnusd_socket_path)
        >= (int) sizeof(magnusd_upgrade_socket_path)) {
        fprintf(stderr, "magnusd: socket path too long\n");
        return 2;
    }

    if (magnus_config_load(magnusd_config_path, &config, error, sizeof(error))
        != MAGNUS_CONFIG_OK) {
        fprintf(stderr, "magnusd: initial config invalid: %s\n", error);
        return 2;
    }
    magnusd_port = config.port;
    {
        char *initial_content = magnusd_read_file(magnusd_config_path);
        if (initial_content != NULL) {
            magnusd_write_file_atomic(magnusd_rollback_path, initial_content);
            free(initial_content);
        }
    }

    if (!magnusd_spawn_child()) {
        fprintf(stderr, "magnusd: failed to spawn magnus\n");
        return 1;
    }
    if (!magnusd_wait_healthy(MAGNUSD_STARTUP_HEALTH_TIMEOUT_MS)) {
        fprintf(stderr, "magnusd: magnus did not become healthy at startup\n");
        magnusd_audit("start", magnus_config_hash(&config), "failed",
                      "initial health check timeout");
        if (magnusd_child_alive()) magnusd_stop_child();
        return 1;
    }
    magnusd_current_hash = magnus_config_hash(&config);
    magnusd_applied_at = time(NULL);
    strcpy(magnusd_last_action, "start");
    strcpy(magnusd_last_result, "ok");
    magnusd_audit("start", magnusd_current_hash, "ok", NULL);

    listener = magnusd_create_socket(magnusd_socket_path);
    if (listener < 0) {
        fprintf(stderr, "magnusd: failed to create control socket '%s': %s\n",
                magnusd_socket_path, strerror(errno));
        magnusd_stop_child();
        return 1;
    }

    signal(SIGINT, magnusd_signal_handler);
    signal(SIGTERM, magnusd_signal_handler);
    signal(SIGCHLD, magnusd_signal_handler);
    signal(SIGPIPE, SIG_IGN);
    fprintf(stderr, "magnusd: supervising pid=%d socket=%s\n",
            (int) magnusd_child_pid, magnusd_socket_path);

    while (magnusd_running) {
        struct pollfd poll_fd = { .fd = listener, .events = POLLIN, .revents = 0 };
        int ready = poll(&poll_fd, 1, MAGNUSD_POLL_TIMEOUT_MS);
        if (ready > 0 && (poll_fd.revents & POLLIN) != 0) {
            int client = accept(listener, NULL, NULL);
            if (client >= 0 && magnusd_handle_client(client)) break;
        }
        if (magnusd_child_reaped) {
            magnusd_child_reaped = 0;
            /* Roadmap 5e-1: SIGCHLD fires for *any* of our children
             * exiting, not just the one magnusd_child_pid currently
             * tracks -- a successful UPGRADE leaves exactly one other
             * child behind (the old, now-fully-drained process, which
             * exits on its own once idle -- magnus.c's own "draining
             * with zero active connections exits" logic) that nothing
             * else here ever waitpid()s for. Reap every already-exited
             * child unconditionally, first, before the tracked-pid
             * crash-detection check below even runs -- otherwise the
             * old process leaks as a zombie forever (harmless to
             * traffic, but a real, unbounded process-table leak across
             * repeated upgrades). WNOHANG in a loop: there can
             * genuinely be more than one exited child coalesced behind
             * a single SIGCHLD delivery (POSIX signals do not queue),
             * and this must never block waiting for one that is not
             * actually done yet. */
            while (waitpid(-1, NULL, WNOHANG) > 0) { }
            if (!magnusd_child_alive()) {
                char *last_good = magnusd_read_file(magnusd_rollback_path);
                magnusd_audit("supervise", magnusd_current_hash, "crashed",
                              "child exited unexpectedly; restarting");
                if (last_good != NULL) {
                    magnusd_write_file_atomic(magnusd_config_path, last_good);
                    free(last_good);
                }
                if (magnusd_spawn_child()
                    && magnusd_wait_healthy(MAGNUSD_STARTUP_HEALTH_TIMEOUT_MS)) {
                    magnusd_audit("supervise", magnusd_current_hash, "ok",
                                  "restarted after crash");
                } else {
                    magnusd_audit("supervise", magnusd_current_hash, "failed",
                                  "restart after crash did not become healthy");
                }
            }
        }
    }

    magnusd_stop_child();
    close(listener);
    unlink(magnusd_socket_path);
    fprintf(stderr, "magnusd: stopped\n");
    return 0;
}
