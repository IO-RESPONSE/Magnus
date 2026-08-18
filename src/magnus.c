#include "magnus_phase.h"
#include "magnus_config.h"
#include "magnus_http.h"
#include "magnus_policy.h"
#include "magnus_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define MAGNUS_VERSION "1.0.0"
#define MAGNUS_MAX_EVENTS 1024
#define MAGNUS_MAX_FDS 65536
#define MAGNUS_INPUT_LIMIT 8192
#define MAGNUS_OUTPUT_LIMIT 2048
#define MAGNUS_IDLE_SECONDS 30
#define MAGNUS_HEADER_TIMEOUT_SECONDS 10
#define MAGNUS_PROXY_BUFFER 16384
#define MAGNUS_INITIAL_INPUT 2048
#define MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS 5
#define MAGNUS_PROXY_READ_TIMEOUT_SECONDS 10
#define MAGNUS_PROXY_HEADER_LIMIT MAGNUS_PROXY_BUFFER
#define MAGNUS_PROXY_SANITIZED_LIMIT 4096
#define MAGNUS_PROXY_MAX_ATTEMPTS 2
#define MAGNUS_HEALTH_CHECK_INTERVAL_SECONDS 5
#define MAGNUS_HEALTH_PROBE_TIMEOUT_SECONDS 2
#define MAGNUS_CLUSTER_FAILURE_THRESHOLD 3
#define MAGNUS_CLUSTER_COOLDOWN_MS 5000
#define MAGNUS_RATE_TABLE_SIZE 512

typedef struct {
    int fd;
    char *input;
    size_t input_capacity;
    size_t input_length;
    char output[MAGNUS_OUTPUT_LIMIT];
    size_t output_length;
    size_t output_sent;
    bool close_after_write;
    int file_fd;
    off_t file_offset;
    off_t file_length;
    SSL *tls;
    bool tls_ready;
    char *file_buffer;
    size_t file_buffer_length;
    size_t file_buffer_sent;
    int upstream_fd;
    bool proxy_active;
    bool proxy_connected;
    bool proxy_headers_sent;
    bool proxy_eof;
    char proxy_request[512];
    size_t proxy_request_length;
    size_t proxy_request_sent;
    char *proxy_buffer;
    size_t proxy_buffer_length;
    size_t proxy_buffer_sent;
    bool proxy_headers_received;
    size_t proxy_header_accum;
    char *proxy_header_out;
    size_t proxy_header_out_length;
    size_t proxy_header_out_sent;
    bool proxy_response_started;
    char proxy_request_id[33];
    time_t proxy_connect_started;
    time_t proxy_last_activity;
    size_t proxy_endpoint_index;
    unsigned proxy_attempt;
    char proxy_affinity_key[64];
    bool proxy_issue_affinity_cookie;
    /* client-side method/target of the request currently being proxied,
     * captured at proxy start so the completion access-log line (written
     * later, asynchronously, once the upstream response arrives) can
     * still report what the client actually asked for. */
    char proxy_log_method[8];
    char proxy_log_target[256];
    struct in_addr client_address;
    /* set when this connection was accepted on the admin-only Unix
     * socket listener (see magnus_admin_listener): restricted to
     * /healthz and /metrics, and exempt from rate limiting since access
     * is already gated by that socket's filesystem permissions. */
    bool admin_only;
    uint64_t request_started_ms;
    /* Absolute deadline (from accept time) for finishing the *first*
     * request's headers, checked in magnus_expire_idle() independently of
     * MAGNUS_IDLE_SECONDS: the idle timer resets on every byte received,
     * so a slowloris-style client trickling one byte every few seconds
     * would never trip it and could hold a connection (and its input
     * buffer and fd) open indefinitely. No longer enforced once
     * request_started_ms shows a request has actually completed --
     * legitimate keep-alive idling between requests is fine and is what
     * MAGNUS_IDLE_SECONDS is for. */
    time_t header_deadline;
    time_t last_active;
} magnus_connection_t;

static volatile sig_atomic_t magnus_running = 1;
static magnus_phase_engine_t magnus_phases;
static magnus_connection_t *magnus_connections[MAGNUS_MAX_FDS];
static int magnus_root_fd = -1;
static SSL_CTX *magnus_tls_context;
static magnus_cluster_t magnus_cluster;
static bool magnus_upstream_enabled;
static magnus_connection_t *magnus_upstream_owner[MAGNUS_MAX_FDS];
/* Health-probe fds share the same epoll_fd as client/upstream connections.
 * Index i+1 (0 means "not a probe fd") names the cluster endpoint a given
 * fd is probing, so the main dispatch loop can route its events here
 * instead of treating it as client or proxied-upstream traffic. */
static int magnus_health_probe_owner[MAGNUS_MAX_FDS];
static int magnus_health_probe_fd[MAGNUS_MAX_UPSTREAMS];
static time_t magnus_health_probe_started[MAGNUS_MAX_UPSTREAMS];
static time_t magnus_health_last_probe[MAGNUS_MAX_UPSTREAMS];
static uint64_t magnus_connections_total;
static uint64_t magnus_connections_active;
static uint64_t magnus_requests_total;
static uint64_t magnus_responses_4xx;
static uint64_t magnus_responses_5xx;
static uint64_t magnus_bytes_sent;
static uint64_t magnus_rate_limited_total;

/* Access log: off/on, and 1-in-N sampling, both configurable (magnus_config
 * access_log / access_log_sample) so a busy deployment can turn the log
 * down instead of paying a syscall per request. Buffered in memory and
 * flushed with a single write() -- on the once-a-second sweep, when the
 * buffer is nearly full, and at shutdown -- rather than one fprintf() per
 * request; a full buffer at flush time is handled by flushing first and
 * retrying rather than silently growing without bound. */
#define MAGNUS_ACCESS_LOG_BUFFER 8192
static bool magnus_access_log_enabled = true;
static unsigned magnus_access_log_sample = 1;
static uint64_t magnus_access_log_seen;
static char magnus_access_log_buffer[MAGNUS_ACCESS_LOG_BUFFER];
static size_t magnus_access_log_length;

/* Request latency histogram (milliseconds, from "headers fully parsed" to
 * "response prepared" -- for a proxied request that means through to the
 * upstream's response headers arriving, not just the connect). Bucket
 * boundaries are intentionally coarse and few: this is a lightweight
 * gateway's own view of its tail, not a general-purpose metrics library. */
static const double magnus_latency_bucket_bounds_ms[] =
    { 1, 5, 10, 50, 100, 500, 1000, 5000 };
#define MAGNUS_LATENCY_BUCKETS \
    (sizeof(magnus_latency_bucket_bounds_ms) \
     / sizeof(magnus_latency_bucket_bounds_ms[0]))
static uint64_t magnus_latency_bucket_counts[MAGNUS_LATENCY_BUCKETS];
static uint64_t magnus_latency_count;
static double magnus_latency_sum_ms;

/* Admin-only Unix domain socket listener (magnus_config admin_socket /
 * --admin-socket): serves only /healthz and /metrics, exempt from rate
 * limiting, access controlled by the socket file's own permissions rather
 * than an in-process RBAC layer. When enabled, /metrics is withdrawn from
 * the regular (TCP) listener entirely -- /healthz stays there too, since
 * that is what a load balancer on the public port needs to reach. */
static int magnus_admin_listener = -1;
static bool magnus_admin_enabled;
static char magnus_admin_socket_path[MAGNUS_CONFIG_PATH_MAX];

/* Per-client-IP ingress rate limiting. Disabled unless --rate-limit is
 * given. A bounded linear-scan table keeps memory flat regardless of how
 * many distinct clients are ever seen; once full, the least-recently-seen
 * entry is evicted to make room for a new client -- acceptable for a
 * lightweight gateway's admission control, not a precise per-IP ledger. */
typedef struct {
    struct in_addr address;
    bool in_use;
    time_t last_seen;
    magnus_rate_limit_t limiter;
} magnus_rate_entry_t;

static bool magnus_rate_limit_enabled;
static double magnus_rate_limit_rps;
static double magnus_rate_limit_burst;
static magnus_rate_entry_t magnus_rate_table[MAGNUS_RATE_TABLE_SIZE];

/* --config <path> mode: magnus_config_path holds the file SIGHUP reload
 * re-reads. Without it (plain --port/--root/... flags), SIGHUP has
 * nothing to reload against and is a documented no-op. */
static bool magnus_config_mode;
static char magnus_config_path[MAGNUS_CONFIG_PATH_MAX];
static unsigned magnus_listen_port;
static volatile sig_atomic_t magnus_reload_requested;

static int magnus_update_interest(int epoll_fd,
                                  magnus_connection_t *connection,
                                  uint32_t events);
static ssize_t magnus_socket_write(magnus_connection_t *connection,
                                   const void *buffer, size_t length);
static void magnus_prepare_response(magnus_connection_t *connection,
                                    unsigned status, const char *reason,
                                    const char *content_type, const char *body,
                                    bool head_only, bool close_connection,
                                    magnus_request_t *request);
static char *magnus_find_header_end(char *buffer, size_t length);
static uint64_t magnus_now_ms(void);
static int magnus_proxy_pick_and_start(int epoll_fd,
                                       magnus_connection_t *connection,
                                       const magnus_request_t *request,
                                       const char *client_affinity_key);

static void
magnus_signal_handler(int signal_number)
{
    (void) signal_number;
    magnus_running = 0;
}

static void
magnus_reload_signal_handler(int signal_number)
{
    (void) signal_number;
    magnus_reload_requested = 1;
}

/* Fills `out[32]` (plus a NUL terminator, so `out` must be at least 33
 * bytes) with a random 128-bit value hex-encoded. Used both for the
 * per-request trace id and for freshly minted cluster affinity tokens. */
static void
magnus_generate_token(char *out)
{
    unsigned char random_bytes[16];
    static const char hex[] = "0123456789abcdef";
    static uint64_t fallback_counter;
    size_t index;

    if (getrandom(random_bytes, sizeof(random_bytes), GRND_NONBLOCK)
        != (ssize_t) sizeof(random_bytes)) {
        struct timespec now;
        uint64_t seed;
        clock_gettime(CLOCK_MONOTONIC, &now);
        seed = (uint64_t) now.tv_nsec ^ (uint64_t) now.tv_sec
               ^ (uint64_t) getpid() ^ ++fallback_counter;
        for (index = 0; index < sizeof(random_bytes); index++) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            random_bytes[index] = (unsigned char) seed;
        }
    }
    for (index = 0; index < sizeof(random_bytes); index++) {
        out[index * 2] = hex[random_bytes[index] >> 4];
        out[index * 2 + 1] = hex[random_bytes[index] & 0x0f];
    }
    out[32] = '\0';
}

static int
magnus_trace_handler(magnus_request_t *request, void *data)
{
    (void) data;
    magnus_generate_token(request->request_id);
    return 0;
}

static void
magnus_close_connection(int epoll_fd, magnus_connection_t *connection)
{
    int fd = connection->fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
    if (connection->file_fd >= 0) close(connection->file_fd);
    if (connection->tls != NULL) SSL_free(connection->tls);
    free(connection->input);
    free(connection->file_buffer);
    free(connection->proxy_buffer);
    free(connection->proxy_header_out);
    if (magnus_connections_active > 0) magnus_connections_active--;
    if (connection->upstream_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->upstream_fd, NULL);
        magnus_upstream_owner[connection->upstream_fd] = NULL;
        close(connection->upstream_fd);
    }
    magnus_connections[fd] = NULL;
    free(connection);
}

static uint64_t
magnus_now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t) now.tv_sec * 1000 + (uint64_t) now.tv_nsec / 1000000;
}

static void
magnus_access_log_flush(void)
{
    if (magnus_access_log_length == 0) return;
    /* Best-effort: a partial or failed write() here would otherwise mean
     * looping or blocking in the middle of the event loop over a log
     * sink under pressure, which the event loop must never do. Dropping
     * log bytes beats stalling every connection to protect them. */
    ssize_t ignored = write(STDERR_FILENO, magnus_access_log_buffer,
                            magnus_access_log_length);
    (void) ignored;
    magnus_access_log_length = 0;
}

static void
magnus_access_log(const char *request_id, const char *method,
                  const char *target, unsigned status, double latency_ms)
{
    int written;
    if (!magnus_access_log_enabled) return;
    magnus_access_log_seen++;
    if (magnus_access_log_sample > 1
        && (magnus_access_log_seen % magnus_access_log_sample) != 0) return;
    written = snprintf(magnus_access_log_buffer + magnus_access_log_length,
        sizeof(magnus_access_log_buffer) - magnus_access_log_length,
        "access request_id=%s method=%s target=%s status=%u "
        "latency_ms=%.2f\n", request_id, method, target, status, latency_ms);
    if (written < 0) return;
    if ((size_t) written >= sizeof(magnus_access_log_buffer)
                            - magnus_access_log_length) {
        magnus_access_log_flush();
        written = snprintf(magnus_access_log_buffer,
            sizeof(magnus_access_log_buffer),
            "access request_id=%s method=%s target=%s status=%u "
            "latency_ms=%.2f\n", request_id, method, target, status,
            latency_ms);
        if (written > 0 && (size_t) written < sizeof(magnus_access_log_buffer))
            magnus_access_log_length = (size_t) written;
        return;
    }
    magnus_access_log_length += (size_t) written;
}

static void
magnus_record_latency(double latency_ms)
{
    size_t index;
    magnus_latency_count++;
    magnus_latency_sum_ms += latency_ms;
    for (index = 0; index < MAGNUS_LATENCY_BUCKETS; index++) {
        if (latency_ms <= magnus_latency_bucket_bounds_ms[index])
            magnus_latency_bucket_counts[index]++;
    }
}

/* Admits or rejects one request from `address` against the shared
 * per-client-IP token bucket table. Always returns true when rate
 * limiting is disabled. Finds (or creates, evicting the oldest entry if
 * the bounded table is full) that client's bucket and consumes a token. */
static bool
magnus_rate_check(struct in_addr address, time_t now)
{
    uint64_t now_ms = (uint64_t) now * 1000;
    size_t free_slot = MAGNUS_RATE_TABLE_SIZE;
    size_t oldest_slot = 0;
    time_t oldest_seen = 0;
    size_t index;

    if (!magnus_rate_limit_enabled) return true;

    for (index = 0; index < MAGNUS_RATE_TABLE_SIZE; index++) {
        magnus_rate_entry_t *entry = &magnus_rate_table[index];
        if (entry->in_use && entry->address.s_addr == address.s_addr) {
            entry->last_seen = now;
            return magnus_rate_allow(&entry->limiter, now_ms);
        }
        if (!entry->in_use && free_slot == MAGNUS_RATE_TABLE_SIZE) {
            free_slot = index;
        }
        if (index == 0 || entry->last_seen < oldest_seen) {
            oldest_seen = entry->last_seen;
            oldest_slot = index;
        }
    }

    index = free_slot != MAGNUS_RATE_TABLE_SIZE ? free_slot : oldest_slot;
    magnus_rate_table[index].address = address;
    magnus_rate_table[index].in_use = true;
    magnus_rate_table[index].last_seen = now;
    magnus_rate_init(&magnus_rate_table[index].limiter, magnus_rate_limit_rps,
                     magnus_rate_limit_burst, now_ms);
    return magnus_rate_allow(&magnus_rate_table[index].limiter, now_ms);
}

static bool
magnus_endpoint_sockaddr(size_t index, struct sockaddr_in *out)
{
    if (index >= magnus_cluster.count) return false;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t) magnus_cluster.endpoints[index].port);
    return inet_pton(AF_INET, magnus_cluster.endpoints[index].address,
                     &out->sin_addr) == 1;
}

/* Opens a non-blocking connect() to cluster endpoint `endpoint_index`,
 * reusing connection->proxy_request (already built by the caller) and
 * (re)allocating connection->proxy_buffer if needed, and registers the
 * socket with epoll. Resets every per-attempt proxy_* field, so this is
 * safe to call again for a retry once the previous attempt's upstream has
 * been torn down via magnus_proxy_teardown_upstream(). Returns 0 once the
 * attempt is in flight, -1 on immediate failure (the caller records the
 * failure and decides whether to retry or give up). */
static int
magnus_proxy_connect_endpoint(int epoll_fd, magnus_connection_t *connection,
                              size_t endpoint_index)
{
    struct sockaddr_in address;
    struct epoll_event event;
    int result;
    int fd;

    if (!magnus_endpoint_sockaddr(endpoint_index, &address)) return -1;
    if (connection->proxy_buffer == NULL) {
        connection->proxy_buffer = malloc(MAGNUS_PROXY_BUFFER);
        if (connection->proxy_buffer == NULL) return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        return -1;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    connection->upstream_fd = fd;
    connection->proxy_active = true;
    connection->proxy_connected = result == 0;
    connection->proxy_request_sent = 0;
    connection->proxy_headers_sent = false;
    connection->proxy_headers_received = false;
    connection->proxy_header_accum = 0;
    connection->proxy_eof = false;
    connection->proxy_response_started = false;
    connection->proxy_endpoint_index = endpoint_index;
    connection->proxy_connect_started = time(NULL);
    connection->proxy_last_activity = connection->proxy_connect_started;
    connection->close_after_write = true;
    magnus_upstream_owner[fd] = connection;
    event = (struct epoll_event) { .events = EPOLLOUT | EPOLLRDHUP,
                                   .data.fd = fd };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        magnus_upstream_owner[fd] = NULL;
        close(fd);
        connection->upstream_fd = -1;
        connection->proxy_active = false;
        return -1;
    }
    return 0;
}

/* The MAGNUS_AFFINITY cookie value this gateway issues encodes the target
 * cluster endpoint directly as a 2-hex-digit prefix (e.g. "05-<random>"),
 * so a returning client's sticky endpoint can be recovered by a plain
 * integer parse instead of re-deriving it by hashing -- precise, and
 * independent of magnus_cluster_select()'s unrelated hash-based affinity
 * mode (kept for other potential callers). Returns false if `cookie` is
 * NULL/empty or not in this format. */
static bool
magnus_decode_affinity_cookie(const char *cookie, size_t *out_index)
{
    char *end;
    unsigned long value;
    if (cookie == NULL || cookie[0] == '\0') return false;
    errno = 0;
    value = strtoul(cookie, &end, 16);
    if (errno != 0 || end == cookie || *end != '-') return false;
    *out_index = (size_t) value;
    return true;
}

static void
magnus_encode_affinity_cookie(char *out, size_t out_capacity,
                              size_t endpoint_index)
{
    char token[33];
    magnus_generate_token(token);
    snprintf(out, out_capacity, "%02zx-%s", endpoint_index, token);
}

/* Builds the outbound proxy request once, then selects a healthy cluster
 * endpoint and connects to it, retrying against a different endpoint -- up
 * to MAGNUS_PROXY_MAX_ATTEMPTS total attempts -- if the connect itself
 * fails immediately. Returns 0 if an attempt is now in flight (client
 * interest already updated to watch for abort), -1 if no healthy endpoint
 * was available or the retry budget was exhausted.
 *
 * Selection uses session affinity: if the client's request carried a valid
 * MAGNUS_AFFINITY cookie, its encoded endpoint is preferred for this first
 * attempt only (magnus_cluster_select_sticky() itself already falls back
 * to round-robin if that endpoint is unavailable); a client with no cookie
 * gets a plain round-robin pick, exactly as if affinity did not exist.
 * Either way, any retry after a failed attempt always falls back to plain
 * round-robin rather than insisting on the same (just-failed) endpoint
 * again -- a single connect failure does not yet flip passive health
 * unhealthy, so re-trying "sticky" here would silently double the wait
 * instead of actually finding a working endpoint. A fresh cookie is minted
 * (for magnus_proxy_receive_headers() to issue via Set-Cookie once headers
 * arrive) whenever the client did not already carry a usable one. */
static int
magnus_proxy_pick_and_start(int epoll_fd, magnus_connection_t *connection,
                            const magnus_request_t *request,
                            const char *client_affinity_cookie)
{
    int written;
    size_t preferred_index;
    bool sticky;

    written = snprintf(connection->proxy_request,
                       sizeof(connection->proxy_request),
                       "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                       "Connection: close\r\nX-Magnus-Request-Id: %s\r\n\r\n",
                       request->method, request->path + 6, request->request_id);
    if (written < 0 || (size_t) written >= sizeof(connection->proxy_request))
        return -1;
    connection->proxy_request_length = (size_t) written;
    memcpy(connection->proxy_request_id, request->request_id,
          sizeof(connection->proxy_request_id));
    connection->proxy_attempt = 0;
    sticky = magnus_decode_affinity_cookie(client_affinity_cookie,
                                           &preferred_index);
    connection->proxy_issue_affinity_cookie = !sticky;

    for (;;) {
        int endpoint = sticky
            ? magnus_cluster_select_sticky(&magnus_cluster, magnus_now_ms(),
                                           preferred_index)
            : magnus_cluster_select(&magnus_cluster, magnus_now_ms(), NULL);
        if (endpoint < 0) return -1;
        if (sticky) {
            sticky = false;
        } else if (connection->proxy_attempt > 0) {
            /* deviating from the client's original sticky target (or from
             * plain round-robin) because a previous attempt failed: the
             * cookie must be refreshed to reflect the endpoint actually
             * used, not what a retried/failed attempt implied. */
            connection->proxy_issue_affinity_cookie = true;
        }
        connection->proxy_attempt++;
        if (magnus_proxy_connect_endpoint(epoll_fd, connection,
                                          (size_t) endpoint) == 0) {
            if (connection->proxy_issue_affinity_cookie) {
                magnus_encode_affinity_cookie(connection->proxy_affinity_key,
                                              sizeof(connection->proxy_affinity_key),
                                              (size_t) endpoint);
            }
            return magnus_update_interest(epoll_fd, connection, EPOLLRDHUP);
        }
        magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                              magnus_now_ms());
        if (connection->proxy_attempt >= MAGNUS_PROXY_MAX_ATTEMPTS) return -1;
    }
}

static void
magnus_proxy_teardown_upstream(int epoll_fd, magnus_connection_t *connection)
{
    if (connection->upstream_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->upstream_fd, NULL);
        magnus_upstream_owner[connection->upstream_fd] = NULL;
        close(connection->upstream_fd);
        connection->upstream_fd = -1;
    }
    connection->proxy_active = false;
    free(connection->proxy_buffer);
    connection->proxy_buffer = NULL;
    free(connection->proxy_header_out);
    connection->proxy_header_out = NULL;
}

/* Ends an in-flight proxy attempt before any response bytes have reached
 * the client: tears the upstream connection down and switches the client
 * connection to a synthesized error response. Must only be called while
 * connection->proxy_response_started is still false -- once the status
 * line has been forwarded downstream a clean status-coded error is no
 * longer possible and magnus_proxy_abort() must be used instead. */
static int
magnus_proxy_fail(int epoll_fd, magnus_connection_t *connection,
                  unsigned status, const char *reason)
{
    magnus_request_t request = {0};
    magnus_proxy_teardown_upstream(epoll_fd, connection);
    memcpy(request.request_id, connection->proxy_request_id,
          sizeof(request.request_id));
    magnus_prepare_response(connection, status, reason, "text/plain",
                            status == 504 ? "gateway timeout\n"
                                          : "bad gateway\n",
                            false, true, &request);
    {
        double latency_ms = (double) (magnus_now_ms()
                                      - connection->request_started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(request.request_id, connection->proxy_log_method,
                          connection->proxy_log_target, status, latency_ms);
    }
    return magnus_update_interest(epoll_fd, connection, EPOLLOUT | EPOLLRDHUP);
}

/* Ends an in-flight proxy attempt after response bytes were already
 * forwarded to the client, so the connection can only be aborted (client
 * abort / truncated response), not answered with a fresh status code. */
static int
magnus_proxy_abort(int epoll_fd, magnus_connection_t *connection)
{
    magnus_proxy_teardown_upstream(epoll_fd, connection);
    return -1;
}

/* Records a connect-stage failure for the endpoint currently in flight and
 * either retries against a different healthy endpoint -- bounded by
 * MAGNUS_PROXY_MAX_ATTEMPTS total attempts -- or gives up with a clean
 * status-coded error. Must only be called while
 * connection->proxy_response_started is still false: a connect-stage
 * failure by definition means no response bytes have reached the client
 * yet, so retrying (or eventually failing cleanly) is always safe here. */
static int
magnus_proxy_connect_failed(int epoll_fd, magnus_connection_t *connection,
                            unsigned give_up_status,
                            const char *give_up_reason)
{
    magnus_cluster_result(&magnus_cluster, connection->proxy_endpoint_index,
                          false, magnus_now_ms());
    magnus_proxy_teardown_upstream(epoll_fd, connection);
    if (connection->proxy_attempt < MAGNUS_PROXY_MAX_ATTEMPTS) {
        /* never sticky here: this is already a retry after a failure, so
         * insisting on the original (just-failed) preferred endpoint again
         * would only waste the remaining attempt budget on it. */
        int endpoint = magnus_cluster_select(&magnus_cluster, magnus_now_ms(),
                                             NULL);
        if (endpoint >= 0) {
            connection->proxy_attempt++;
            if (magnus_proxy_connect_endpoint(epoll_fd, connection,
                                              (size_t) endpoint) == 0) {
                /* deviated from whatever selection strategy produced the
                 * failed attempt: refresh the cookie to match reality. */
                connection->proxy_issue_affinity_cookie = true;
                magnus_encode_affinity_cookie(connection->proxy_affinity_key,
                                              sizeof(connection->proxy_affinity_key),
                                              (size_t) endpoint);
                return magnus_update_interest(epoll_fd, connection,
                                              EPOLLRDHUP);
            }
            magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                                  magnus_now_ms());
        }
    }
    return magnus_proxy_fail(epoll_fd, connection, give_up_status,
                             give_up_reason);
}

static int
magnus_proxy_flush(int epoll_fd, magnus_connection_t *connection)
{
    while (connection->proxy_header_out != NULL
           && connection->proxy_header_out_sent
              < connection->proxy_header_out_length) {
        ssize_t sent = magnus_socket_write(connection,
            connection->proxy_header_out + connection->proxy_header_out_sent,
            connection->proxy_header_out_length
                - connection->proxy_header_out_sent);
        if (sent > 0) {
            connection->proxy_header_out_sent += (size_t) sent;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return magnus_update_interest(epoll_fd, connection,
                                          EPOLLOUT | EPOLLRDHUP);
        return magnus_proxy_abort(epoll_fd, connection);
    }
    if (connection->proxy_header_out != NULL) {
        free(connection->proxy_header_out);
        connection->proxy_header_out = NULL;
        connection->proxy_response_started = true;
    }
    while (connection->proxy_buffer_sent < connection->proxy_buffer_length) {
        ssize_t sent = magnus_socket_write(connection,
            connection->proxy_buffer + connection->proxy_buffer_sent,
            connection->proxy_buffer_length - connection->proxy_buffer_sent);
        if (sent > 0) {
            connection->proxy_buffer_sent += (size_t) sent;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
            connection->proxy_response_started = true;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return magnus_update_interest(epoll_fd, connection,
                                          EPOLLOUT | EPOLLRDHUP);
        return magnus_proxy_abort(epoll_fd, connection);
    }
    connection->proxy_buffer_length = 0;
    connection->proxy_buffer_sent = 0;
    if (connection->proxy_eof) return magnus_proxy_abort(epoll_fd, connection);
    if (connection->upstream_fd >= 0) {
        struct epoll_event event = { .events = EPOLLIN | EPOLLRDHUP,
                                     .data.fd = connection->upstream_fd };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd, &event);
    }
    return magnus_update_interest(epoll_fd, connection, EPOLLRDHUP);
}

/* Accumulates the upstream response's status line + header block (which
 * may arrive split across several recv() calls) into connection->proxy_buffer,
 * then rewrites it via magnus_proxy_sanitize_response_headers() once the
 * terminating blank line is found. Leftover bytes already read past the
 * header block are preserved as the first chunk of body. Returns 1 while
 * still waiting for more header bytes, 0 once handed off to
 * magnus_proxy_flush(), or a magnus_proxy_fail()/-1 result on error. */
static int
magnus_proxy_receive_headers(int epoll_fd, magnus_connection_t *connection)
{
    char *body_start;
    size_t header_length;
    size_t leftover;
    char header_copy[MAGNUS_PROXY_HEADER_LIMIT + 1];
    char sanitized[MAGNUS_PROXY_SANITIZED_LIMIT];
    unsigned upstream_status;
    int sanitized_length;

    while (connection->proxy_header_accum < MAGNUS_PROXY_BUFFER) {
        ssize_t received = recv(connection->upstream_fd,
            connection->proxy_buffer + connection->proxy_header_accum,
            MAGNUS_PROXY_BUFFER - connection->proxy_header_accum, 0);
        if (received > 0) {
            connection->proxy_header_accum += (size_t) received;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
            /* Stop as soon as the header block is complete instead of
             * greedily draining the socket: for a fast/bursty upstream
             * (the whole response already sitting in the kernel receive
             * buffer) that avoids reading all the way up to
             * MAGNUS_PROXY_BUFFER, which would otherwise make the next
             * recv() request zero bytes -- and recv() with length 0
             * legitimately returns 0, indistinguishable here from a real
             * peer close, which would misreport upstream EOF and truncate
             * the response. Any body bytes left unread simply stay in the
             * kernel buffer for the normal body-relay path to pick up. */
            if (magnus_find_header_end(connection->proxy_buffer,
                                       connection->proxy_header_accum) != NULL) {
                break;
            }
            continue;
        }
        if (received == 0) {
            connection->proxy_eof = true;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    }

    body_start = magnus_find_header_end(connection->proxy_buffer,
                                        connection->proxy_header_accum);
    if (body_start == NULL) {
        if (connection->proxy_eof)
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
        if (connection->proxy_header_accum == MAGNUS_PROXY_BUFFER)
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
        return 1;
    }

    header_length = (size_t) (body_start - connection->proxy_buffer);
    leftover = connection->proxy_header_accum - header_length;
    if (header_length > MAGNUS_PROXY_HEADER_LIMIT)
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    memcpy(header_copy, connection->proxy_buffer, header_length);
    header_copy[header_length] = '\0';
    sanitized_length = magnus_proxy_sanitize_response_headers(header_copy,
        header_length, sanitized, sizeof(sanitized), &upstream_status,
        connection->proxy_issue_affinity_cookie
            ? connection->proxy_affinity_key : NULL);
    if (sanitized_length < 0)
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");

    connection->proxy_header_out = malloc((size_t) sanitized_length);
    if (connection->proxy_header_out == NULL)
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    memcpy(connection->proxy_header_out, sanitized, (size_t) sanitized_length);
    connection->proxy_header_out_length = (size_t) sanitized_length;
    connection->proxy_header_out_sent = 0;
    memmove(connection->proxy_buffer, body_start, leftover);
    connection->proxy_buffer_length = leftover;
    connection->proxy_buffer_sent = 0;
    connection->proxy_headers_received = true;
    magnus_cluster_result(&magnus_cluster, connection->proxy_endpoint_index,
                          true, magnus_now_ms());
    magnus_requests_total++;
    if (upstream_status >= 500) magnus_responses_5xx++;
    else if (upstream_status >= 400) magnus_responses_4xx++;
    {
        double latency_ms = (double) (magnus_now_ms()
                                      - connection->request_started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(connection->proxy_request_id,
                          connection->proxy_log_method,
                          connection->proxy_log_target, upstream_status,
                          latency_ms);
    }
    return magnus_proxy_flush(epoll_fd, connection);
}

static int
magnus_handle_upstream(int epoll_fd, magnus_connection_t *connection,
                       uint32_t flags)
{
    struct epoll_event event;
    if ((flags & (EPOLLERR | EPOLLHUP)) != 0) {
        if (connection->proxy_response_started)
            return magnus_proxy_abort(epoll_fd, connection);
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    }
    if (!connection->proxy_connected) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(connection->upstream_fd, SOL_SOCKET, SO_ERROR,
                       &error, &length) < 0 || error != 0)
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                               "Bad Gateway");
        connection->proxy_connected = true;
        connection->proxy_last_activity = time(NULL);
    }
    while (!connection->proxy_headers_sent) {
        ssize_t sent = send(connection->upstream_fd,
            connection->proxy_request + connection->proxy_request_sent,
            connection->proxy_request_length - connection->proxy_request_sent,
            MSG_NOSIGNAL);
        if (sent > 0) {
            connection->proxy_request_sent += (size_t) sent;
            connection->proxy_last_activity = time(NULL);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                               "Bad Gateway");
        }
        if (connection->proxy_request_sent == connection->proxy_request_length)
            connection->proxy_headers_sent = true;
    }
    if (!connection->proxy_headers_received) {
        if ((flags & (EPOLLIN | EPOLLRDHUP)) != 0) {
            return magnus_proxy_receive_headers(epoll_fd, connection);
        }
        event = (struct epoll_event) { .events = EPOLLIN | EPOLLRDHUP,
                                       .data.fd = connection->upstream_fd };
        return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd,
                         &event);
    }
    if (connection->proxy_buffer_length != 0) return 0;
    if ((flags & EPOLLIN) != 0 || (flags & EPOLLRDHUP) != 0) {
        ssize_t received = recv(connection->upstream_fd, connection->proxy_buffer,
                                MAGNUS_PROXY_BUFFER, 0);
        if (received > 0) {
            connection->proxy_buffer_length = (size_t) received;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
        } else if (received == 0) {
            connection->proxy_eof = true;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return magnus_proxy_abort(epoll_fd, connection);
        }
        if (connection->proxy_buffer_length != 0 || connection->proxy_eof)
            return magnus_proxy_flush(epoll_fd, connection);
    }
    event = (struct epoll_event) { .events = EPOLLIN | EPOLLRDHUP,
                                   .data.fd = connection->upstream_fd };
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd, &event);
}

static ssize_t
magnus_socket_read(magnus_connection_t *connection, void *buffer, size_t length)
{
    int result;
    int ssl_error;
    if (connection->tls == NULL)
        return recv(connection->fd, buffer, length, 0);
    result = SSL_read(connection->tls, buffer, (int) length);
    if (result > 0) return result;
    ssl_error = SSL_get_error(connection->tls, result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    if (ssl_error == SSL_ERROR_ZERO_RETURN) return 0;
    errno = EIO;
    return -1;
}

static ssize_t
magnus_socket_write(magnus_connection_t *connection, const void *buffer,
                    size_t length)
{
    int result;
    int ssl_error;
    if (connection->tls == NULL)
        return send(connection->fd, buffer, length, MSG_NOSIGNAL);
    result = SSL_write(connection->tls, buffer, (int) length);
    if (result > 0) return result;
    ssl_error = SSL_get_error(connection->tls, result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    errno = EIO;
    return -1;
}

static int
magnus_tls_handshake(int epoll_fd, magnus_connection_t *connection)
{
    int result = SSL_accept(connection->tls);
    int ssl_error;
    if (result == 1) {
        connection->tls_ready = true;
        return magnus_update_interest(epoll_fd, connection, EPOLLIN | EPOLLRDHUP);
    }
    ssl_error = SSL_get_error(connection->tls, result);
    if (ssl_error == SSL_ERROR_WANT_READ)
        return magnus_update_interest(epoll_fd, connection, EPOLLIN | EPOLLRDHUP);
    if (ssl_error == SSL_ERROR_WANT_WRITE)
        return magnus_update_interest(epoll_fd, connection, EPOLLOUT | EPOLLRDHUP);
    return -1;
}

static const char *
magnus_content_type(const char *path)
{
    const char *extension = strrchr(path, '.');
    if (extension == NULL) return "application/octet-stream";
    if (strcmp(extension, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(extension, ".css") == 0) return "text/css; charset=utf-8";
    if (strcmp(extension, ".js") == 0) return "text/javascript; charset=utf-8";
    if (strcmp(extension, ".json") == 0) return "application/json";
    if (strcmp(extension, ".svg") == 0) return "image/svg+xml";
    if (strcmp(extension, ".png") == 0) return "image/png";
    if (strcmp(extension, ".jpg") == 0 || strcmp(extension, ".jpeg") == 0)
        return "image/jpeg";
    return "application/octet-stream";
}

static int
magnus_open_static(const char *target, struct stat *metadata)
{
    char path[256];
    char *part;
    char *next;
    char *state = NULL;
    size_t length = strcspn(target, "?");
    int directory;
    int fd = -1;
    if (magnus_root_fd < 0 || length < 2 || length >= sizeof(path)
        || memchr(target, '%', length) != NULL
        || strstr(target, "//") != NULL || strstr(target, "/../") != NULL
        || (length >= 3 && memcmp(target + length - 3, "/..", 3) == 0))
        return -1;
    memcpy(path, target + 1, length - 1);
    path[length - 1] = '\0';
    directory = dup(magnus_root_fd);
    if (directory < 0) return -1;
    part = strtok_r(path, "/", &state);
    while (part != NULL) {
        next = strtok_r(NULL, "/", &state);
        if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0) {
            close(directory);
            return -1;
        }
        fd = openat(directory, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW
                    | (next != NULL ? O_DIRECTORY : 0));
        close(directory);
        if (fd < 0) return -1;
        if (next == NULL) break;
        directory = fd;
        fd = -1;
        part = next;
    }
    if (fd < 0 || fstat(fd, metadata) < 0 || !S_ISREG(metadata->st_mode)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static void
magnus_prepare_file_response(magnus_connection_t *connection, int file_fd,
                             const struct stat *metadata, bool head_only,
                             bool close_connection, magnus_request_t *request)
{
    int written;
    request->status = 200;
    magnus_requests_total++;
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_RESPONSE, request);
    written = snprintf(connection->output, sizeof(connection->output),
        "HTTP/1.1 200 OK\r\nServer: Magnus/%s\r\nContent-Type: %s\r\n"
        "Content-Length: %lld\r\nConnection: %s\r\nAccept-Ranges: bytes\r\n"
        "X-Magnus-Engine: native-c17/0.1\r\nX-Magnus-Request-Id: %s\r\n\r\n",
        MAGNUS_VERSION, magnus_content_type(request->path),
        (long long) metadata->st_size, close_connection ? "close" : "keep-alive",
        request->request_id);
    if (written < 0 || (size_t) written >= sizeof(connection->output)) {
        close(file_fd);
        connection->output_length = 0;
        connection->close_after_write = true;
        return;
    }
    connection->output_length = (size_t) written;
    connection->output_sent = 0;
    connection->close_after_write = close_connection;
    connection->file_fd = head_only ? -1 : file_fd;
    connection->file_offset = 0;
    connection->file_length = head_only ? 0 : metadata->st_size;
    if (head_only) close(file_fd);
}

static int
magnus_update_interest(int epoll_fd, magnus_connection_t *connection,
                       uint32_t events)
{
    struct epoll_event event = { .events = events, .data.fd = connection->fd };
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->fd, &event);
}

static char *
magnus_find_header_end(char *buffer, size_t length)
{
    size_t index;
    for (index = 3; index < length; index++) {
        if (buffer[index - 3] == '\r' && buffer[index - 2] == '\n'
            && buffer[index - 1] == '\r' && buffer[index] == '\n') {
            return &buffer[index + 1];
        }
    }
    return NULL;
}

static void
magnus_prepare_response(magnus_connection_t *connection, unsigned status,
                        const char *reason, const char *content_type,
                        const char *body, bool head_only, bool close_connection,
                        magnus_request_t *request)
{
    size_t body_length = strlen(body);
    int written;

    request->status = status;
    magnus_requests_total++;
    if (status >= 500) magnus_responses_5xx++;
    else if (status >= 400) magnus_responses_4xx++;
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_RESPONSE, request);
    written = snprintf(connection->output, sizeof(connection->output),
        "HTTP/1.1 %u %s\r\n"
        "Server: Magnus/%s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "X-Magnus-Engine: native-c17/0.1\r\n"
        "X-Magnus-Request-Id: %s\r\n"
        "X-Magnus-Phases: ingress,route,response\r\n"
        "\r\n%s",
        status, reason, MAGNUS_VERSION, content_type, body_length,
        close_connection ? "close" : "keep-alive", request->request_id,
        head_only ? "" : body);
    if (written < 0 || (size_t) written >= sizeof(connection->output)) {
        connection->output_length = 0;
        connection->close_after_write = true;
        return;
    }
    connection->output_length = (size_t) written;
    connection->output_sent = 0;
    connection->close_after_write = close_connection;
}

static int
magnus_process_request(int epoll_fd, magnus_connection_t *connection,
                       size_t request_length)
{
    magnus_request_t request = {0};
    magnus_http_request_t parsed;
    magnus_http_result_t parse_result;
    bool close_connection;
    bool head_only;

    parse_result = magnus_http_parse(connection->input, request_length, &parsed);
    if (parse_result != MAGNUS_HTTP_OK) {
        unsigned status = parse_result == MAGNUS_HTTP_URI_TOO_LONG ? 414
            : parse_result == MAGNUS_HTTP_VERSION_UNSUPPORTED ? 505 : 400;
        const char *reason = status == 414 ? "URI Too Long"
            : status == 505 ? "HTTP Version Not Supported" : "Bad Request";
        magnus_trace_handler(&request, NULL);
        magnus_prepare_response(connection, status, reason, "text/plain",
                                "bad request\n", false, true, &request);
        return 0;
    }

    memcpy(request.method, parsed.method, sizeof(request.method));
    memcpy(request.path, parsed.target, sizeof(request.path));

    close_connection = parsed.close_connection;
    head_only = parsed.head_only;
    if (magnus_phase_run(&magnus_phases, MAGNUS_PHASE_INGRESS, &request) != 0
        || magnus_phase_run(&magnus_phases, MAGNUS_PHASE_ROUTE, &request) != 0) {
        magnus_prepare_response(connection, 500, "Internal Server Error",
                                "text/plain", "phase error\n", head_only, true,
                                &request);
        return 0;
    }

    /* /healthz and /metrics stay exempt: they are exactly what an operator
     * or monitoring system needs to reach to see *why* real traffic is
     * being throttled, so gating them behind the same limiter would be
     * self-defeating. The admin channel is exempt outright -- access to
     * it is already gated by its socket's own file permissions. */
    if (!connection->admin_only
        && strcmp(request.path, "/healthz") != 0
        && strcmp(request.path, "/metrics") != 0
        && !magnus_rate_check(connection->client_address, time(NULL))) {
        magnus_rate_limited_total++;
        magnus_prepare_response(connection, 429, "Too Many Requests",
                                "text/plain", "rate limit exceeded\n", head_only,
                                true, &request);
        return 0;
    }

    if (strcmp(request.method, "GET") != 0 && !head_only) {
        magnus_prepare_response(connection, 405, "Method Not Allowed",
                                "text/plain", "method not allowed\n", false,
                                close_connection, &request);
    } else if (strcmp(request.path, "/healthz") == 0) {
        magnus_prepare_response(connection, 200, "OK", "text/plain",
                                "magnus: ok\n", head_only, close_connection,
                                &request);
    } else if (strcmp(request.path, "/metrics") == 0
               && (connection->admin_only || !magnus_admin_enabled)) {
        /* Sized to stay well clear of MAGNUS_OUTPUT_LIMIT once wrapped in
         * response headers; the per-endpoint/per-bucket loops below stop
         * appending once they run out of room rather than risk
         * overflowing the response envelope, so the fixed aggregate lines
         * are always present even when there is not room for full detail. */
        char metrics[1536];
        size_t written;
        size_t healthy = 0;
        for (size_t index = 0; index < magnus_cluster.count; index++) {
            if (magnus_cluster.endpoints[index].healthy) healthy++;
        }
        written = (size_t) snprintf(metrics, sizeof(metrics),
            "# TYPE magnus_connections_total counter\n"
            "magnus_connections_total %llu\n"
            "# TYPE magnus_connections_active gauge\n"
            "magnus_connections_active %llu\n"
            "# TYPE magnus_requests_total counter\n"
            "magnus_requests_total %llu\n"
            "magnus_responses_4xx_total %llu\n"
            "magnus_responses_5xx_total %llu\n"
            "magnus_bytes_sent_total %llu\n"
            "magnus_rate_limited_total %llu\n"
            "# TYPE magnus_upstream_endpoints gauge\n"
            "magnus_upstream_endpoints_total %zu\n"
            "magnus_upstream_endpoints_healthy %zu\n",
            (unsigned long long) magnus_connections_total,
            (unsigned long long) magnus_connections_active,
            (unsigned long long) magnus_requests_total,
            (unsigned long long) magnus_responses_4xx,
            (unsigned long long) magnus_responses_5xx,
            (unsigned long long) magnus_bytes_sent,
            (unsigned long long) magnus_rate_limited_total,
            magnus_cluster.count, healthy);
        for (size_t index = 0; index < magnus_cluster.count
             && written < sizeof(metrics); index++) {
            int line = snprintf(metrics + written, sizeof(metrics) - written,
                "magnus_upstream_healthy{endpoint=\"%s:%u\"} %d\n",
                magnus_cluster.endpoints[index].address,
                magnus_cluster.endpoints[index].port,
                magnus_cluster.endpoints[index].healthy ? 1 : 0);
            if (line < 0 || (size_t) line >= sizeof(metrics) - written) break;
            written += (size_t) line;
        }
        if (written < sizeof(metrics)) {
            int line = snprintf(metrics + written, sizeof(metrics) - written,
                "# TYPE magnus_request_duration_milliseconds histogram\n");
            if (line > 0 && (size_t) line < sizeof(metrics) - written)
                written += (size_t) line;
        }
        for (size_t index = 0; index < MAGNUS_LATENCY_BUCKETS
             && written < sizeof(metrics); index++) {
            int line = snprintf(metrics + written, sizeof(metrics) - written,
                "magnus_request_duration_milliseconds_bucket{le=\"%g\"} %llu\n",
                magnus_latency_bucket_bounds_ms[index],
                (unsigned long long) magnus_latency_bucket_counts[index]);
            if (line < 0 || (size_t) line >= sizeof(metrics) - written) break;
            written += (size_t) line;
        }
        if (written < sizeof(metrics)) {
            int line = snprintf(metrics + written, sizeof(metrics) - written,
                "magnus_request_duration_milliseconds_bucket{le=\"+Inf\"} %llu\n"
                "magnus_request_duration_milliseconds_sum %.2f\n"
                "magnus_request_duration_milliseconds_count %llu\n",
                (unsigned long long) magnus_latency_count,
                magnus_latency_sum_ms,
                (unsigned long long) magnus_latency_count);
            if (line > 0 && (size_t) line < sizeof(metrics) - written)
                written += (size_t) line;
        }
        magnus_prepare_response(connection, 200, "OK",
                                "text/plain; version=0.0.4", metrics,
                                head_only, close_connection, &request);
    } else if (connection->admin_only) {
        /* Everything else is off-limits on the admin channel. */
        magnus_prepare_response(connection, 404, "Not Found", "text/plain",
                                "not found\n", head_only, close_connection,
                                &request);
    } else if (magnus_upstream_enabled
               && strncmp(request.path, "/proxy", 6) == 0
               && (request.path[6] == '/' || request.path[6] == '\0')) {
        if (magnus_proxy_pick_and_start(epoll_fd, connection, &request,
                                        parsed.affinity_key) == 0) {
            /* No access-log line here: the request has not completed yet
             * (that happens later, asynchronously, once the upstream
             * responds -- see magnus_proxy_receive_headers/_fail). Just
             * remember what the client asked for so that completion line
             * can still report it. */
            strncpy(connection->proxy_log_method, request.method,
                   sizeof(connection->proxy_log_method) - 1);
            connection->proxy_log_method[
                sizeof(connection->proxy_log_method) - 1] = '\0';
            strncpy(connection->proxy_log_target, request.path,
                   sizeof(connection->proxy_log_target) - 1);
            connection->proxy_log_target[
                sizeof(connection->proxy_log_target) - 1] = '\0';
            return 1;
        }
        magnus_prepare_response(connection, 502, "Bad Gateway", "text/plain",
                                "bad gateway\n", head_only, true, &request);
    } else if (strcmp(request.path, "/") == 0) {
        magnus_prepare_response(connection, 200, "OK", "application/json",
                                "{\"name\":\"Magnus\",\"engine\":\"native-c17\",\"status\":\"ready\"}\n",
                                head_only, close_connection, &request);
    } else {
        struct stat metadata;
        int file_fd = magnus_open_static(request.path, &metadata);
        if (file_fd >= 0)
            magnus_prepare_file_response(connection, file_fd, &metadata,
                                         head_only, close_connection, &request);
        else
            magnus_prepare_response(connection, 404, "Not Found", "text/plain",
                                    "not found\n", head_only, close_connection,
                                    &request);
    }
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_LOG, &request);
    {
        double latency_ms = (double) (magnus_now_ms()
                                      - connection->request_started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(request.request_id, request.method, request.path,
                          request.status, latency_ms);
    }
    return 0;
}

static int
magnus_process_input(int epoll_fd, magnus_connection_t *connection)
{
    char *end = magnus_find_header_end(connection->input,
                                       connection->input_length);
    size_t request_length;

    if (end == NULL) {
        if (connection->input_length == MAGNUS_INPUT_LIMIT) {
            magnus_request_t request = {0};
            magnus_trace_handler(&request, NULL);
            magnus_prepare_response(connection, 431,
                                    "Request Header Fields Too Large",
                                    "text/plain", "headers too large\n", false,
                                    true, &request);
            return magnus_update_interest(epoll_fd, connection, EPOLLOUT);
        }
        return 0;
    }

    request_length = (size_t) (end - connection->input);
    connection->request_started_ms = magnus_now_ms();
    int process_result = magnus_process_request(epoll_fd, connection,
                                                request_length);
    memmove(connection->input, connection->input + request_length,
            connection->input_length - request_length);
    connection->input_length -= request_length;
    if (process_result == 1) return 0;
    return magnus_update_interest(epoll_fd, connection, EPOLLOUT);
}

static int
magnus_handle_read(int epoll_fd, magnus_connection_t *connection)
{
    ssize_t received;
    if (connection->input_length == connection->input_capacity
        && connection->input_capacity < MAGNUS_INPUT_LIMIT) {
        size_t capacity = connection->input_capacity * 2;
        char *grown;
        if (capacity > MAGNUS_INPUT_LIMIT) capacity = MAGNUS_INPUT_LIMIT;
        grown = realloc(connection->input, capacity);
        if (grown == NULL) return -1;
        connection->input = grown;
        connection->input_capacity = capacity;
    }
    while (connection->input_length < connection->input_capacity) {
        received = magnus_socket_read(connection,
                        connection->input + connection->input_length,
                        connection->input_capacity - connection->input_length);
        if (received > 0) {
            connection->input_length += (size_t) received;
            connection->last_active = time(NULL);
            if (magnus_find_header_end(connection->input,
                                       connection->input_length) != NULL) {
                return magnus_process_input(epoll_fd, connection);
            }
            continue;
        }
        if (received == 0) {
            return -1;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
    return magnus_process_input(epoll_fd, connection);
}

static int
magnus_handle_write(int epoll_fd, magnus_connection_t *connection)
{
    ssize_t sent;
    while (connection->output_sent < connection->output_length) {
        sent = magnus_socket_write(connection,
                    connection->output + connection->output_sent,
                    connection->output_length - connection->output_sent);
        if (sent > 0) {
            connection->output_sent += (size_t) sent;
            magnus_bytes_sent += (uint64_t) sent;
            connection->last_active = time(NULL);
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return -1;
    }
    while (connection->tls == NULL && connection->file_fd >= 0
           && connection->file_offset < connection->file_length) {
        sent = sendfile(connection->fd, connection->file_fd,
                        &connection->file_offset,
                        (size_t) (connection->file_length
                                  - connection->file_offset));
        if (sent > 0) {
            magnus_bytes_sent += (uint64_t) sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    while (connection->tls != NULL && connection->file_fd >= 0
           && connection->file_offset < connection->file_length) {
        if (connection->file_buffer_sent == connection->file_buffer_length) {
            if (connection->file_buffer == NULL) {
                connection->file_buffer = malloc(4096);
                if (connection->file_buffer == NULL) return -1;
            }
            ssize_t loaded = pread(connection->file_fd, connection->file_buffer,
                                   4096,
                                   connection->file_offset);
            if (loaded <= 0) return -1;
            connection->file_buffer_length = (size_t) loaded;
            connection->file_buffer_sent = 0;
        }
        sent = magnus_socket_write(connection,
            connection->file_buffer + connection->file_buffer_sent,
            connection->file_buffer_length - connection->file_buffer_sent);
        if (sent > 0) {
            connection->file_buffer_sent += (size_t) sent;
            connection->file_offset += sent;
            magnus_bytes_sent += (uint64_t) sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    if (connection->file_fd >= 0) {
        close(connection->file_fd);
        connection->file_fd = -1;
    }
    if (connection->close_after_write) {
        return -1;
    }
    connection->output_length = 0;
    connection->output_sent = 0;
    if (connection->input_length > 0
        && magnus_find_header_end(connection->input,
                                  connection->input_length) != NULL) {
        return magnus_process_input(epoll_fd, connection);
    }
    return magnus_update_interest(epoll_fd, connection, EPOLLIN | EPOLLRDHUP);
}

static int
magnus_accept_connections(int epoll_fd, int listener, bool admin)
{
    for (;;) {
        struct sockaddr_in peer_address = {0};
        socklen_t peer_length = sizeof(peer_address);
        /* The admin listener is a Unix domain socket: it has no IPv4 peer
         * address, and access to it is already controlled by the socket
         * file's own permissions, so we do not bother asking for one. */
        int client = admin
            ? accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)
            : accept4(listener, (struct sockaddr *) &peer_address,
                      &peer_length, SOCK_NONBLOCK | SOCK_CLOEXEC);
        magnus_connection_t *connection;
        struct epoll_event event;

        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (client >= MAGNUS_MAX_FDS) {
            close(client);
            continue;
        }
        connection = calloc(1, sizeof(*connection));
        if (connection == NULL) {
            close(client);
            continue;
        }
        connection->input = malloc(MAGNUS_INITIAL_INPUT);
        if (connection->input == NULL) {
            close(client);
            free(connection);
            continue;
        }
        connection->input_capacity = MAGNUS_INITIAL_INPUT;
        connection->fd = client;
        connection->file_fd = -1;
        /* calloc() zero-initializes the rest of the struct, so without
         * this, upstream_fd defaults to 0 (not "no upstream") for every
         * connection that never proxies. magnus_close_connection()'s only
         * "no upstream" check is `>= 0`, so that 0 reads as a real fd to
         * tear down -- silently close()ing fd 0 on every ordinary
         * connection's cleanup. Harmless by pure accident as long as fd 0
         * was inherited stdin magnus never reads -- but the very next
         * unrelated open() elsewhere (SIGHUP reload re-opening the root
         * directory, in particular) then silently lands on fd 0 instead,
         * which is exactly what surfaced this: a reload's new root fd
         * ending up on 0, breaking static file lookups. */
        connection->upstream_fd = -1;
        connection->client_address = peer_address.sin_addr;
        connection->admin_only = admin;
        /* No TLS on the admin channel: it is a local Unix socket, already
         * confidential and access-controlled by filesystem permissions,
         * and keeping it TLS-free keeps the isolation story simple (one
         * fewer thing that could be misconfigured to leak metrics). */
        if (!admin && magnus_tls_context != NULL) {
            connection->tls = SSL_new(magnus_tls_context);
            if (connection->tls == NULL
                || SSL_set_fd(connection->tls, client) != 1) {
                if (connection->tls != NULL) SSL_free(connection->tls);
                close(client);
                free(connection->input);
                free(connection);
                continue;
            }
            SSL_set_accept_state(connection->tls);
        } else {
            connection->tls_ready = true;
        }
        connection->last_active = time(NULL);
        connection->header_deadline =
            connection->last_active + MAGNUS_HEADER_TIMEOUT_SECONDS;
        magnus_connections[client] = connection;
        event = (struct epoll_event) {
            .events = EPOLLIN | EPOLLRDHUP,
            .data.fd = client
        };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &event) < 0) {
            magnus_connections[client] = NULL;
            close(client);
            if (connection->tls != NULL) SSL_free(connection->tls);
            free(connection->input);
            free(connection);
        } else {
            magnus_connections_total++;
            magnus_connections_active++;
        }
    }
}

static void
magnus_expire_idle(int epoll_fd, time_t now)
{
    int fd;
    for (fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_connection_t *connection = magnus_connections[fd];
        if (connection == NULL) continue;
        if (now - connection->last_active > MAGNUS_IDLE_SECONDS) {
            magnus_close_connection(epoll_fd, connection);
            continue;
        }
        /* Slowloris guard: a trickle of bytes keeps resetting last_active
         * above without ever finishing a request, so it alone cannot
         * catch this. Only applies before the first request on this
         * connection has ever completed (request_started_ms == 0) --
         * legitimate keep-alive idling between later requests is exactly
         * what MAGNUS_IDLE_SECONDS above is for. */
        if (connection->request_started_ms == 0
            && now > connection->header_deadline) {
            magnus_close_connection(epoll_fd, connection);
        }
    }
}

/* Bounds how long a proxied request may spend connecting to, or waiting on,
 * an upstream: a stalled connect() is reported as 504 after
 * MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS, and a connected-but-silent upstream
 * (or a stalled write to a slow client while relaying) is reported as 504
 * after MAGNUS_PROXY_READ_TIMEOUT_SECONDS of proxy inactivity. Once
 * response bytes have already reached the client a clean status can no
 * longer be sent, so the connection is aborted instead.
 *
 * Only the connect-stage timeout retries against a different endpoint: a
 * connect() that never completed is exactly the "try elsewhere" case a
 * retry budget exists for. A connected-but-silent upstream is deliberately
 * NOT retried here -- the endpoint already accepted the connection, so
 * retrying would only double the wait (another full read timeout) without
 * addressing a slow responder, which is precisely the retry-storm/tail-
 * latency amplification the retry budget must avoid. */
static void
magnus_expire_proxies(int epoll_fd, time_t now)
{
    int fd;
    for (fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_connection_t *connection = magnus_connections[fd];
        int result;
        if (connection == NULL || !connection->proxy_active) continue;
        if (!connection->proxy_connected) {
            if (now - connection->proxy_connect_started
                < MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS) continue;
            result = magnus_proxy_connect_failed(epoll_fd, connection, 504,
                                                 "Gateway Timeout");
        } else if (now - connection->proxy_last_activity
                   >= MAGNUS_PROXY_READ_TIMEOUT_SECONDS) {
            if (connection->proxy_response_started) {
                result = magnus_proxy_abort(epoll_fd, connection);
            } else {
                /* still counts as a passive-health failure even though we
                 * do not retry this request against another endpoint. */
                magnus_cluster_result(&magnus_cluster,
                                      connection->proxy_endpoint_index, false,
                                      magnus_now_ms());
                result = magnus_proxy_fail(epoll_fd, connection, 504,
                                           "Gateway Timeout");
            }
        } else {
            continue;
        }
        if (result < 0 && magnus_connections[connection->fd] != NULL) {
            magnus_close_connection(epoll_fd, connection);
        }
    }
}

/* Active health checking: independent of live traffic, periodically opens
 * a bare non-blocking TCP connect() to each cluster endpoint and feeds the
 * outcome into the same magnus_cluster_result() passive-health state that
 * real proxy traffic feeds, so an endpoint can be found (and recover) even
 * while it is receiving no requests at all. */

static void
magnus_health_close_probe(int epoll_fd, size_t index)
{
    int fd = magnus_health_probe_fd[index];
    if (fd < 0) return;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    magnus_health_probe_owner[fd] = 0;
    close(fd);
    magnus_health_probe_fd[index] = -1;
}

static void
magnus_health_start_probe(int epoll_fd, size_t index, time_t now)
{
    struct sockaddr_in address;
    struct epoll_event event;
    int fd;
    int result;

    if (!magnus_endpoint_sockaddr(index, &address)) return;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        return;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        magnus_cluster_result(&magnus_cluster, index, false, magnus_now_ms());
        return;
    }
    event = (struct epoll_event) { .events = EPOLLOUT | EPOLLRDHUP,
                                   .data.fd = fd };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        close(fd);
        return;
    }
    magnus_health_probe_fd[index] = fd;
    magnus_health_probe_owner[fd] = (int) (index + 1);
    magnus_health_probe_started[index] = now;
    if (result == 0) {
        /* connected synchronously (typical for loopback/LAN targets):
         * resolve immediately instead of waiting on an epoll event that a
         * level-triggered, already-satisfied condition may not re-deliver. */
        magnus_cluster_result(&magnus_cluster, index, true, magnus_now_ms());
        magnus_health_close_probe(epoll_fd, index);
    }
}

static void
magnus_health_handle_probe(int epoll_fd, size_t index, uint32_t flags)
{
    int fd = magnus_health_probe_fd[index];
    bool success = false;
    if (fd < 0) return;
    if ((flags & (EPOLLERR | EPOLLHUP)) == 0) {
        int error = 0;
        socklen_t length = sizeof(error);
        success = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0
                   && error == 0;
    }
    magnus_cluster_result(&magnus_cluster, index, success, magnus_now_ms());
    magnus_health_close_probe(epoll_fd, index);
}

static void
magnus_health_tick(int epoll_fd, time_t now)
{
    size_t index;
    for (index = 0; index < magnus_cluster.count; index++) {
        if (magnus_health_probe_fd[index] >= 0) {
            if (now - magnus_health_probe_started[index]
                >= MAGNUS_HEALTH_PROBE_TIMEOUT_SECONDS) {
                magnus_cluster_result(&magnus_cluster, index, false,
                                      magnus_now_ms());
                magnus_health_close_probe(epoll_fd, index);
            }
            continue;
        }
        if (now - magnus_health_last_probe[index]
            >= MAGNUS_HEALTH_CHECK_INTERVAL_SECONDS) {
            magnus_health_last_probe[index] = now;
            magnus_health_start_probe(epoll_fd, index, now);
        }
    }
}

static int
magnus_create_listener(unsigned port)
{
    int listener;
    int enabled = 1;
    struct sockaddr_in address = {0};

    listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        return -1;
    }
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled,
                   sizeof(enabled)) < 0) {
        close(listener);
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t) port);
    if (bind(listener, (struct sockaddr *) &address, sizeof(address)) < 0
        || listen(listener, SOMAXCONN) < 0) {
        close(listener);
        return -1;
    }
    return listener;
}

/* Binds the admin-only Unix domain socket listener at `path`: mode 0700
 * (owner-only) is the access control for /healthz and /metrics on this
 * channel, in place of an in-process RBAC layer -- whoever can reach this
 * socket file can reach admin endpoints, same as any other Unix socket
 * service. A stale socket file from a previous run (e.g. an unclean
 * shutdown) is removed first so bind() does not fail with EADDRINUSE. */
static int
magnus_create_admin_listener(const char *path)
{
    int listener;
    struct sockaddr_un address = {0};

    if (strlen(path) >= sizeof(address.sun_path)) return -1;
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) return -1;
    unlink(path);
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, path);
    if (bind(listener, (struct sockaddr *) &address, sizeof(address)) < 0
        || chmod(path, 0700) < 0 || listen(listener, SOMAXCONN) < 0) {
        close(listener);
        unlink(path);
        return -1;
    }
    return listener;
}

/* Builds new root-fd/TLS-context/cluster/rate-limit state from a validated
 * config and, only once every referenced resource actually opened
 * successfully, swaps it into the live globals in one shot. Since magnus
 * is single-threaded (epoll, no worker threads), this swap is atomic from
 * every other execution point's perspective -- there is no window in
 * which another code path could observe half-old/half-new state. It
 * intentionally never touches the listening port or in-flight
 * connections: existing proxy attempts already hold their own connected
 * upstream fd and never re-consult magnus_cluster, and already-open
 * static-file fds and already-established TLS sessions keep working via
 * OpenSSL's own SSL_CTX refcounting -- so in-flight requests "drain"
 * naturally against whatever generation they started under, while every
 * request that begins after this function returns sees the new one.
 * Returns 0 on success, -1 if a filesystem/TLS resource named in the
 * config could not actually be opened despite passing
 * magnus_config_load()'s validation (e.g. removed between check and
 * apply); nothing is changed in that case. */
static int
magnus_apply_config(const magnus_config_t *config)
{
    int new_root_fd = -1;
    SSL_CTX *new_tls_context = NULL;
    magnus_cluster_t new_cluster;
    size_t index;

    if (config->has_root) {
        new_root_fd = open(config->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC
                           | O_NOFOLLOW);
        if (new_root_fd < 0) return -1;
    }
    if (config->has_tls) {
        new_tls_context = SSL_CTX_new(TLS_server_method());
        if (new_tls_context == NULL
            || SSL_CTX_set_min_proto_version(new_tls_context,
                                             TLS1_2_VERSION) != 1
            || SSL_CTX_use_certificate_chain_file(new_tls_context,
                                                  config->tls_cert) != 1
            || SSL_CTX_use_PrivateKey_file(new_tls_context, config->tls_key,
                                           SSL_FILETYPE_PEM) != 1
            || SSL_CTX_check_private_key(new_tls_context) != 1) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
        SSL_CTX_set_options(new_tls_context, SSL_OP_NO_COMPRESSION);
    }
    magnus_cluster_init(&new_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS);
    for (index = 0; index < config->upstream_count; index++) {
        if (magnus_cluster_add(&new_cluster, config->upstreams[index].address,
                               config->upstreams[index].port,
                               config->upstreams[index].weight) != 0) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
    }

    if (magnus_root_fd >= 0) close(magnus_root_fd);
    magnus_root_fd = new_root_fd;
    if (magnus_tls_context != NULL) SSL_CTX_free(magnus_tls_context);
    magnus_tls_context = new_tls_context;
    magnus_cluster = new_cluster;
    magnus_upstream_enabled = new_cluster.count > 0;
    magnus_rate_limit_enabled = config->has_rate_limit;
    if (config->has_rate_limit) {
        magnus_rate_limit_rps = config->rate_limit_rps;
        magnus_rate_limit_burst = config->rate_limit_burst;
    }
    magnus_access_log_enabled = config->access_log_enabled;
    magnus_access_log_sample = config->access_log_sample;
    return 0;
}

static void
magnus_handle_reload(void)
{
    magnus_config_t config;
    char error[192];

    if (!magnus_config_mode) {
        fprintf(stderr, "magnus: reload ignored: not started with "
                        "--config, nothing to reload from\n");
        return;
    }
    if (magnus_config_load(magnus_config_path, &config, error, sizeof(error))
        != MAGNUS_CONFIG_OK) {
        fprintf(stderr, "magnus: reload rejected: %s\n", error);
        return;
    }
    if (config.port != magnus_listen_port) {
        fprintf(stderr, "magnus: reload rejected: changing the listening "
                        "port requires a restart (running on %u, config "
                        "has %u)\n", magnus_listen_port, config.port);
        return;
    }
    if (config.has_admin_socket != magnus_admin_enabled
        || (config.has_admin_socket
            && strcmp(config.admin_socket, magnus_admin_socket_path) != 0)) {
        fprintf(stderr, "magnus: reload rejected: changing admin_socket "
                        "requires a restart\n");
        return;
    }
    if (magnus_apply_config(&config) != 0) {
        fprintf(stderr, "magnus: reload rejected: a referenced root/tls "
                        "resource could not be opened\n");
        return;
    }
    fprintf(stderr, "magnus: reload applied generation=%016llx\n",
            (unsigned long long) magnus_config_hash(&config));
}

static unsigned
magnus_parse_options(int argc, char **argv)
{
    unsigned port = 0;
    int index;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("Magnus Web Engine %s (native C17/epoll)\n", MAGNUS_VERSION);
        exit(0);
    }
    if (argc == 3 && strcmp(argv[1], "--config") == 0) {
        /* Config-file mode replaces every other flag: port, root, TLS,
         * upstream cluster and rate limit all come from the file, and the
         * same path is remembered for SIGHUP to re-validate and apply
         * later (magnus_handle_reload). */
        magnus_config_t config;
        char error[192];
        if (magnus_config_load(argv[2], &config, error, sizeof(error))
            != MAGNUS_CONFIG_OK) {
            fprintf(stderr, "magnus: config: %s\n", error);
            exit(2);
        }
        if (strlen(argv[2]) >= sizeof(magnus_config_path)) {
            fprintf(stderr, "magnus: config: path too long\n");
            exit(2);
        }
        strcpy(magnus_config_path, argv[2]);
        magnus_config_mode = true;
        if (magnus_apply_config(&config) != 0) {
            fprintf(stderr, "magnus: config: a referenced root/tls "
                            "resource could not be opened\n");
            exit(2);
        }
        if (config.has_admin_socket) {
            strcpy(magnus_admin_socket_path, config.admin_socket);
            magnus_admin_enabled = true;
        }
        return config.port;
    }
    const char *certificate = NULL;
    const char *private_key = NULL;
    magnus_cluster_init(&magnus_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS);
    for (index = 1; index < argc; index += 2) {
        if (index + 1 >= argc) break;
        if (strcmp(argv[index], "--port") == 0) {
            char *end;
            unsigned long value;
            errno = 0;
            value = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || value == 0 || value > 65535)
                break;
            port = (unsigned) value;
        } else if (strcmp(argv[index], "--root") == 0) {
            magnus_root_fd = open(argv[index + 1], O_RDONLY | O_DIRECTORY
                                  | O_CLOEXEC | O_NOFOLLOW);
            if (magnus_root_fd < 0) {
                perror("magnus: root");
                exit(2);
            }
        } else if (strcmp(argv[index], "--tls-cert") == 0) {
            certificate = argv[index + 1];
        } else if (strcmp(argv[index], "--tls-key") == 0) {
            private_key = argv[index + 1];
        } else if (strcmp(argv[index], "--upstream") == 0) {
            /* host:port or host:port:weight; repeatable to build a cluster. */
            char spec[80];
            char *saveptr = NULL;
            char *address;
            char *port_text;
            char *weight_text;
            char *end;
            unsigned long upstream_port;
            unsigned long weight = 1;
            struct in_addr probe;
            if (strlen(argv[index + 1]) >= sizeof(spec)) break;
            strcpy(spec, argv[index + 1]);
            address = strtok_r(spec, ":", &saveptr);
            port_text = strtok_r(NULL, ":", &saveptr);
            weight_text = strtok_r(NULL, ":", &saveptr);
            if (address == NULL || port_text == NULL
                || inet_pton(AF_INET, address, &probe) != 1) break;
            errno = 0;
            upstream_port = strtoul(port_text, &end, 10);
            if (errno != 0 || *end != '\0' || upstream_port == 0
                || upstream_port > 65535) break;
            if (weight_text != NULL) {
                errno = 0;
                weight = strtoul(weight_text, &end, 10);
                if (errno != 0 || *end != '\0' || weight == 0
                    || weight > 1000) break;
            }
            if (magnus_cluster_add(&magnus_cluster, address,
                                   (unsigned) upstream_port,
                                   (unsigned) weight) != 0) break;
            magnus_upstream_enabled = true;
        } else if (strcmp(argv[index], "--rate-limit") == 0) {
            /* requests-per-second, or requests-per-second:burst */
            char spec[32];
            char *saveptr = NULL;
            char *rps_text;
            char *burst_text;
            char *end;
            double rps;
            double burst;
            if (strlen(argv[index + 1]) >= sizeof(spec)) break;
            strcpy(spec, argv[index + 1]);
            rps_text = strtok_r(spec, ":", &saveptr);
            burst_text = strtok_r(NULL, ":", &saveptr);
            if (rps_text == NULL) break;
            errno = 0;
            rps = strtod(rps_text, &end);
            if (errno != 0 || *end != '\0' || !(rps > 0.0)) break;
            burst = rps;
            if (burst_text != NULL) {
                errno = 0;
                burst = strtod(burst_text, &end);
                if (errno != 0 || *end != '\0' || !(burst > 0.0)) break;
            }
            magnus_rate_limit_rps = rps;
            magnus_rate_limit_burst = burst;
            magnus_rate_limit_enabled = true;
        } else if (strcmp(argv[index], "--admin-socket") == 0) {
            if (strlen(argv[index + 1]) >= sizeof(magnus_admin_socket_path))
                break;
            strcpy(magnus_admin_socket_path, argv[index + 1]);
            magnus_admin_enabled = true;
        } else if (strcmp(argv[index], "--access-log") == 0) {
            if (strcmp(argv[index + 1], "on") == 0) {
                magnus_access_log_enabled = true;
            } else if (strcmp(argv[index + 1], "off") == 0) {
                magnus_access_log_enabled = false;
            } else {
                break;
            }
        } else if (strcmp(argv[index], "--access-log-sample") == 0) {
            char *end;
            unsigned long sample;
            errno = 0;
            sample = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || sample == 0
                || sample > 1000000) break;
            magnus_access_log_sample = (unsigned) sample;
        } else {
            break;
        }
    }
    if (index == argc && port != 0
        && ((certificate == NULL && private_key == NULL)
            || (certificate != NULL && private_key != NULL))) {
        if (certificate != NULL) {
            magnus_tls_context = SSL_CTX_new(TLS_server_method());
            if (magnus_tls_context == NULL
                || SSL_CTX_set_min_proto_version(magnus_tls_context,
                                                 TLS1_2_VERSION) != 1
                || SSL_CTX_use_certificate_chain_file(magnus_tls_context,
                                                      certificate) != 1
                || SSL_CTX_use_PrivateKey_file(magnus_tls_context, private_key,
                                               SSL_FILETYPE_PEM) != 1
                || SSL_CTX_check_private_key(magnus_tls_context) != 1) {
                ERR_print_errors_fp(stderr);
                exit(2);
            }
            SSL_CTX_set_options(magnus_tls_context, SSL_OP_NO_COMPRESSION);
        }
        return port;
    }
    fprintf(stderr, "usage: %s --port <1-65535> [--root <directory>] "
                    "[--tls-cert <pem> --tls-key <pem>] "
                    "[--upstream <ipv4:port[:weight]> ...] "
                    "[--rate-limit <rps[:burst]>] "
                    "[--admin-socket <path>] "
                    "[--access-log on|off] [--access-log-sample <n>] "
                    "| %s --config <path> | %s --version\n",
            argv[0], argv[0], argv[0]);
    exit(2);
}

/* Defense in depth alongside the upstream_fd fix above: magnus never
 * reads stdin, so fd 0 is unconditionally pinned to our own /dev/null
 * before anything else runs. A process spawned detached from a
 * controlling terminal (magnusd's fork()+exec() child, in particular) can
 * inherit fd 0 as something that looks valid at startup but turns out to
 * be fragile; owning it ourselves from the very first instruction removes
 * any dependency on what was inherited. stdout/stderr are left alone when
 * already valid (used for logging); only a genuine gap there is filled. */
static void
magnus_ensure_standard_fds(void)
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
    unsigned port;
    int listener;
    magnus_ensure_standard_fds();
    port = magnus_parse_options(argc, argv);
    magnus_listen_port = port;
    listener = magnus_create_listener(port);
    int epoll_fd;
    struct epoll_event listener_event;
    struct epoll_event events[MAGNUS_MAX_EVENTS];
    time_t last_sweep = time(NULL);

    if (listener < 0) {
        perror("magnus: listener");
        return 1;
    }
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        perror("magnus: epoll_create1");
        close(listener);
        return 1;
    }
    listener_event = (struct epoll_event) { .events = EPOLLIN,
                                             .data.fd = listener };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &listener_event) < 0) {
        perror("magnus: epoll_ctl");
        close(epoll_fd);
        close(listener);
        return 1;
    }
    if (magnus_admin_enabled) {
        struct epoll_event admin_event;
        magnus_admin_listener =
            magnus_create_admin_listener(magnus_admin_socket_path);
        if (magnus_admin_listener < 0) {
            perror("magnus: admin-socket");
            close(epoll_fd);
            close(listener);
            return 1;
        }
        admin_event = (struct epoll_event) { .events = EPOLLIN,
                                             .data.fd = magnus_admin_listener };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, magnus_admin_listener,
                      &admin_event) < 0) {
            perror("magnus: admin-socket epoll_ctl");
            close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
    }

    magnus_phase_init(&magnus_phases);
    if (magnus_phase_register(&magnus_phases, MAGNUS_PHASE_INGRESS, 100,
                              "request-trace", magnus_trace_handler, NULL) != 0) {
        fprintf(stderr, "magnus: phase registration failed\n");
        return 1;
    }
    signal(SIGINT, magnus_signal_handler);
    signal(SIGTERM, magnus_signal_handler);
    signal(SIGHUP, magnus_reload_signal_handler);
    signal(SIGPIPE, SIG_IGN);
    for (size_t index = 0; index < MAGNUS_MAX_UPSTREAMS; index++) {
        magnus_health_probe_fd[index] = -1;
    }
    fprintf(stderr, "magnus: native engine listening on 0.0.0.0:%u\n", port);

    while (magnus_running) {
        int ready;
        int index;
        time_t now;
        if (magnus_reload_requested) {
            magnus_reload_requested = 0;
            magnus_handle_reload();
        }
        ready = epoll_wait(epoll_fd, events, MAGNUS_MAX_EVENTS, 1000);
        now = time(NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("magnus: epoll_wait");
            break;
        }
        for (index = 0; index < ready; index++) {
            int fd = events[index].data.fd;
            uint32_t flags = events[index].events;
            magnus_connection_t *connection;
            int result = 0;
            if (fd == listener) {
                (void) magnus_accept_connections(epoll_fd, listener, false);
                continue;
            }
            if (magnus_admin_enabled && fd == magnus_admin_listener) {
                (void) magnus_accept_connections(epoll_fd, magnus_admin_listener,
                                                 true);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_upstream_owner[fd] != NULL) {
                connection = magnus_upstream_owner[fd];
                result = magnus_handle_upstream(epoll_fd, connection, flags);
                if (result < 0
                    && magnus_connections[connection->fd] != NULL)
                    magnus_close_connection(epoll_fd, connection);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_health_probe_owner[fd] != 0) {
                magnus_health_handle_probe(epoll_fd,
                    (size_t) (magnus_health_probe_owner[fd] - 1), flags);
                continue;
            }
            if (fd < 0 || fd >= MAGNUS_MAX_FDS
                || (connection = magnus_connections[fd]) == NULL) {
                continue;
            }
            if ((flags & (EPOLLERR | EPOLLHUP)) != 0) {
                result = -1;
            } else if (!connection->tls_ready) {
                result = magnus_tls_handshake(epoll_fd, connection);
            } else if ((flags & EPOLLIN) != 0) {
                result = magnus_handle_read(epoll_fd, connection);
            } else if ((flags & EPOLLOUT) != 0 && connection->proxy_active) {
                result = magnus_proxy_flush(epoll_fd, connection);
            } else if ((flags & EPOLLOUT) != 0) {
                result = magnus_handle_write(epoll_fd, connection);
            } else if ((flags & EPOLLRDHUP) != 0 && connection->proxy_active) {
                /* client aborted while we were only watching for hangup
                 * (connecting to, or waiting on headers from, upstream) */
                result = -1;
            }
            if (result < 0 && magnus_connections[fd] != NULL) {
                magnus_close_connection(epoll_fd, connection);
            }
        }
        if (now != last_sweep) {
            magnus_expire_proxies(epoll_fd, now);
            magnus_expire_idle(epoll_fd, now);
            magnus_health_tick(epoll_fd, now);
            magnus_access_log_flush();
            last_sweep = now;
        }
    }

    for (int fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        if (magnus_connections[fd] != NULL) {
            magnus_close_connection(epoll_fd, magnus_connections[fd]);
        }
    }
    close(epoll_fd);
    close(listener);
    if (magnus_admin_listener >= 0) {
        close(magnus_admin_listener);
        unlink(magnus_admin_socket_path);
    }
    if (magnus_root_fd >= 0) close(magnus_root_fd);
    if (magnus_tls_context != NULL) SSL_CTX_free(magnus_tls_context);
    magnus_access_log_flush();
    fprintf(stderr, "magnus: stopped\n");
    return 0;
}
