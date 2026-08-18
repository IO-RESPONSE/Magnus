#include "magnus_phase.h"
#include "magnus_http.h"

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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define MAGNUS_VERSION "0.2.0-dev"
#define MAGNUS_MAX_EVENTS 1024
#define MAGNUS_MAX_FDS 65536
#define MAGNUS_INPUT_LIMIT 8192
#define MAGNUS_OUTPUT_LIMIT 1024
#define MAGNUS_IDLE_SECONDS 30
#define MAGNUS_PROXY_BUFFER 16384
#define MAGNUS_INITIAL_INPUT 2048

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
    time_t last_active;
} magnus_connection_t;

static volatile sig_atomic_t magnus_running = 1;
static magnus_phase_engine_t magnus_phases;
static magnus_connection_t *magnus_connections[MAGNUS_MAX_FDS];
static int magnus_root_fd = -1;
static SSL_CTX *magnus_tls_context;
static struct sockaddr_in magnus_upstream_address;
static bool magnus_upstream_enabled;
static magnus_connection_t *magnus_upstream_owner[MAGNUS_MAX_FDS];
static uint64_t magnus_connections_total;
static uint64_t magnus_connections_active;
static uint64_t magnus_requests_total;
static uint64_t magnus_responses_4xx;
static uint64_t magnus_responses_5xx;
static uint64_t magnus_bytes_sent;

static int magnus_update_interest(int epoll_fd,
                                  magnus_connection_t *connection,
                                  uint32_t events);
static ssize_t magnus_socket_write(magnus_connection_t *connection,
                                   const void *buffer, size_t length);

static void
magnus_signal_handler(int signal_number)
{
    (void) signal_number;
    magnus_running = 0;
}

static int
magnus_trace_handler(magnus_request_t *request, void *data)
{
    unsigned char random_bytes[16];
    static const char hex[] = "0123456789abcdef";
    static uint64_t fallback_counter;
    size_t index;

    (void) data;
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
        request->request_id[index * 2] = hex[random_bytes[index] >> 4];
        request->request_id[index * 2 + 1] = hex[random_bytes[index] & 0x0f];
    }
    request->request_id[32] = '\0';
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
    if (magnus_connections_active > 0) magnus_connections_active--;
    if (connection->upstream_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->upstream_fd, NULL);
        magnus_upstream_owner[connection->upstream_fd] = NULL;
        close(connection->upstream_fd);
    }
    magnus_connections[fd] = NULL;
    free(connection);
}

static int
magnus_start_proxy(int epoll_fd, magnus_connection_t *connection,
                   const magnus_request_t *request)
{
    struct epoll_event event;
    int result;
    int written;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS
        || (connection->proxy_buffer = malloc(MAGNUS_PROXY_BUFFER)) == NULL) {
        if (fd >= 0) close(fd);
        return -1;
    }
    written = snprintf(connection->proxy_request,
                       sizeof(connection->proxy_request),
                       "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                       "Connection: close\r\nX-Magnus-Request-Id: %s\r\n\r\n",
                       request->method, request->path + 6, request->request_id);
    if (written < 0 || (size_t) written >= sizeof(connection->proxy_request)) {
        close(fd);
        return -1;
    }
    result = connect(fd, (struct sockaddr *) &magnus_upstream_address,
                     sizeof(magnus_upstream_address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    connection->upstream_fd = fd;
    connection->proxy_active = true;
    connection->proxy_connected = result == 0;
    connection->proxy_request_length = (size_t) written;
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
    return magnus_update_interest(epoll_fd, connection, EPOLLRDHUP);
}

static int
magnus_proxy_flush(int epoll_fd, magnus_connection_t *connection)
{
    while (connection->proxy_buffer_sent < connection->proxy_buffer_length) {
        ssize_t sent = magnus_socket_write(connection,
            connection->proxy_buffer + connection->proxy_buffer_sent,
            connection->proxy_buffer_length - connection->proxy_buffer_sent);
        if (sent > 0) {
            connection->proxy_buffer_sent += (size_t) sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return magnus_update_interest(epoll_fd, connection,
                                          EPOLLOUT | EPOLLRDHUP);
        return -1;
    }
    connection->proxy_buffer_length = 0;
    connection->proxy_buffer_sent = 0;
    if (connection->proxy_eof) return -1;
    if (connection->upstream_fd >= 0) {
        struct epoll_event event = { .events = EPOLLIN | EPOLLRDHUP,
                                     .data.fd = connection->upstream_fd };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd, &event);
    }
    return magnus_update_interest(epoll_fd, connection, EPOLLRDHUP);
}

static int
magnus_handle_upstream(int epoll_fd, magnus_connection_t *connection,
                       uint32_t flags)
{
    struct epoll_event event;
    if ((flags & (EPOLLERR | EPOLLHUP)) != 0) return -1;
    if (!connection->proxy_connected) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(connection->upstream_fd, SOL_SOCKET, SO_ERROR,
                       &error, &length) < 0 || error != 0) return -1;
        connection->proxy_connected = true;
    }
    while (!connection->proxy_headers_sent) {
        ssize_t sent = send(connection->upstream_fd,
            connection->proxy_request + connection->proxy_request_sent,
            connection->proxy_request_length - connection->proxy_request_sent,
            MSG_NOSIGNAL);
        if (sent > 0) connection->proxy_request_sent += (size_t) sent;
        else if (sent < 0 && errno == EINTR) continue;
        else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        else return -1;
        if (connection->proxy_request_sent == connection->proxy_request_length)
            connection->proxy_headers_sent = true;
    }
    if (connection->proxy_buffer_length != 0) return 0;
    if ((flags & EPOLLIN) != 0 || (flags & EPOLLRDHUP) != 0) {
        ssize_t received = recv(connection->upstream_fd, connection->proxy_buffer,
                                MAGNUS_PROXY_BUFFER, 0);
        if (received > 0) connection->proxy_buffer_length = (size_t) received;
        else if (received == 0) connection->proxy_eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -1;
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

    if (strcmp(request.method, "GET") != 0 && !head_only) {
        magnus_prepare_response(connection, 405, "Method Not Allowed",
                                "text/plain", "method not allowed\n", false,
                                close_connection, &request);
    } else if (strcmp(request.path, "/healthz") == 0) {
        magnus_prepare_response(connection, 200, "OK", "text/plain",
                                "magnus: ok\n", head_only, close_connection,
                                &request);
    } else if (strcmp(request.path, "/metrics") == 0) {
        char metrics[768];
        snprintf(metrics, sizeof(metrics),
            "# TYPE magnus_connections_total counter\n"
            "magnus_connections_total %llu\n"
            "# TYPE magnus_connections_active gauge\n"
            "magnus_connections_active %llu\n"
            "# TYPE magnus_requests_total counter\n"
            "magnus_requests_total %llu\n"
            "magnus_responses_4xx_total %llu\n"
            "magnus_responses_5xx_total %llu\n"
            "magnus_bytes_sent_total %llu\n",
            (unsigned long long) magnus_connections_total,
            (unsigned long long) magnus_connections_active,
            (unsigned long long) magnus_requests_total,
            (unsigned long long) magnus_responses_4xx,
            (unsigned long long) magnus_responses_5xx,
            (unsigned long long) magnus_bytes_sent);
        magnus_prepare_response(connection, 200, "OK",
                                "text/plain; version=0.0.4", metrics,
                                head_only, close_connection, &request);
    } else if (magnus_upstream_enabled
               && strncmp(request.path, "/proxy", 6) == 0
               && (request.path[6] == '/' || request.path[6] == '\0')) {
        if (magnus_start_proxy(epoll_fd, connection, &request) == 0) {
            fprintf(stderr,
                    "access request_id=%s method=%s target=%s status=proxy\n",
                    request.request_id, request.method, request.path);
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
    fprintf(stderr, "access request_id=%s method=%s target=%s status=%u\n",
            request.request_id, request.method, request.path, request.status);
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
magnus_accept_connections(int epoll_fd, int listener)
{
    for (;;) {
        int client = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
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
        if (magnus_tls_context != NULL) {
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
        if (connection != NULL
            && now - connection->last_active > MAGNUS_IDLE_SECONDS) {
            magnus_close_connection(epoll_fd, connection);
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

static unsigned
magnus_parse_options(int argc, char **argv)
{
    unsigned port = 0;
    int index;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("Magnus Web Engine %s (native C17/epoll)\n", MAGNUS_VERSION);
        exit(0);
    }
    const char *certificate = NULL;
    const char *private_key = NULL;
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
            char address[64];
            char *separator;
            char *end;
            unsigned long upstream_port;
            if (strlen(argv[index + 1]) >= sizeof(address)) break;
            strcpy(address, argv[index + 1]);
            separator = strrchr(address, ':');
            if (separator == NULL) break;
            *separator++ = '\0';
            errno = 0;
            upstream_port = strtoul(separator, &end, 10);
            if (errno != 0 || *end != '\0' || upstream_port == 0
                || upstream_port > 65535
                || inet_pton(AF_INET, address,
                             &magnus_upstream_address.sin_addr) != 1) break;
            magnus_upstream_address.sin_family = AF_INET;
            magnus_upstream_address.sin_port = htons((uint16_t) upstream_port);
            magnus_upstream_enabled = true;
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
                    "[--upstream <ipv4:port>] | --version\n",
            argv[0]);
    exit(2);
}

int
main(int argc, char **argv)
{
    unsigned port = magnus_parse_options(argc, argv);
    int listener = magnus_create_listener(port);
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

    magnus_phase_init(&magnus_phases);
    if (magnus_phase_register(&magnus_phases, MAGNUS_PHASE_INGRESS, 100,
                              "request-trace", magnus_trace_handler, NULL) != 0) {
        fprintf(stderr, "magnus: phase registration failed\n");
        return 1;
    }
    signal(SIGINT, magnus_signal_handler);
    signal(SIGTERM, magnus_signal_handler);
    signal(SIGPIPE, SIG_IGN);
    fprintf(stderr, "magnus: native engine listening on 0.0.0.0:%u\n", port);

    while (magnus_running) {
        int ready = epoll_wait(epoll_fd, events, MAGNUS_MAX_EVENTS, 1000);
        int index;
        time_t now = time(NULL);
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
                (void) magnus_accept_connections(epoll_fd, listener);
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
            }
            if (result < 0 && magnus_connections[fd] != NULL) {
                magnus_close_connection(epoll_fd, connection);
            }
        }
        if (now != last_sweep) {
            magnus_expire_idle(epoll_fd, now);
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
    if (magnus_root_fd >= 0) close(magnus_root_fd);
    if (magnus_tls_context != NULL) SSL_CTX_free(magnus_tls_context);
    fprintf(stderr, "magnus: stopped\n");
    return 0;
}
