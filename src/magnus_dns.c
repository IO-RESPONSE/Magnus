#include "magnus_dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAGNUS_DNS_QUEUE_SIZE 32
#define MAGNUS_DNS_HOSTNAME_MAX 256

typedef struct {
    char hostname[MAGNUS_DNS_HOSTNAME_MAX];
    size_t token;
} magnus_dns_request_t;

static pthread_t magnus_dns_thread;
static pthread_mutex_t magnus_dns_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t magnus_dns_cond = PTHREAD_COND_INITIALIZER;
static bool magnus_dns_running;
static bool magnus_dns_shutdown_requested;
static int magnus_dns_eventfd_fd = -1;

static magnus_dns_request_t magnus_dns_requests[MAGNUS_DNS_QUEUE_SIZE];
static size_t magnus_dns_request_head;
static size_t magnus_dns_request_count;

static magnus_dns_result_t magnus_dns_results[MAGNUS_DNS_QUEUE_SIZE];
static size_t magnus_dns_result_head;
static size_t magnus_dns_result_count;

static void
magnus_dns_resolve_one(const magnus_dns_request_t *request,
                       magnus_dns_result_t *out)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    out->token = request->token;
    out->ok = false;
    out->address[0] = '\0';

    /* This is the one blocking call in this entire module -- deliberately
     * kept off the main thread (see magnus_dns.h's design note) rather
     * than avoided, since avoiding it means hand-rolling DNS wire-format
     * parsing instead. */
    rc = getaddrinfo(request->hostname, NULL, &hints, &result);
    if (rc == 0 && result != NULL) {
        const struct sockaddr_in *address
            = (const struct sockaddr_in *) (const void *) result->ai_addr;
        if (inet_ntop(AF_INET, &address->sin_addr, out->address,
                      sizeof(out->address)) != NULL) {
            out->ok = true;
        }
        freeaddrinfo(result);
    }
}

static void *
magnus_dns_worker(void *unused)
{
    (void) unused;
    for (;;) {
        magnus_dns_request_t request;
        magnus_dns_result_t result;
        uint64_t one = 1;
        ssize_t ignored;

        pthread_mutex_lock(&magnus_dns_mutex);
        while (magnus_dns_request_count == 0 && !magnus_dns_shutdown_requested)
            pthread_cond_wait(&magnus_dns_cond, &magnus_dns_mutex);
        if (magnus_dns_request_count == 0 && magnus_dns_shutdown_requested) {
            pthread_mutex_unlock(&magnus_dns_mutex);
            break;
        }
        request = magnus_dns_requests[magnus_dns_request_head];
        magnus_dns_request_head
            = (magnus_dns_request_head + 1) % MAGNUS_DNS_QUEUE_SIZE;
        magnus_dns_request_count--;
        pthread_mutex_unlock(&magnus_dns_mutex);

        magnus_dns_resolve_one(&request, &result);

        pthread_mutex_lock(&magnus_dns_mutex);
        if (magnus_dns_result_count < MAGNUS_DNS_QUEUE_SIZE) {
            size_t tail = (magnus_dns_result_head + magnus_dns_result_count)
                % MAGNUS_DNS_QUEUE_SIZE;
            magnus_dns_results[tail] = result;
            magnus_dns_result_count++;
        }
        /* else: the main thread has not drained in a very long time (its
         * own queue-size worth of outstanding lookups) -- drop rather
         * than block the worker or grow unboundedly. The periodic
         * re-resolution schedule in magnus.c will simply ask again. */
        pthread_mutex_unlock(&magnus_dns_mutex);

        ignored = write(magnus_dns_eventfd_fd, &one, sizeof(one));
        (void) ignored;
    }
    return NULL;
}

int
magnus_dns_start(void)
{
    if (magnus_dns_running) return -1;
    magnus_dns_eventfd_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (magnus_dns_eventfd_fd < 0) return -1;
    magnus_dns_shutdown_requested = false;
    magnus_dns_request_head = 0;
    magnus_dns_request_count = 0;
    magnus_dns_result_head = 0;
    magnus_dns_result_count = 0;
    if (pthread_create(&magnus_dns_thread, NULL, magnus_dns_worker, NULL) != 0) {
        close(magnus_dns_eventfd_fd);
        magnus_dns_eventfd_fd = -1;
        return -1;
    }
    magnus_dns_running = true;
    return magnus_dns_eventfd_fd;
}

void
magnus_dns_resolve(const char *hostname, size_t token)
{
    size_t tail;
    if (!magnus_dns_running || strlen(hostname) >= MAGNUS_DNS_HOSTNAME_MAX) return;
    pthread_mutex_lock(&magnus_dns_mutex);
    if (magnus_dns_request_count == MAGNUS_DNS_QUEUE_SIZE) {
        pthread_mutex_unlock(&magnus_dns_mutex);
        return;
    }
    tail = (magnus_dns_request_head + magnus_dns_request_count)
        % MAGNUS_DNS_QUEUE_SIZE;
    strcpy(magnus_dns_requests[tail].hostname, hostname);
    magnus_dns_requests[tail].token = token;
    magnus_dns_request_count++;
    pthread_cond_signal(&magnus_dns_cond);
    pthread_mutex_unlock(&magnus_dns_mutex);
}

void
magnus_dns_drain_results(void (*callback)(const magnus_dns_result_t *result,
                                          void *data), void *data)
{
    magnus_dns_result_t drained[MAGNUS_DNS_QUEUE_SIZE];
    size_t count;
    uint64_t ignored_count;
    ssize_t ignored;

    if (!magnus_dns_running) return;
    /* Consumes (and thereby re-arms) the eventfd's pending counter; the
     * actual results ride in the queue below, not in this value. A
     * nonblocking read failing with EAGAIN just means nothing new arrived
     * since the last drain, which is fine to no-op on. */
    ignored = read(magnus_dns_eventfd_fd, &ignored_count, sizeof(ignored_count));
    (void) ignored;

    pthread_mutex_lock(&magnus_dns_mutex);
    count = magnus_dns_result_count;
    for (size_t i = 0; i < count; i++) {
        drained[i] = magnus_dns_results[
            (magnus_dns_result_head + i) % MAGNUS_DNS_QUEUE_SIZE];
    }
    magnus_dns_result_head
        = (magnus_dns_result_head + count) % MAGNUS_DNS_QUEUE_SIZE;
    magnus_dns_result_count = 0;
    pthread_mutex_unlock(&magnus_dns_mutex);

    for (size_t i = 0; i < count; i++)
        callback(&drained[i], data);
}

void
magnus_dns_stop(void)
{
    if (!magnus_dns_running) return;
    pthread_mutex_lock(&magnus_dns_mutex);
    magnus_dns_shutdown_requested = true;
    pthread_cond_signal(&magnus_dns_cond);
    pthread_mutex_unlock(&magnus_dns_mutex);
    pthread_join(magnus_dns_thread, NULL);
    close(magnus_dns_eventfd_fd);
    magnus_dns_eventfd_fd = -1;
    magnus_dns_running = false;
}
