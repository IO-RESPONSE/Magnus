#ifndef MAGNUS_STATIC_H
#define MAGNUS_STATIC_H

/* magnus.c's own static-file-serving and built-in-text-response
 * (/healthz, /metrics) primitives, exposed (not `static`) for
 * magnus_quic.c's HTTP/3 request dispatch (roadmap Phase 4b/4c) to
 * reuse directly -- the same reasoning magnus_h2.h's own comment gives
 * for why HTTP/2's request dispatch lives inline in magnus.c instead of
 * magnus_h2.c: deep access to these internals is unavoidable. QUIC
 * cannot follow that same pattern (HTTP/2 piggybacks on the *existing*
 * per-fd magnus_connection_t; a QUIC connection has no fd of its own --
 * see src/magnus_quic.h), so this header is the boundary instead: magnus.c
 * still *owns* path resolution/traversal safety, MIME typing, and metrics
 * text generation -- every protocol agrees on them by construction
 * rather than each maintaining its own copy, but magnus_quic.c calls
 * them across a real translation unit boundary rather than inline. */

#include "magnus_policy.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

/* Document root fd (O_DIRECTORY), or -1 if no root is configured. */
extern int magnus_root_fd;

/* Resolves `target` (a request path, e.g. "/index.html", query string
 * and all -- see the .c definition for the exact traversal-safety
 * rules) against magnus_root_fd and returns an open, read-only fd for
 * it plus its metadata, or -1 if it doesn't resolve to a regular file
 * magnus_root_fd can safely serve. Caller owns the returned fd. */
int magnus_open_static(const char *target, struct stat *metadata);

/* MIME type for `path`, by extension; a safe generic default when the
 * extension is unrecognized or absent. Never fails. */
const char *magnus_content_type(const char *path);

/* True once --admin-socket/admin_socket is configured -- /metrics is
 * withdrawn from every *public* listener (the main TCP one already,
 * roadmap 1e-4; the QUIC one too, roadmap 4c) once this is set, same
 * access-control boundary applied consistently across protocols.
 * /healthz is unaffected -- it stays public on every listener
 * regardless, since that is what a load balancer on the public port
 * needs to reach. */
extern bool magnus_admin_enabled;

/* Renders the current Prometheus text-format /metrics body into `out`
 * (NUL-terminated, truncated rather than overflowed if it doesn't
 * fit -- see the .c definition). The one place every protocol's own
 * /metrics response (HTTP/1.1, HTTP/2, HTTP/3) gets its numbers from,
 * so they cannot drift into reporting different counts for the same
 * process. */
void magnus_build_metrics(char *out, size_t out_capacity);

/* The plain (non-route-table) upstream cluster `--upstream`/`upstream=`
 * configures -- what a literal "/proxy" path prefix dispatches to on
 * every protocol, HTTP/3's new proxy dispatch (roadmap 4d) included.
 * `magnus_upstream_enabled` is `magnus_cluster.count > 0`, kept as its
 * own flag (not recomputed from the count each time) for the same
 * reason every other protocol's own dispatch already reads it that way.
 * Deliberately NOT the `route` table (host/path-prefix/header/cookie/
 * query/source-CIDR matching, each with its own cluster) -- 4d's own
 * scope note in src/magnus_quic.h covers why. */
extern magnus_cluster_t magnus_cluster;
extern bool magnus_upstream_enabled;

/* Resolves cluster endpoint `index` (`magnus_cluster`'s own indexing)
 * to a connectable IPv4 address, or false if `index` is out of range or
 * the endpoint is a not-yet-resolved hostname (roadmap 1c) with no
 * address available yet. */
bool magnus_endpoint_sockaddr(size_t index, struct sockaddr_in *out);

/* The one epoll instance every fd in this process is registered
 * against -- an HTTP/3 proxy dispatch's own upstream connection fd
 * (roadmap 4d) included, despite the QUIC connection that owns it
 * having no fd of its own. Set once, early in main(), well before any
 * QUIC traffic can arrive. */
extern int magnus_global_epoll_fd;

#endif
