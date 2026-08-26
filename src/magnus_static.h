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

#include <openssl/ssl.h>

#include "magnus_config.h"
#include "magnus_policy.h"
#include "magnus_route.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

/* Document root fd (O_DIRECTORY), or -1 if no root is configured. */
extern int magnus_root_fd;

/* Resolves `target` (a request path, e.g. "/index.html", query string
 * and all -- see the .c definition for the exact traversal-safety
 * rules) against `root_override` if non-NULL, or magnus_root_fd
 * otherwise, and returns an open, read-only fd for it plus its
 * metadata, or -1 if it doesn't resolve to a regular file the chosen
 * root can safely serve. `root_override` (roadmap 1b: a matched
 * action=static route's own `root=<path>` -- src/magnus_route.h) is a
 * plain directory path, opened fresh (O_DIRECTORY) on every call rather
 * than cached the way magnus_root_fd is, since it is not known until a
 * route actually matches and this codebase has no per-route fd table to
 * keep one warm in; NULL means "no route-level override applies, use
 * the process's own global document root" exactly as before this
 * parameter existed. Caller owns the returned fd. */
int magnus_open_static(const char *target, struct stat *metadata,
                       const char *root_override);

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

/* The plain upstream cluster `--upstream`/`upstream=` configures --
 * what a literal "/proxy" path prefix dispatches to on every protocol,
 * HTTP/3's own proxy dispatch (roadmap 4d) included, and also what a
 * matched `route` table entry's own action=proxy dispatches to (roadmap
 * 4f) -- there is only ever this one cluster; a route match decides
 * *whether* and *what path* to forward, never a different upstream of
 * its own (matching magnus_proxy_pick_and_start()'s identical h1/h2
 * behavior). `magnus_upstream_enabled` is `magnus_cluster.count > 0`,
 * kept as its own flag (not recomputed from the count each time) for
 * the same reason every other protocol's own dispatch already reads it
 * that way. */
extern magnus_cluster_t magnus_cluster;
extern bool magnus_upstream_enabled;

/* The `route` table (roadmap 4f for HTTP/3; host/path-prefix/method/
 * header/header_prefix/cookie/query/source-CIDR matching -- see
 * src/magnus_route.h) every protocol evaluates in file order, first
 * match wins, ahead of falling through to the literal "/proxy" prefix
 * and static-file dispatch. `magnus_route_count` entries are valid in
 * `magnus_routes[]`; the array itself is sized (MAGNUS_CONFIG_MAX_ROUTES,
 * src/magnus_config.h) only where it is actually defined, magnus.c --
 * declared here as an incomplete array type (valid C, just not
 * `sizeof`-able from this translation unit, which magnus_quic.c never
 * needs to do since it only ever indexes up to magnus_route_count). */
extern magnus_route_t magnus_routes[];
extern size_t magnus_route_count;

/* Real IP (roadmap 2b), exposed here for the identical reason
 * magnus_routes[]/magnus_route_count just above are: config state
 * magnus.c owns and populates once at startup (magnus_apply_config()),
 * read (never written) by magnus_quic.c's own HTTP/3 dispatch --
 * magnus_realip_is_trusted()/magnus_realip_resolve_headers() themselves
 * already have real prototypes in src/magnus_realip.h, which
 * magnus_quic.c includes directly; only the trust-list data itself,
 * with no natural header of its own, needs exposing here.
 * `magnus_trusted_proxy_count` entries are valid in
 * `magnus_trusted_proxies[]`, sized (MAGNUS_CONFIG_MAX_TRUSTED_PROXIES,
 * src/magnus_config.h) only where it is actually defined, magnus.c. */
extern magnus_cidr_t magnus_trusted_proxies[];
extern size_t magnus_trusted_proxy_count;

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

/* Session affinity (roadmap 4h for HTTP/3): the MAGNUS_AFFINITY cookie
 * codec every protocol's own proxy dispatch shares -- decode a
 * returning client's cookie value into the cluster endpoint index it
 * names (false if absent/malformed, meaning "no sticky preference"),
 * or encode a fresh one naming the endpoint a request actually landed
 * on. `magnus_cluster_select_sticky()` (src/magnus_policy.h) and
 * `magnus_proxy_sanitize_response_headers()`'s own `affinity_key`
 * parameter (src/magnus_proxy.h, already the place every protocol's
 * proxy response emits the resulting Set-Cookie) are the other two
 * pieces of this same mechanism -- neither needed exposing here, both
 * already public. */
bool magnus_decode_affinity_cookie(const char *cookie, size_t *out_index);
void magnus_encode_affinity_cookie(char *out, size_t out_capacity,
                                   size_t endpoint_index);

/* Idle upstream connection pool (roadmap 4j for HTTP/3), keyed by
 * cluster endpoint -- one shared pool, not one per protocol, since it
 * is indexed by which *endpoint* a connection belongs to, never by
 * which client connection or protocol asked for it (the same reasoning
 * magnus_h2_proxy_connect_endpoint()'s own comment gives for reusing
 * this unmodified on the h2 side). `magnus_pool_checkout()` returns a
 * still-live, reusable fd for `endpoint_index` if one is idle (-1 if
 * not, meaning "open a fresh connection instead" exactly as if pooling
 * did not exist), also filling in how many requests that connection has
 * already served. `magnus_pool_checkin()` returns a finished
 * connection's fd to the idle pool if it still has budget left
 * (MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION, magnus.c-internal), or
 * simply closes it -- caller must have already cleared its own
 * *_upstream_owner[]/epoll registration for `fd` first, since idle
 * connections are deliberately not registered with epoll at all.
 * `out_tls` (roadmap 1a-2, TLS-upstream connection support) receives the
 * checked-out connection's live TLS session for a TLS upstream endpoint,
 * or NULL for a plain-TCP one; magnus_quic.c's own HTTP/3 proxy dispatch
 * always passes NULL here (that path is not TLS-upstream-aware in this
 * increment -- see docs/development-roadmap.md), which is safe: a TLS
 * slot is simply never handed to a NULL-out_tls caller (see
 * magnus_pool_checkout()'s own magnus.c-side comment for exactly what
 * happens to it instead). Passing a live SSL* into magnus_pool_checkin()
 * for an endpoint that is not itself TLS should never happen and is not
 * specially guarded against -- callers only ever pass back what
 * magnus_pool_checkout() itself handed them. */
int magnus_pool_checkout(size_t endpoint_index, unsigned *out_requests_served,
                         SSL **out_tls);
void magnus_pool_checkin(size_t endpoint_index, int fd,
                         unsigned requests_served, SSL *tls);

#endif
