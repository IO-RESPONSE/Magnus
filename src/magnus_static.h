#ifndef MAGNUS_STATIC_H
#define MAGNUS_STATIC_H

/* magnus.c's own static-file-serving primitives, exposed (not `static`)
 * for magnus_quic.c's HTTP/3 static-file dispatch (roadmap Phase 4b) to
 * reuse directly -- the same reasoning magnus_h2.h's own comment gives
 * for why HTTP/2's request dispatch lives inline in magnus.c instead of
 * magnus_h2.c: deep access to these internals is unavoidable. QUIC
 * cannot follow that same pattern (HTTP/2 piggybacks on the *existing*
 * per-fd magnus_connection_t; a QUIC connection has no fd of its own --
 * see src/magnus_quic.h), so this header is the boundary instead: magnus.c
 * still *owns* path resolution/traversal safety and MIME typing, both
 * protocols agree on them by construction rather than each maintaining
 * their own copy, but magnus_quic.c calls them across a real translation
 * unit boundary rather than inline. */

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

#endif
