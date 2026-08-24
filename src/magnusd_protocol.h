#ifndef MAGNUSD_PROTOCOL_H
#define MAGNUSD_PROTOCOL_H

/* The magnusd <-> magnusctl control protocol: one command per line over a
 * connected Unix domain stream socket, one response line back, then the
 * connection closes. Kept deliberately tiny (magnusd owns the config file
 * and the magnus child directly; magnusctl is a thin remote control, not
 * a general RPC client) -- see src/magnusd.c's file header for the wider
 * design. */

#define MAGNUSD_CMD_STATUS "STATUS"
#define MAGNUSD_CMD_RELOAD "RELOAD"
#define MAGNUSD_CMD_SHUTDOWN "SHUTDOWN"
/* Roadmap 5d-1 (Runtime API expansion): tells the running magnus child
 * to stop accepting new client connections while continuing to serve
 * every connection already in flight -- distinct from both RELOAD
 * (swaps live config, keeps accepting) and SHUTDOWN (unconditional,
 * does not wait for in-flight work). See src/magnusd.c's own
 * magnusd_drain() and src/magnus.c's own SIGUSR1 handling for the full
 * mechanism. */
#define MAGNUSD_CMD_DRAIN "DRAIN"
/* Roadmap 5e-1 (zero-downtime binary upgrade): replaces the running
 * magnus child with a fresh process (a new build, or the same binary
 * path re-executed) that inherits the live listener fd from the old
 * one via SCM_RIGHTS -- optionally followed by a space and a new
 * binary path on the same line ("UPGRADE /path/to/new/magnus"); a bare
 * "UPGRADE" re-executes whatever binary path magnusd was already
 * configured with. The only command in this protocol that carries an
 * argument on the wire at all -- every other one is still a bare
 * keyword. See src/magnusd.c's own magnusd_upgrade() for the full,
 * health-gated handoff sequence. */
#define MAGNUSD_CMD_UPGRADE "UPGRADE"

#endif
