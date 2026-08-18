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

#endif
