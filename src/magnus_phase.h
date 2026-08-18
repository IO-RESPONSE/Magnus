#ifndef MAGNUS_PHASE_H
#define MAGNUS_PHASE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    MAGNUS_PHASE_INGRESS = 0,
    MAGNUS_PHASE_ROUTE,
    MAGNUS_PHASE_RESPONSE,
    MAGNUS_PHASE_LOG,
    MAGNUS_PHASE_COUNT
} magnus_phase_t;

typedef struct {
    char method[8];
    char path[256];
    char request_id[33];
    unsigned status;
    uint32_t phases;
} magnus_request_t;

typedef int (*magnus_phase_handler_t)(magnus_request_t *request, void *data);

typedef struct {
    magnus_phase_t phase;
    int priority;
    const char *name;
    magnus_phase_handler_t handler;
    void *data;
} magnus_hook_t;

#define MAGNUS_MAX_HOOKS 64

typedef struct {
    magnus_hook_t hooks[MAGNUS_MAX_HOOKS];
    size_t count;
} magnus_phase_engine_t;

void magnus_phase_init(magnus_phase_engine_t *engine);
int magnus_phase_register(magnus_phase_engine_t *engine, magnus_phase_t phase,
                          int priority, const char *name,
                          magnus_phase_handler_t handler, void *data);
int magnus_phase_run(magnus_phase_engine_t *engine, magnus_phase_t phase,
                     magnus_request_t *request);

#endif
