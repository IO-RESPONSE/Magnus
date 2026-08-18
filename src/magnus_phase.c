#include "magnus_phase.h"

#include <string.h>

void
magnus_phase_init(magnus_phase_engine_t *engine)
{
    memset(engine, 0, sizeof(*engine));
}

int
magnus_phase_register(magnus_phase_engine_t *engine, magnus_phase_t phase,
                      int priority, const char *name,
                      magnus_phase_handler_t handler, void *data)
{
    size_t index;

    if (engine == NULL || handler == NULL || name == NULL
        || phase >= MAGNUS_PHASE_COUNT || engine->count >= MAGNUS_MAX_HOOKS) {
        return -1;
    }

    index = engine->count++;
    while (index > 0 && engine->hooks[index - 1].priority > priority) {
        engine->hooks[index] = engine->hooks[index - 1];
        index--;
    }
    engine->hooks[index] = (magnus_hook_t) {
        .phase = phase,
        .priority = priority,
        .name = name,
        .handler = handler,
        .data = data
    };
    return 0;
}

int
magnus_phase_run(magnus_phase_engine_t *engine, magnus_phase_t phase,
                 magnus_request_t *request)
{
    size_t index;
    int result;

    if (engine == NULL || request == NULL || phase >= MAGNUS_PHASE_COUNT) {
        return -1;
    }
    for (index = 0; index < engine->count; index++) {
        magnus_hook_t *hook = &engine->hooks[index];
        if (hook->phase != phase) {
            continue;
        }
        result = hook->handler(request, hook->data);
        if (result != 0) {
            return result;
        }
    }
    request->phases |= UINT32_C(1) << phase;
    return 0;
}
