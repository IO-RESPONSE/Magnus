#include "magnus_policy.h"

#include <assert.h>

int main(void)
{
    magnus_cluster_t cluster;
    magnus_rate_limit_t rate;
    int first;
    magnus_cluster_init(&cluster, 2, 1000);
    assert(magnus_cluster_add(&cluster, "127.0.0.1", 8001, 2) == 0);
    assert(magnus_cluster_add(&cluster, "127.0.0.1", 8002, 1) == 0);
    assert(magnus_cluster_select(&cluster, 0, NULL) == 0);
    assert(magnus_cluster_select(&cluster, 0, NULL) == 1);
    assert(magnus_cluster_select(&cluster, 0, NULL) == 0);
    first = magnus_cluster_select(&cluster, 0, "session-a");
    assert(first == magnus_cluster_select(&cluster, 0, "session-a"));
    magnus_cluster_result(&cluster, (size_t) first, false, 100);
    magnus_cluster_result(&cluster, (size_t) first, false, 100);
    assert(!cluster.endpoints[first].healthy);
    assert(magnus_cluster_select(&cluster, 200, "session-a") != first);
    assert(magnus_cluster_select(&cluster, 1200, "session-a") == first);
    magnus_rate_init(&rate, 2.0, 2.0, 0);
    assert(magnus_rate_allow(&rate, 0));
    assert(magnus_rate_allow(&rate, 0));
    assert(!magnus_rate_allow(&rate, 0));
    assert(magnus_rate_allow(&rate, 500));
    return 0;
}
