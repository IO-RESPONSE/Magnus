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

    /* sticky selection: an in-range, available preferred index is returned
     * directly and does not disturb the round-robin weight ledger. */
    {
        magnus_cluster_t sticky;
        int a;
        int b;
        magnus_cluster_init(&sticky, 3, 1000);
        assert(magnus_cluster_add(&sticky, "127.0.0.1", 9001, 1) == 0);
        assert(magnus_cluster_add(&sticky, "127.0.0.1", 9002, 1) == 0);
        assert(magnus_cluster_select_sticky(&sticky, 0, 1) == 1);
        assert(magnus_cluster_select_sticky(&sticky, 0, 1) == 1);
        assert(magnus_cluster_select_sticky(&sticky, 0, 0) == 0);
        /* out of range: falls back to plain round robin instead of erroring */
        assert(magnus_cluster_select_sticky(&sticky, 0, 99) >= 0);
        /* preferred endpoint down (3 strikes): falls back to the other one */
        magnus_cluster_result(&sticky, 1, false, 100);
        magnus_cluster_result(&sticky, 1, false, 100);
        magnus_cluster_result(&sticky, 1, false, 100);
        assert(!sticky.endpoints[1].healthy);
        a = magnus_cluster_select_sticky(&sticky, 200, 1);
        assert(a == 0);
        /* once its cooldown passes, the preferred endpoint is honored again */
        b = magnus_cluster_select_sticky(&sticky, 2000, 1);
        assert(b == 1);
    }
    return 0;
}
