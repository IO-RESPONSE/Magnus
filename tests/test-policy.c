#include "magnus_policy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

static struct in_addr
ip(const char *text)
{
    struct in_addr address;
    assert(inet_pton(AF_INET, text, &address) == 1);
    return address;
}

int main(void)
{
    struct in_addr no_ip = {0};
    magnus_cluster_t cluster;
    magnus_rate_limit_t rate;
    int first;
    magnus_cluster_init(&cluster, 2, 1000, MAGNUS_LB_ROUND_ROBIN);
    assert(magnus_cluster_add(&cluster, "127.0.0.1", 8001, 2) == 0);
    assert(magnus_cluster_add(&cluster, "127.0.0.1", 8002, 1) == 0);
    assert(magnus_cluster_select(&cluster, 0, NULL, no_ip) == 0);
    assert(magnus_cluster_select(&cluster, 0, NULL, no_ip) == 1);
    assert(magnus_cluster_select(&cluster, 0, NULL, no_ip) == 0);
    first = magnus_cluster_select(&cluster, 0, "session-a", no_ip);
    assert(first == magnus_cluster_select(&cluster, 0, "session-a", no_ip));
    magnus_cluster_result(&cluster, (size_t) first, false, 100);
    magnus_cluster_result(&cluster, (size_t) first, false, 100);
    assert(!cluster.endpoints[first].healthy);
    assert(magnus_cluster_select(&cluster, 200, "session-a", no_ip) != first);
    assert(magnus_cluster_select(&cluster, 1200, "session-a", no_ip) == first);
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
        magnus_cluster_init(&sticky, 3, 1000, MAGNUS_LB_ROUND_ROBIN);
        assert(magnus_cluster_add(&sticky, "127.0.0.1", 9001, 1) == 0);
        assert(magnus_cluster_add(&sticky, "127.0.0.1", 9002, 1) == 0);
        assert(magnus_cluster_select_sticky(&sticky, 0, 1, no_ip) == 1);
        assert(magnus_cluster_select_sticky(&sticky, 0, 1, no_ip) == 1);
        assert(magnus_cluster_select_sticky(&sticky, 0, 0, no_ip) == 0);
        /* out of range: falls back to plain round robin instead of erroring */
        assert(magnus_cluster_select_sticky(&sticky, 0, 99, no_ip) >= 0);
        /* preferred endpoint down (3 strikes): falls back to the other one */
        magnus_cluster_result(&sticky, 1, false, 100);
        magnus_cluster_result(&sticky, 1, false, 100);
        magnus_cluster_result(&sticky, 1, false, 100);
        assert(!sticky.endpoints[1].healthy);
        a = magnus_cluster_select_sticky(&sticky, 200, 1, no_ip);
        assert(a == 0);
        /* once its cooldown passes, the preferred endpoint is honored again */
        b = magnus_cluster_select_sticky(&sticky, 2000, 1, no_ip);
        assert(b == 1);
    }

    /* MAGNUS_LB_LEAST_CONN (roadmap 2e-1): always picks the endpoint with
     * the fewest active_requests, ties broken by lowest index -- entirely
     * independent of the weighted round-robin ledger (never consulted by
     * this policy at all). */
    {
        magnus_cluster_t lc;
        magnus_cluster_init(&lc, 3, 1000, MAGNUS_LB_LEAST_CONN);
        assert(magnus_cluster_add(&lc, "127.0.0.1", 9101, 1) == 0);
        assert(magnus_cluster_add(&lc, "127.0.0.1", 9102, 1) == 0);
        assert(magnus_cluster_add(&lc, "127.0.0.1", 9103, 1) == 0);
        /* all tied at 0 -> lowest index wins */
        assert(magnus_cluster_select(&lc, 0, NULL, no_ip) == 0);
        magnus_cluster_endpoint_begin(&lc, 0);
        magnus_cluster_endpoint_begin(&lc, 0);
        magnus_cluster_endpoint_begin(&lc, 1);
        /* 0 has 2 in flight, 1 has 1, 2 has 0 -> 2 wins */
        assert(magnus_cluster_select(&lc, 0, NULL, no_ip) == 2);
        magnus_cluster_endpoint_begin(&lc, 2);
        /* now 0=2, 1=1, 2=1 -> lowest index among the tied pair (1) wins */
        assert(magnus_cluster_select(&lc, 0, NULL, no_ip) == 1);
        magnus_cluster_endpoint_end(&lc, 0);
        magnus_cluster_endpoint_end(&lc, 0);
        /* end() on an already-0 count never underflows */
        magnus_cluster_endpoint_end(&lc, 0);
        assert(lc.endpoints[0].active_requests == 0);
        /* now 0=0, 1=1, 2=1 -> 0 wins again */
        assert(magnus_cluster_select(&lc, 0, NULL, no_ip) == 0);
        /* an unhealthy endpoint is skipped regardless of its own count */
        magnus_cluster_result(&lc, 0, false, 100);
        magnus_cluster_result(&lc, 0, false, 100);
        magnus_cluster_result(&lc, 0, false, 100);
        assert(!lc.endpoints[0].healthy);
        assert(magnus_cluster_select(&lc, 200, NULL, no_ip) != 0);
        /* an explicit affinity_key still always wins over the policy */
        {
            int by_key = magnus_cluster_select(&lc, 200, "sticky-token", no_ip);
            assert(by_key == magnus_cluster_select(&lc, 200, "sticky-token",
                                                    no_ip));
        }
    }

    /* MAGNUS_LB_IP_HASH (roadmap 2e-1): the same client IP always maps to
     * the same endpoint, deterministically, with no affinity_key at all;
     * two different IPs are not guaranteed (or expected) to land on
     * different endpoints, only to each be internally consistent. */
    {
        magnus_cluster_t ih;
        struct in_addr client_a = ip("10.0.0.5");
        struct in_addr client_b = ip("10.0.0.6");
        int a1, a2, b1;
        magnus_cluster_init(&ih, 3, 1000, MAGNUS_LB_IP_HASH);
        assert(magnus_cluster_add(&ih, "127.0.0.1", 9201, 1) == 0);
        assert(magnus_cluster_add(&ih, "127.0.0.1", 9202, 1) == 0);
        assert(magnus_cluster_add(&ih, "127.0.0.1", 9203, 1) == 0);
        a1 = magnus_cluster_select(&ih, 0, NULL, client_a);
        a2 = magnus_cluster_select(&ih, 0, NULL, client_a);
        assert(a1 == a2);
        b1 = magnus_cluster_select(&ih, 0, NULL, client_b);
        assert(b1 >= 0);
        /* an affinity_key, if one is somehow also presented, still wins
         * over ip_hash -- the cookie mechanism and ip_hash are two
         * different stickiness sources, but the cookie is always the
         * more specific/explicit one. */
        assert(magnus_cluster_select(&ih, 0, "explicit-cookie", client_a)
               == magnus_cluster_select(&ih, 0, "explicit-cookie", client_a));
        /* removing client_a's own winning endpoint only remaps client_a,
         * not client_b, if client_b's own winner is a different endpoint
         * (the whole point of rendezvous over plain modulo hashing). */
        {
            int before_b = b1;
            magnus_cluster_result(&ih, (size_t) a1, false, 100);
            magnus_cluster_result(&ih, (size_t) a1, false, 100);
            magnus_cluster_result(&ih, (size_t) a1, false, 100);
            if (before_b != a1) {
                assert(magnus_cluster_select(&ih, 200, NULL, client_b)
                       == before_b);
            }
        }
    }

    return 0;
}
