#!/usr/bin/env bash
set -euo pipefail
[ -n "${TRACE:-}" ] && set -x

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary="$project_dir/build/magnus"
port=${MAGNUS_TEST_PORT:-19080}
log=$(mktemp)
web_root=$(mktemp -d)

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    cp "$log" /tmp/magnus-test-core-failure.log 2>/dev/null || true
    echo "test-core.sh failed; magnus stderr preserved at /tmp/magnus-test-core-failure.log" >&2
  fi
  if [ -n "${server_pid:-}" ]; then
    kill -TERM "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ -n "${backend_pid:-}" ]; then
    kill -TERM "$backend_pid" >/dev/null 2>&1 || true
    wait "$backend_pid" 2>/dev/null || true
  fi
  if [ -n "${backend2_pid:-}" ]; then
    kill -TERM "$backend2_pid" >/dev/null 2>&1 || true
    wait "$backend2_pid" 2>/dev/null || true
  fi
  if [ -n "${backend3_pid:-}" ]; then
    kill -TERM "$backend3_pid" >/dev/null 2>&1 || true
    wait "$backend3_pid" 2>/dev/null || true
  fi
  if [ -n "${backend4_pid:-}" ]; then
    kill -TERM "$backend4_pid" >/dev/null 2>&1 || true
    wait "$backend4_pid" 2>/dev/null || true
  fi
  if [ -n "${backend5_pid:-}" ]; then
    kill -TERM "$backend5_pid" >/dev/null 2>&1 || true
    wait "$backend5_pid" 2>/dev/null || true
  fi
  if [ -n "${backend6_pid:-}" ]; then
    kill -TERM "$backend6_pid" >/dev/null 2>&1 || true
    wait "$backend6_pid" 2>/dev/null || true
  fi
  if [ -n "${backend7_pid:-}" ]; then
    kill -TERM "$backend7_pid" >/dev/null 2>&1 || true
    wait "$backend7_pid" 2>/dev/null || true
  fi
  if [ -n "${backend8_pid:-}" ]; then
    kill -TERM "$backend8_pid" >/dev/null 2>&1 || true
    wait "$backend8_pid" 2>/dev/null || true
  fi
  if [ -n "${backend9_pid:-}" ]; then
    kill -TERM "$backend9_pid" >/dev/null 2>&1 || true
    wait "$backend9_pid" 2>/dev/null || true
  fi
  if [ -n "${backend10_pid:-}" ]; then
    kill -TERM "$backend10_pid" >/dev/null 2>&1 || true
    wait "$backend10_pid" 2>/dev/null || true
  fi
  if [ -n "${backend11_pid:-}" ]; then
    kill -TERM "$backend11_pid" >/dev/null 2>&1 || true
    wait "$backend11_pid" 2>/dev/null || true
  fi
  if [ -n "${backend12_pid:-}" ]; then
    kill -TERM "$backend12_pid" >/dev/null 2>&1 || true
    wait "$backend12_pid" 2>/dev/null || true
  fi
  if [ -n "${backend13_pid:-}" ]; then
    kill -TERM "$backend13_pid" >/dev/null 2>&1 || true
    wait "$backend13_pid" 2>/dev/null || true
  fi
  if [ -n "${backend14_pid:-}" ]; then
    kill -TERM "$backend14_pid" >/dev/null 2>&1 || true
    wait "$backend14_pid" 2>/dev/null || true
  fi
  if [ -n "${backend15_pid:-}" ]; then
    kill -TERM "$backend15_pid" >/dev/null 2>&1 || true
    wait "$backend15_pid" 2>/dev/null || true
  fi
  if [ -n "${backend16_pid:-}" ]; then
    kill -TERM "$backend16_pid" >/dev/null 2>&1 || true
    wait "$backend16_pid" 2>/dev/null || true
  fi
  if [ -n "${backend17_pid:-}" ]; then
    kill -TERM "$backend17_pid" >/dev/null 2>&1 || true
    wait "$backend17_pid" 2>/dev/null || true
  fi
  if [ -n "${backend18_pid:-}" ]; then
    kill -TERM "$backend18_pid" >/dev/null 2>&1 || true
    wait "$backend18_pid" 2>/dev/null || true
  fi
  if [ -n "${backend19_pid:-}" ]; then
    kill -TERM "$backend19_pid" >/dev/null 2>&1 || true
    wait "$backend19_pid" 2>/dev/null || true
  fi
  if [ -n "${backend20_pid:-}" ]; then
    kill -TERM "$backend20_pid" >/dev/null 2>&1 || true
    wait "$backend20_pid" 2>/dev/null || true
  fi
  if [ -n "${backend21_pid:-}" ]; then
    kill -TERM "$backend21_pid" >/dev/null 2>&1 || true
    wait "$backend21_pid" 2>/dev/null || true
  fi
  rm -f "$log"
  rm -rf "$web_root"
}
trap cleanup EXIT

"$binary" --version | grep -q 'native C17/epoll'
printf '%s\n' 'magnus static file' >"$web_root/hello.txt"
mkdir -p "$web_root/assets"
printf '%s\n' '<svg>magnus</svg>' >"$web_root/assets/logo.svg"
ln -s /etc/passwd "$web_root/passwd-link"
upstream_port=$((port + 2))
python3 -m http.server "$upstream_port" --bind 127.0.0.1 \
  --directory "$web_root" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_port/hello.txt" >/dev/null \
    && break
  sleep 1
done
"$binary" --port "$port" --root "$web_root" \
  --upstream "127.0.0.1:$upstream_port" 2>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port/healthz" >/dev/null && break
  sleep 1
done

headers=$(curl --fail --silent --dump-header - --output /dev/null \
  "http://127.0.0.1:$port/")
printf '%s' "$headers" | grep -qi '^Server: Magnus/'
printf '%s' "$headers" | grep -qi '^X-Magnus-Engine: native-c17/0.1'
first=$(printf '%s' "$headers" | sed -n 's/^X-Magnus-Request-Id: \([0-9a-f]*\).*/\1/ip')
second=$(curl --fail --silent --dump-header - --output /dev/null \
  "http://127.0.0.1:$port/" | sed -n 's/^X-Magnus-Request-Id: \([0-9a-f]*\).*/\1/ip')
test "${#first}" -eq 32
test "${#second}" -eq 32
test "$first" != "$second"

# Regression test for a missing-TCP_NODELAY bug: without it, each response
# on a reused keep-alive connection sat in Nagle's algorithm waiting on the
# peer's delayed ACK, adding a fixed ~40ms to every request regardless of
# load (Connection: close traffic never showed it, which is what let it
# hide). 20 sequential requests over one reused connection must finish
# nowhere near 20 * 40ms; give a generous 400ms ceiling so this stays
# reliable on a loaded host while still catching the regression, which
# would blow past a full second.
keepalive_urls=()
for _ in $(seq 1 20); do keepalive_urls+=("http://127.0.0.1:$port/hello.txt"); done
keepalive_start=$(date +%s%3N)
curl --fail --silent "${keepalive_urls[@]}" >/dev/null
keepalive_elapsed=$(( $(date +%s%3N) - keepalive_start ))
test "$keepalive_elapsed" -lt 400

test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port/missing")" = 404
test "$(curl --silent --request POST --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port/")" = 405
test "$(curl --fail --silent "http://127.0.0.1:$port/hello.txt")" = 'magnus static file'
curl --fail --silent --head "http://127.0.0.1:$port/assets/logo.svg" \
  | grep -qi '^Content-Type: image/svg+xml'
test "$(curl --path-as-is --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port/../etc/passwd")" = 404
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port/passwd-link")" = 404
test "$(curl --fail --silent "http://127.0.0.1:$port/proxy/hello.txt")" \
  = 'magnus static file'
curl --fail --silent "http://127.0.0.1:$port/metrics" \
  | grep -Eq '^magnus_connections_active [0-9]+'

# M2: upstream response headers are sanitized -- hop-by-hop headers
# dropped, exactly one Connection header, marker present. This backend's
# response carries a Content-Length and the client (curl, default) wants
# keep-alive, so as of the 1a connection-pool work Connection is
# "keep-alive" here, not the M2-era hardcoded "close" -- see the
# keep-alive/no-Content-Length cases further down for both directions.
proxy_headers=$(curl --fail --silent --dump-header - --output /dev/null \
  "http://127.0.0.1:$port/proxy/hello.txt")
test "$(printf '%s' "$proxy_headers" | grep -ic '^Connection:')" = 1
printf '%s' "$proxy_headers" | grep -qi '^Connection: keep-alive'
printf '%s' "$proxy_headers" | grep -qi '^X-Magnus-Via: magnus-proxy/0.1'

# M2: large body relayed through the bounded proxy buffer across multiple
# recv/flush cycles must be byte-for-byte identical to a direct fetch.
head -c 2000000 /dev/urandom >"$web_root/big.bin"
direct_sha=$(curl --fail --silent "http://127.0.0.1:$upstream_port/big.bin" \
  | sha256sum | cut -d' ' -f1)
proxy_sha=$(curl --fail --silent "http://127.0.0.1:$port/proxy/big.bin" \
  | sha256sum | cut -d' ' -f1)
test "$proxy_sha" = "$direct_sha"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
grep -q 'magnus: stopped' "$log"
grep -Eq 'access request_id=[0-9a-f]{32} method=GET target=/hello.txt status=200' "$log"

# M2: connect() failure surfaces as a clean 502, not a dropped connection.
port_502=$((port + 3))
upstream_502=$((port + 4))
"$binary" --port "$port_502" --root "$web_root" \
  --upstream "127.0.0.1:$upstream_502" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_502/healthz" >/dev/null && break
  sleep 1
done
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_502/proxy/hello.txt")" = 502
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# M2: an upstream that accepts but never answers surfaces as 504 once the
# proxy read timeout elapses, instead of hanging the connection forever.
port_504=$((port + 5))
upstream_504=$((port + 6))
python3 -c "
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $upstream_504))
s.listen(1)
while True:
    conn, _ = s.accept()
    time.sleep(30)
    conn.close()
" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  python3 -c "import socket; socket.create_connection(('127.0.0.1', $upstream_504), timeout=1).close()" \
    >/dev/null 2>&1 && break
  sleep 1
done
"$binary" --port "$port_504" --root "$web_root" \
  --upstream "127.0.0.1:$upstream_504" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_504/healthz" >/dev/null && break
  sleep 1
done
test "$(curl --silent --max-time 15 --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_504/proxy/hello.txt")" = 504
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# M3: multi-endpoint cluster -- smooth weighted round-robin (equal weight 1)
# alternates strictly between two live endpoints, so two requests are enough
# to prove both are actually reachable through the cluster, not just the
# first one configured.
mkdir -p "$web_root/cluster-a" "$web_root/cluster-b"
printf '%s\n' 'endpoint-a' >"$web_root/cluster-a/id.txt"
printf '%s\n' 'endpoint-b' >"$web_root/cluster-b/id.txt"
upstream_a=$((port + 7))
upstream_b=$((port + 8))
python3 -m http.server "$upstream_a" --bind 127.0.0.1 \
  --directory "$web_root/cluster-a" >/dev/null 2>&1 &
backend_pid=$!
python3 -m http.server "$upstream_b" --bind 127.0.0.1 \
  --directory "$web_root/cluster-b" >/dev/null 2>&1 &
backend2_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_a/id.txt" >/dev/null \
    && curl --fail --silent "http://127.0.0.1:$upstream_b/id.txt" >/dev/null \
    && break
  sleep 1
done
port_cluster=$((port + 9))
"$binary" --port "$port_cluster" --root "$web_root/cluster-a" \
  --upstream "127.0.0.1:$upstream_a" --upstream "127.0.0.1:$upstream_b" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_cluster/healthz" >/dev/null && break
  sleep 1
done
curl --fail --silent "http://127.0.0.1:$port_cluster/metrics" \
  | grep -Eq '^magnus_upstream_endpoints_total 2$'
first_endpoint=$(curl --fail --silent "http://127.0.0.1:$port_cluster/proxy/id.txt")
second_endpoint=$(curl --fail --silent "http://127.0.0.1:$port_cluster/proxy/id.txt")
test "$first_endpoint" != "$second_endpoint"
case "$first_endpoint" in endpoint-a|endpoint-b) : ;; *) exit 1 ;; esac
case "$second_endpoint" in endpoint-a|endpoint-b) : ;; *) exit 1 ;; esac
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# M3: retry budget -- the first endpoint refuses every connection, so a
# request must transparently retry against the second (live) endpoint and
# still complete successfully instead of surfacing 502.
port_retry=$((port + 10))
dead_upstream=$((port + 11))
"$binary" --port "$port_retry" --root "$web_root/cluster-a" \
  --upstream "127.0.0.1:$dead_upstream" --upstream "127.0.0.1:$upstream_a" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_retry/healthz" >/dev/null && break
  sleep 1
done
retried_ok=0
for attempt in 1 2 3 4; do
  code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "http://127.0.0.1:$port_retry/proxy/id.txt")
  test "$code" = 200 && retried_ok=$((retried_ok + 1))
done
test "$retried_ok" -ge 1
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
kill -TERM "$backend2_pid"
wait "$backend2_pid" 2>/dev/null || true
backend2_pid=

# M3: active health check finds a dead endpoint, and recovers it, purely in
# the background -- no proxy traffic is sent at all during this block, so
# only the periodic probe (independent of live requests) can move the
# metric.
port_health=$((port + 12))
probe_upstream=$((port + 13))
"$binary" --port "$port_health" --root "$web_root/cluster-a" \
  --upstream "127.0.0.1:$probe_upstream" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_health/healthz" >/dev/null && break
  sleep 1
done
# three consecutive failed probes (~5s apart, failure_threshold=3) are
# needed before the shared passive/active health state flips unhealthy --
# give it comfortable margin over the ~11-15s that takes.
unhealthy_seen=0
for attempt in $(seq 1 18); do
  sleep 1
  if curl --fail --silent "http://127.0.0.1:$port_health/metrics" \
      | grep -Eq '^magnus_upstream_endpoints_healthy 0$'; then
    unhealthy_seen=1
    break
  fi
done
test "$unhealthy_seen" = 1

python3 -m http.server "$probe_upstream" --bind 127.0.0.1 \
  --directory "$web_root/cluster-a" >/dev/null 2>&1 &
backend_pid=$!
recovered=0
for attempt in $(seq 1 10); do
  sleep 1
  if curl --fail --silent "http://127.0.0.1:$port_health/metrics" \
      | grep -Eq '^magnus_upstream_endpoints_healthy 1$'; then
    recovered=1
    break
  fi
done
test "$recovered" = 1
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# M4: cookie-based session affinity -- a client with no MAGNUS_AFFINITY
# cookie gets round-robined and issued one; presenting that cookie back
# keeps every subsequent request on the same endpoint.
python3 -m http.server "$upstream_a" --bind 127.0.0.1 \
  --directory "$web_root/cluster-a" >/dev/null 2>&1 &
backend_pid=$!
python3 -m http.server "$upstream_b" --bind 127.0.0.1 \
  --directory "$web_root/cluster-b" >/dev/null 2>&1 &
backend2_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_a/id.txt" >/dev/null \
    && curl --fail --silent "http://127.0.0.1:$upstream_b/id.txt" >/dev/null \
    && break
  sleep 1
done
port_affinity=$((port + 14))
"$binary" --port "$port_affinity" --root "$web_root/cluster-a" \
  --upstream "127.0.0.1:$upstream_a" --upstream "127.0.0.1:$upstream_b" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_affinity/healthz" >/dev/null \
    && break
  sleep 1
done

jar=$(mktemp)
sticky_endpoint=$(curl --fail --silent --cookie-jar "$jar" \
  "http://127.0.0.1:$port_affinity/proxy/id.txt")
grep -qi 'MAGNUS_AFFINITY' "$jar"
for attempt in 1 2 3; do
  test "$(curl --fail --silent --cookie "$jar" \
    "http://127.0.0.1:$port_affinity/proxy/id.txt")" = "$sticky_endpoint"
done

# M4: affinity + circuit breaker together -- once the sticky endpoint's
# backend is gone, the very same cookie must fail over to the surviving
# endpoint (via the connect-stage retry budget) instead of the request
# failing, and the response must issue a refreshed cookie for it.
if [ "$sticky_endpoint" = "endpoint-a" ]; then
  kill -TERM "$backend_pid"
  wait "$backend_pid" 2>/dev/null || true
  backend_pid=
  expect_after=endpoint-b
else
  kill -TERM "$backend2_pid"
  wait "$backend2_pid" 2>/dev/null || true
  backend2_pid=
  expect_after=endpoint-a
fi
failover_body_file=$(mktemp)
failover_headers=$(curl --fail --silent --cookie "$jar" --dump-header - \
  --output "$failover_body_file" \
  "http://127.0.0.1:$port_affinity/proxy/id.txt")
test "$(cat "$failover_body_file")" = "$expect_after"
printf '%s' "$failover_headers" | grep -qi '^Set-Cookie: MAGNUS_AFFINITY='
rm -f "$failover_body_file" "$jar"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
if [ -n "${backend_pid:-}" ]; then
  kill -TERM "$backend_pid"
  wait "$backend_pid" 2>/dev/null || true
  backend_pid=
fi
if [ -n "${backend2_pid:-}" ]; then
  kill -TERM "$backend2_pid"
  wait "$backend2_pid" 2>/dev/null || true
  backend2_pid=
fi

# M4: per-client-IP ingress rate limiting -- a burst above the configured
# rate is rejected with 429 and recovers once tokens refill.
port_rl=$((port + 15))
"$binary" --port "$port_rl" --root "$web_root" --rate-limit 0.5:2 \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_rl/healthz" >/dev/null && break
  sleep 1
done
# /healthz is exempt from rate limiting, so the full burst of 2 is still
# available: the first two requests succeed and the third is rejected.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_rl/hello.txt")" = 200
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_rl/hello.txt")" = 200
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_rl/hello.txt")" = 429
curl --fail --silent "http://127.0.0.1:$port_rl/metrics" \
  | grep -Eq '^magnus_rate_limited_total [1-9][0-9]*$'
sleep 3
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_rl/hello.txt")" = 200
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# M6: admin channel isolation -- /metrics is withdrawn from the main (TCP)
# listener once --admin-socket is configured, but /healthz stays; the
# Unix socket serves /metrics (with the latency histogram) but rejects
# anything else, and is created with owner-only permissions.
port_admin=$((port + 16))
admin_socket="$web_root/admin.sock"
"$binary" --port "$port_admin" --root "$web_root" \
  --admin-socket "$admin_socket" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_admin/healthz" >/dev/null \
    && break
  sleep 1
done
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_admin/metrics")" = 404
test "$(curl --fail --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_admin/healthz")" = 200
test "$(curl --unix-socket "$admin_socket" --silent --output /dev/null \
  --write-out '%{http_code}' http://localhost/metrics)" = 200
curl --unix-socket "$admin_socket" --fail --silent http://localhost/metrics \
  | grep -q '^magnus_request_duration_milliseconds_bucket{le="1"}'
test "$(curl --unix-socket "$admin_socket" --silent --output /dev/null \
  --write-out '%{http_code}' http://localhost/hello.txt)" = 404
stat -c '%a' "$admin_socket" | grep -q '^700$'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# M6: access log off and 1-in-N sampling.
port_noaccess=$((port + 17))
"$binary" --port "$port_noaccess" --root "$web_root" --access-log off \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_noaccess/healthz" >/dev/null \
    && break
  sleep 1
done
before_lines=$(wc -l < "$log")
curl --fail --silent -o /dev/null "http://127.0.0.1:$port_noaccess/hello.txt"
curl --fail --silent -o /dev/null "http://127.0.0.1:$port_noaccess/hello.txt"
sleep 2
after_lines=$(wc -l < "$log")
test "$before_lines" = "$after_lines"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

port_sample=$((port + 18))
sample_log=$(mktemp)
"$binary" --port "$port_sample" --root "$web_root" --access-log-sample 3 \
  2>"$sample_log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_sample/healthz" >/dev/null \
    && break
  sleep 1
done
for attempt in 1 2 3 4 5 6; do
  curl --fail --silent -o /dev/null "http://127.0.0.1:$port_sample/hello.txt"
done
sleep 2
test "$(grep -c '^access ' "$sample_log")" = 2
rm -f "$sample_log"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# M6: slowloris -- a client that trickles request bytes one at a time,
# never idling long enough to trip MAGNUS_IDLE_SECONDS, must still be cut
# off by the header-phase deadline instead of holding the connection (and
# its fd) open indefinitely.
port_slow=$((port + 19))
"$binary" --port "$port_slow" --root "$web_root" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_slow/healthz" >/dev/null \
    && break
  sleep 1
done
slowloris_start=$(date +%s)
python3 -c "
import socket, time
s = socket.create_connection(('127.0.0.1', $port_slow), timeout=15)
line = b'GET /hello.txt HTTP/1.1\r\n'
for byte in line:
    s.send(bytes([byte]))
    time.sleep(0.3)
try:
    s.settimeout(15)
    remaining = s.recv(4096)
except socket.timeout:
    remaining = b''
s.close()
import sys
sys.stdout.write(remaining.decode('latin1'))
" > "$web_root/slowloris-response.txt" 2>&1 || true
slowloris_elapsed=$(( $(date +%s) - slowloris_start ))
# the connection must have been closed (headers never completed) well
# under the 30s idle timeout, proving the header-phase deadline -- not
# idle expiry -- is what ended it.
test "$slowloris_elapsed" -lt 20
test ! -s "$web_root/slowloris-response.txt"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# M6: malformed request handling -- raw garbage bytes over the wire (never
# something curl itself would ever construct) must not crash the server,
# and it must keep serving legitimate requests afterward.
port_malformed=$((port + 20))
"$binary" --port "$port_malformed" --root "$web_root" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_malformed/healthz" >/dev/null \
    && break
  sleep 1
done
python3 -c "
import socket
payloads = [
    bytes(range(256)) * 4,
    b'GET ' + b'A' * 5000 + b' HTTP/1.1\r\n\r\n',
    b'GET / HTTP/9.9\r\n\r\n',
    b'\r\n\r\n\r\n\r\n',
    b'not even close to http',
    b'GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n',
    b'G\x00T / HTTP/1.1\r\nHost: a\r\n\r\n',
]
for payload in payloads:
    s = socket.create_connection(('127.0.0.1', $port_malformed), timeout=5)
    s.sendall(payload)
    try:
        s.settimeout(2)
        s.recv(4096)
    except socket.timeout:
        pass
    s.close()
print('sent', len(payloads), 'malformed payloads')
"
test "$(curl --fail --silent "http://127.0.0.1:$port_malformed/healthz")" \
  = 'magnus: ok'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
grep -q 'magnus: stopped' "$log"

# M6: fd exhaustion -- under a tight per-process fd limit, magnus must
# keep running (not crash) and recover once connections close, even
# though it cannot accept everything while the limit is being hit.
port_fdlimit=$((port + 21))
(
  ulimit -n 40
  exec "$binary" --port "$port_fdlimit" --root "$web_root"
) 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_fdlimit/healthz" >/dev/null \
    && break
  sleep 1
done
python3 -c "
import socket
socks = []
try:
    for _ in range(80):
        s = socket.create_connection(('127.0.0.1', $port_fdlimit), timeout=2)
        socks.append(s)
except OSError:
    pass
print('opened', len(socks), 'connections under fd pressure')
for s in socks:
    s.close()
"
sleep 1
test "$(curl --fail --silent "http://127.0.0.1:$port_fdlimit/healthz")" \
  = 'magnus: ok'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

tls_port=$((port + 1))
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/server.key" -out "$web_root/server.crt" >/dev/null 2>&1
"$binary" --port "$tls_port" --root "$web_root" \
  --tls-cert "$web_root/server.crt" --tls-key "$web_root/server.key" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --tlsv1.3 --insecure --fail --silent \
    "https://127.0.0.1:$tls_port/healthz" >/dev/null && break
  sleep 1
done
test "$(curl --tls-max 1.2 --tlsv1.2 --insecure --fail --silent \
  "https://127.0.0.1:$tls_port/hello.txt")" = 'magnus static file'
if curl --tls-max 1.1 --insecure --silent \
  "https://127.0.0.1:$tls_port/healthz" >/dev/null 2>&1; then
  exit 1
fi
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Request bodies through the proxy: /proxy/* must relay any method (not
# just GET/HEAD) and forward the client's body to the upstream intact,
# while every other route stays GET/HEAD-only exactly as before. A plain
# http.server backend 501s on POST/PUT, which is only useful for proving a
# method got relayed at all -- a tiny echo backend is needed to also prove
# the body bytes themselves arrived correctly.
port_body=$((port + 22))
upstream_echo=$((port + 23))
python3 -c "
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b''
        payload = ('method=' + self.command + ' path=' + self.path
                   + ' len=' + str(len(body)) + ' body='
                   + body.decode('utf-8', 'replace')).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle
    def log_message(self, *a): pass

http.server.HTTPServer(('127.0.0.1', $upstream_echo), Handler).serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_echo/ping" >/dev/null && break
  sleep 1
done
"$binary" --port "$port_body" --root "$web_root" \
  --upstream "127.0.0.1:$upstream_echo" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_body/healthz" >/dev/null && break
  sleep 1
done

test "$(curl --fail --silent --request POST --data 'hello=world' \
  "http://127.0.0.1:$port_body/proxy/echo")" \
  = 'method=POST path=/echo len=11 body=hello=world'
test "$(curl --fail --silent --request PUT --data '{"a":1}' \
  "http://127.0.0.1:$port_body/proxy/thing/1")" \
  = 'method=PUT path=/thing/1 len=7 body={"a":1}'
test "$(curl --fail --silent --request DELETE \
  "http://127.0.0.1:$port_body/proxy/thing/1")" \
  = 'method=DELETE path=/thing/1 len=0 body='

# A body split across many reads (larger than one TCP segment/the header
# buffer) must still arrive byte-for-byte intact. The echoed response is
# "<prefix>body=<the body verbatim>" and the body itself is multi-line
# (base64-wrapped), so extraction has to be byte-offset based (tail -c),
# not sed/grep, which only ever match within a single line.
head -c 500000 /dev/urandom | base64 >"$web_root/large_body.txt"
large_len=$(wc -c <"$web_root/large_body.txt")
large_sha=$(sha256sum "$web_root/large_body.txt" | cut -d' ' -f1)
echo_prefix="method=POST path=/big len=$large_len body="
prefix_len=$(printf '%s' "$echo_prefix" | wc -c)
relayed_sha=$(curl --fail --silent --request POST \
  --data-binary "@$web_root/large_body.txt" \
  "http://127.0.0.1:$port_body/proxy/big" \
  | tail -c "+$((prefix_len + 1))" | sha256sum | cut -d' ' -f1)
test "$relayed_sha" = "$large_sha"

# A body over the 1MiB cap is rejected before it is ever forwarded.
head -c 1500000 /dev/urandom | base64 >"$web_root/huge_body.txt"
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST --data-binary "@$web_root/huge_body.txt" \
  "http://127.0.0.1:$port_body/proxy/huge")" = 413

# Transfer-Encoding (chunked or otherwise) is rejected outright -- not yet
# supported, and silently mishandling it would be a framing hazard.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST --header 'Transfer-Encoding: chunked' --data hello \
  "http://127.0.0.1:$port_body/proxy/chunked")" = 400

# Everything that is not /proxy/* is still GET/HEAD-only.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST --data 'x=1' "http://127.0.0.1:$port_body/hello.txt")" = 405

# Multiple body-bearing requests, plus a bodyless one, chained over one
# reused connection must each be framed correctly -- no request's body
# bleeding into the next request's headers.
chained=$(curl --fail --silent \
  --request POST --data 'first=1' "http://127.0.0.1:$port_body/proxy/a" \
  --next \
  --request POST --data 'second=22' "http://127.0.0.1:$port_body/proxy/b" \
  --next \
  "http://127.0.0.1:$port_body/proxy/c" \
  --next \
  --request POST --data 'fourth=4444' "http://127.0.0.1:$port_body/proxy/d")
test "$chained" = 'method=POST path=/a len=7 body=first=1method=POST path=/b len=9 body=second=22method=GET path=/c len=0 body=method=POST path=/d len=11 body=fourth=4444'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# Upstream connection pool (1a): a backend that reports which specific
# TCP connection (by identity, assigned once per accept) each request
# arrived on, fronted by a Content-Length-only response so both legs
# qualify for reuse. Deliberately *not* a running "connections accepted so
# far" counter compared for equality across requests -- magnus's own
# active health checker (independent of anything under test here) opens
# its own periodic probe connections to this same backend in the
# background, which would otherwise intermix with and inflate any such
# counter. Comparing *which* id a request landed on, rather than counting
# how many accepts happened in between, is immune to that: a health probe
# consumes an id that simply never appears in any of these responses.
port_pool=$((port + 24))
upstream_pool=$((port + 25))
python3 -c "
import http.server, threading

lock = threading.Lock()
next_id = [0]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        super().setup()
        with lock:
            next_id[0] += 1
            self.conn_id = next_id[0]
    def do_GET(self):
        payload = ('id=' + str(self.conn_id)).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(('127.0.0.1', $upstream_pool), Handler).serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
sleep 1
# --config, not plain flags: SIGHUP reload is a documented no-op in plain
# --port/--root/... mode (nothing to reload from), and the pool-flush
# check below needs a reload that actually happens.
pool_config="$web_root/pool.conf"
printf 'port = %s\nroot = %s\nupstream = 127.0.0.1:%s:1\n' \
  "$port_pool" "$web_root" "$upstream_pool" > "$pool_config"
"$binary" --config "$pool_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_pool/healthz" >/dev/null && break
  sleep 1
done

# Content-Length known, client wants keep-alive (curl's default) -> both
# legs get to stay open, matching magnus_proxy_response_info_t's contract.
# This is also the pool's first real request, establishing the baseline
# connection id.
headers=$(curl --fail --silent --dump-header - --output /dev/null \
  "http://127.0.0.1:$port_pool/proxy/x")
printf '%s' "$headers" | grep -qi '^Connection: keep-alive'
baseline=$(curl --fail --silent "http://127.0.0.1:$port_pool/proxy/x")

# 10 requests over one reused *client* connection must all land on that
# same pooled upstream connection id.
pooled_ten=$(curl --fail --silent \
  "http://127.0.0.1:$port_pool/proxy/x" "http://127.0.0.1:$port_pool/proxy/x" \
  "http://127.0.0.1:$port_pool/proxy/x" "http://127.0.0.1:$port_pool/proxy/x" \
  "http://127.0.0.1:$port_pool/proxy/x" "http://127.0.0.1:$port_pool/proxy/x" \
  "http://127.0.0.1:$port_pool/proxy/x" "http://127.0.0.1:$port_pool/proxy/x" \
  "http://127.0.0.1:$port_pool/proxy/x" "http://127.0.0.1:$port_pool/proxy/x")
test "$(printf '%s' "$pooled_ten" | grep -o 'id=[0-9]*' | sort -u)" = "$baseline"

# A brand-new *client* connection reusing that same pooled *upstream*
# connection id is the actual point of a pool scoped to the endpoint
# rather than to one client connection.
eleventh=$(curl --fail --silent "http://127.0.0.1:$port_pool/proxy/x")
test "$eleventh" = "$baseline"

# MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION (100) retires a connection right
# on schedule. 13 requests have gone through the baseline connection so
# far (the two that set `headers`/`baseline`, the 10-batch, and the
# eleventh); 87 more brings it to exactly 100, so the very next one must
# land on a second, distinct upstream connection id.
for _ in $(seq 1 87); do
  curl --fail --silent "http://127.0.0.1:$port_pool/proxy/x" >/dev/null
done
rollover=$(curl --fail --silent "http://127.0.0.1:$port_pool/proxy/x")
test "$rollover" != "$baseline"

# A config reload must flush the pool: reused connections are indexed by
# endpoint *position*, and a reload does not guarantee position N is still
# the same backend, even against this identical single-upstream config.
kill -HUP "$server_pid"
sleep 0.5
after_reload=$(curl --fail --silent "http://127.0.0.1:$port_pool/proxy/x")
test "$after_reload" != "$baseline" && test "$after_reload" != "$rollover"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# A backend that dies while its connection sits idle in the pool: the next
# request must recover with a clean 502 (dead connection detected at
# checkout, fresh connect attempted, fails since nothing is listening),
# not hang or crash magnus itself.
port_pooldead=$((port + 26))
upstream_pooldead=$((port + 27))
python3 -m http.server "$upstream_pooldead" --bind 127.0.0.1 \
  --directory "$web_root" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_pooldead/hello.txt" >/dev/null \
    && break
  sleep 1
done
"$binary" --port "$port_pooldead" --root "$web_root" \
  --upstream "127.0.0.1:$upstream_pooldead" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_pooldead/healthz" >/dev/null && break
  sleep 1
done
test "$(curl --fail --silent "http://127.0.0.1:$port_pooldead/proxy/hello.txt")" \
  = 'magnus static file'
kill -KILL "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
sleep 0.5
test "$(curl --silent --max-time 5 --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_pooldead/proxy/hello.txt")" = 502
test "$(curl --fail --silent "http://127.0.0.1:$port_pooldead/healthz")" = 'magnus: ok'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Advanced routing (1b): host/path_prefix/header/source_cidr conditions,
# each combined with an action. A route with action=proxy forwards the
# request's *full* path (not the literal-"/proxy"-prefix-stripped one the
# hardcoded /proxy/* dispatch uses -- routes are not anchored to that
# prefix, so there is nothing to strip), a deny match short-circuits to
# 403 ahead of everything else, and neither disturbs a request that
# matches no route at all, including the pre-existing literal /proxy/*
# dispatch.
port_route=$((port + 28))
upstream_route=$((port + 29))
python3 -c "
import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = ('backend saw path=' + self.path).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', $upstream_route), Handler).serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
sleep 1
route_config="$web_root/route.conf"
cat > "$route_config" <<EOF
port = $port_route
root = $web_root
upstream = 127.0.0.1:$upstream_route:1
route = host=api.internal; path_prefix=/v1; action=proxy
route = header:X-Blocked=1; action=deny
route = source_cidr=127.0.0.0/8; path_prefix=/blocked-by-cidr; action=deny
EOF
"$binary" --config "$route_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_route/healthz" >/dev/null && break
  sleep 1
done

# host+path_prefix match -> proxy, full path forwarded unchanged.
test "$(curl --fail --silent --header 'Host: api.internal' \
  "http://127.0.0.1:$port_route/v1/widgets")" \
  = 'backend saw path=/v1/widgets'

# Same path, non-matching Host -> no route matches, falls through to the
# ordinary (here, 404 -- ordinary static dispatch, no such file) path.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'Host: other.internal' "http://127.0.0.1:$port_route/v1/widgets")" \
  = 404

# header: condition -> deny short-circuits to 403.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'X-Blocked: 1' "http://127.0.0.1:$port_route/hello.txt")" = 403
# Without the header, the very same request is unaffected.
test "$(curl --fail --silent "http://127.0.0.1:$port_route/hello.txt")" \
  = 'magnus static file'

# source_cidr matches real loopback traffic (127.0.0.1/8) on the
# path_prefix-gated path -> denied; the same CIDR condition does not fire
# outside that path_prefix, so unrelated requests are unaffected.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_route/blocked-by-cidr/x")" = 403
test "$(curl --fail --silent "http://127.0.0.1:$port_route/hello.txt")" \
  = 'magnus static file'

# The pre-existing literal /proxy/* dispatch is completely unaffected by
# any of the above: still strips the "/proxy" prefix before forwarding.
test "$(curl --fail --silent "http://127.0.0.1:$port_route/proxy/x")" \
  = 'backend saw path=/x'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# DNS-resolved upstream (1c): "localhost" instead of a literal IP, in
# both --config mode and plain --upstream CLI-flag mode, actually
# resolves asynchronously and proxies successfully -- not just accepted
# by config parsing. A config reload re-resolves and keeps working. An
# upstream hostname that cannot resolve at all fails proxy attempts
# cleanly (502), not a hang or crash, and does not stop magnus itself
# from staying healthy.
port_dns=$((port + 30))
upstream_dns=$((port + 31))
printf '%s\n' 'dns-resolved backend' >"$web_root/dns-backend.txt"
python3 -m http.server "$upstream_dns" --bind 127.0.0.1 \
  --directory "$web_root" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_dns/dns-backend.txt" \
    >/dev/null && break
  sleep 1
done
dns_config="$web_root/dns.conf"
cat > "$dns_config" <<EOF
port = $port_dns
root = $web_root
upstream = localhost:$upstream_dns:1
EOF
"$binary" --config "$dns_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_dns/healthz" >/dev/null && break
  sleep 1
done
resolved=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  test "$(curl --silent "http://127.0.0.1:$port_dns/proxy/dns-backend.txt")" \
    = 'dns-resolved backend' && resolved=1 && break
  sleep 1
done
test "$resolved" = 1
curl --fail --silent "http://127.0.0.1:$port_dns/metrics" \
  | grep -Eq '^magnus_upstream_healthy\{endpoint="127\.0\.0\.1:'"$upstream_dns"'"\} 1$'

# Reload re-resolves (a fresh cluster after reload starts unresolved
# again -- see magnus_dns_apply_upstreams()) and keeps working.
kill -HUP "$server_pid"
sleep 1
test "$(curl --fail --silent "http://127.0.0.1:$port_dns/proxy/dns-backend.txt")" \
  = 'dns-resolved backend'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# A hostname that cannot resolve at all: proxy attempts fail cleanly, and
# magnus itself is unaffected.
port_dnsbad=$((port + 32))
bad_config="$web_root/dns-bad.conf"
cat > "$bad_config" <<EOF
port = $port_dnsbad
root = $web_root
upstream = this-name-should-not-resolve.invalid:1:1
EOF
"$binary" --config "$bad_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_dnsbad/healthz" >/dev/null && break
  sleep 1
done
sleep 1
test "$(curl --silent --max-time 5 --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:$port_dnsbad/proxy/dns-backend.txt")" = 502
test "$(curl --fail --silent "http://127.0.0.1:$port_dnsbad/healthz")" = 'magnus: ok'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# CLI --upstream also accepts and resolves a hostname, not just --config.
port_dnscli=$((port + 33))
upstream_dnscli=$((port + 34))
python3 -m http.server "$upstream_dnscli" --bind 127.0.0.1 \
  --directory "$web_root" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_dnscli/dns-backend.txt" \
    >/dev/null && break
  sleep 1
done
"$binary" --port "$port_dnscli" --root "$web_root" \
  --upstream "localhost:$upstream_dnscli:1" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_dnscli/healthz" >/dev/null && break
  sleep 1
done
resolved=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  test "$(curl --silent "http://127.0.0.1:$port_dnscli/proxy/dns-backend.txt")" \
    = 'dns-resolved backend' && resolved=1 && break
  sleep 1
done
test "$resolved" = 1
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# WebSocket (1d): a plain-stdlib (no extra dependency, unlike a real
# WebSocket client library) raw-socket backend and client -- the backend
# computes a real Sec-WebSocket-Accept from the actual request's key and
# then echoes whatever raw bytes arrive after the handshake, so this
# verifies both that the handshake relay is byte-exact in each direction
# (a wrong Accept value would mean magnus corrupted or recomputed
# something it must only relay) and that the post-handshake connection is
# a correct raw bidirectional pipe, including a payload well over one
# relay buffer's worth (MAGNUS_PROXY_BUFFER, 16 KiB) to exercise the
# multi-chunk path, not just a single small echo.
port_ws=$((port + 35))
upstream_ws=$((port + 36))
python3 -c "
import socket, hashlib, base64

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', $upstream_ws))
srv.listen(5)
while True:
    conn, _ = srv.accept()
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    header_text = data.split(b'\r\n\r\n', 1)[0].decode()
    key = ''
    for line in header_text.split('\r\n')[1:]:
        if line.lower().startswith('sec-websocket-key:'):
            key = line.split(':', 1)[1].strip()
    accept = base64.b64encode(
        hashlib.sha1((key + GUID).encode()).digest()).decode()
    conn.sendall((
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Accept: ' + accept + '\r\n'
        '\r\n'
    ).encode())
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        conn.sendall(chunk)
    conn.close()
" >/dev/null 2>&1 &
backend_pid=$!
sleep 1
ws_config="$web_root/ws.conf"
cat > "$ws_config" <<EOF
port = $port_ws
root = $web_root
upstream = 127.0.0.1:$upstream_ws:1
EOF
"$binary" --config "$ws_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_ws/healthz" >/dev/null && break
  sleep 1
done

python3 -c "
import socket, base64, os, hashlib

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
key = base64.b64encode(os.urandom(16)).decode()
req = (
    'GET /proxy/echo HTTP/1.1\r\n'
    'Host: example\r\n'
    'Upgrade: websocket\r\n'
    'Connection: Upgrade\r\n'
    'Sec-WebSocket-Key: ' + key + '\r\n'
    'Sec-WebSocket-Version: 13\r\n'
    '\r\n'
)
s = socket.create_connection(('127.0.0.1', $port_ws), timeout=5)
s.sendall(req.encode())
s.settimeout(5)
resp = b''
while b'\r\n\r\n' not in resp:
    resp += s.recv(4096)
header_text = resp.split(b'\r\n\r\n', 1)[0]
assert header_text.startswith(b'HTTP/1.1 101'), header_text
expected_accept = base64.b64encode(
    hashlib.sha1((key + GUID).encode()).digest()).decode()
assert ('Sec-WebSocket-Accept: ' + expected_accept).encode() in header_text, (
    'Sec-WebSocket-Accept mismatch -- handshake was not relayed byte-exact')

def echo_check(payload, chunk_size):
    s.sendall(payload)
    received = b''
    while len(received) < len(payload):
        chunk = s.recv(chunk_size)
        if not chunk:
            raise AssertionError('connection closed early')
        received += chunk
    assert received == payload, 'echo mismatch for %d-byte payload' % len(payload)

echo_check(os.urandom(1000), 4096)
echo_check(os.urandom(50000), 65536)  # over one MAGNUS_PROXY_BUFFER (16 KiB)
s.close()
print('ws ok')
"

# Non-WebSocket traffic through the very same magnus instance -- proxying
# a WebSocket upgrade must not disturb ordinary proxied requests.
printf '%s\n' 'still ordinary' >"$web_root/still-ordinary.txt"
test "$(curl --fail --silent "http://127.0.0.1:$port_ws/still-ordinary.txt")" \
  = 'still ordinary'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# HTTP/2 (1e-1): ALPN-negotiated "h2", static files only -- curl is real,
# independent tooling here exactly like the `websockets` PyPI client was
# for 1d, not code that shares any implementation with magnus itself.
# Exercises: ALPN actually lands on h2 (curl reports http_version 2, not
# 1.1), a small file, a file well over one MAGNUS_PROXY_BUFFER-worth
# (exercises the pread()-chunked data-provider path across several
# read-callback invocations, not just a single one), byte-exact bodies,
# HEAD (no body, correct Content-Length still), 404 for a missing file, a
# client that never offers h2 at all still gets ordinary HTTP/1.1 (ALPN is
# additive, not a mode switch on the listener), and that concurrent
# streams multiplexed over one connection all come back correct --
# proving real stream-id bookkeeping, not just "one request at a time
# happens to work".
port_h2=$((port + 37))
h2_web_root="$web_root/h2"
mkdir -p "$h2_web_root"
printf '%s\n' 'magnus h2 static file' >"$h2_web_root/hello.txt"
head -c 50000 /dev/urandom | base64 >"$h2_web_root/large.txt"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/h2-server.key" -out "$web_root/h2-server.crt" \
  >/dev/null 2>&1
"$binary" --port "$port_h2" --root "$h2_web_root" \
  --tls-cert "$web_root/h2-server.crt" --tls-key "$web_root/h2-server.key" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2 --insecure --fail --silent \
    "https://127.0.0.1:$port_h2/healthz" >/dev/null && break
  sleep 1
done

version=$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_version}' "https://127.0.0.1:$port_h2/hello.txt")
test "$version" = '2'
test "$(curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2/hello.txt")" = 'magnus h2 static file'
diff <(curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2/large.txt") "$h2_web_root/large.txt"

head_status=$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' --head "https://127.0.0.1:$port_h2/hello.txt")
test "$head_status" = '200'
head_length=$(curl --http2 --insecure --silent --head \
  "https://127.0.0.1:$port_h2/hello.txt" | tr -d '\r' \
  | sed -n 's/^content-length: //ip')
test "$head_length" = '22'

not_found=$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2/missing.txt")
test "$not_found" = '404'

# ALPN is additive, not a mode switch: a client that never offers h2 at
# all is served ordinary HTTP/1.1 exactly as before this phase existed.
version_h1=$(curl --http1.1 --insecure --silent --output /dev/null \
  --write-out '%{http_version}' "https://127.0.0.1:$port_h2/hello.txt")
test "$version_h1" = '1.1'

# Real multiplexing: several requests over one h2 connection, all
# correct -- not just one request happening to round-trip. curl only
# honors --output/--write-out for the *first* URL of a multi-URL command
# line unless each subsequent URL is separated with --next, so that is
# used here rather than three bare URLs (which would otherwise dump the
# 2nd/3rd bodies to stdout ahead of their %{http_code} lines).
mapfile -t multi_status < <(curl --http2 --insecure --silent \
  --output /dev/null --write-out '%{http_code}\n' \
  "https://127.0.0.1:$port_h2/hello.txt" \
  --next --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}\n' "https://127.0.0.1:$port_h2/large.txt" \
  --next --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}\n' "https://127.0.0.1:$port_h2/hello.txt")
test "${#multi_status[@]}" = 3
for status in "${multi_status[@]}"; do test "$status" = '200'; done

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# HTTP/2 proxy dispatch + H2<->H1 upstream translation (1e-2): an h2
# stream matched to a proxy route is relayed to an ordinary HTTP/1.1
# upstream and the response translated back into h2 response headers +
# DATA frames. The backend below is the same connection-identity-
# tracking shape as the 1a pool test above (id assigned once per
# accept()), reused here for the same reason: it lets "did this land on
# the pooled connection" be checked by *which* id came back rather than
# a running accept count, immune to magnus's own background health
# probes hitting the same backend. Exercises: GET and a POST with a body
# (crossing multiple relay-buffer chunks) both proxy correctly and reuse
# one pooled upstream connection across many h2 streams -- including
# genuinely concurrent ones, proving this is real per-stream upstream
# state, not serialized under the hood; HEAD; an action=deny route still
# denies over h2; a request body over MAGNUS_MAX_BODY (1 MiB) still 413s
# instead of hanging or crashing; ordinary (non-proxy) h2 static-file
# serving keeps working on the same connection a proxy route also
# matches on.
port_h2proxy=$((port + 40))
upstream_h2proxy=$((port + 41))
python3 -c "
import http.server, threading, json

lock = threading.Lock()
next_id = [0]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        super().setup()
        with lock:
            next_id[0] += 1
            self.conn_id = next_id[0]
    def _handle(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length > 0 else b''
        payload = json.dumps({'method': self.command, 'path': self.path,
            'body_len': len(body), 'conn_id': self.conn_id}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(payload)
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_HEAD(self): self._handle()
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(('127.0.0.1', $upstream_h2proxy), Handler).serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
sleep 1
h2proxy_root="$web_root/h2proxy"
mkdir -p "$h2proxy_root"
printf '%s\n' 'still static' >"$h2proxy_root/still-static.txt"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/h2proxy-server.key" -out "$web_root/h2proxy-server.crt" \
  >/dev/null 2>&1
h2proxy_config="$web_root/h2proxy.conf"
cat > "$h2proxy_config" <<EOF
port = $port_h2proxy
root = $h2proxy_root
tls_cert = $web_root/h2proxy-server.crt
tls_key = $web_root/h2proxy-server.key
upstream = 127.0.0.1:$upstream_h2proxy:1
route = path_prefix=/blocked; action=deny
route = path_prefix=/api; action=proxy
EOF
"$binary" --config "$h2proxy_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2 --insecure --fail --silent \
    "https://127.0.0.1:$port_h2proxy/healthz" >/dev/null && break
  sleep 1
done

get_body=$(curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2proxy/api/foo?x=1")
printf '%s' "$get_body" | grep -q '"method": "GET"'
printf '%s' "$get_body" | grep -q '"path": "/api/foo?x=1"'
baseline_conn=$(printf '%s' "$get_body" \
  | sed -n 's/.*"conn_id": \([0-9]*\).*/\1/p')

post_payload=$(head -c 90000 /dev/urandom | base64)
post_payload_length=$(printf '%s' "$post_payload" | wc -c)
post_body=$(curl --http2 --insecure --fail --silent -X POST \
  --data-binary "$post_payload" "https://127.0.0.1:$port_h2proxy/api/echo")
printf '%s' "$post_body" | grep -q '"method": "POST"'
printf '%s' "$post_body" | grep -q "\"body_len\": $post_payload_length"

head_status=$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' --head "https://127.0.0.1:$port_h2proxy/api/foo")
test "$head_status" = '200'

# 15 genuinely concurrent proxy requests (separate h2 connections, same
# magnus instance/backend): every response must be correct (right path
# echoed back to the right request) -- proving real per-request upstream
# state under concurrency, with no cross-request corruption, rather than
# something that only happens to work one request at a time. Not a pool-
# reuse assertion: genuine concurrency beyond however many idle pooled
# connections exist at that instant legitimately opens fresh ones (pool
# reuse itself is already proven above by the sequential GET/POST/HEAD
# baseline requests all landing on the same conn_id).
mux_dir=$(mktemp -d)
mux_pids=()
for i in $(seq 1 15); do
  curl --http2 --insecure --fail --silent \
    "https://127.0.0.1:$port_h2proxy/api/mux$i" \
    -o "$mux_dir/$i.json" &
  mux_pids+=($!)
done
for pid in "${mux_pids[@]}"; do wait "$pid"; done
for i in $(seq 1 15); do
  grep -q "\"path\": \"/api/mux$i\"" "$mux_dir/$i.json"
done
rm -rf "$mux_dir"

# action=deny still denies over h2.
denied_status=$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2proxy/blocked/x")
test "$denied_status" = '403'

# A request body over MAGNUS_MAX_BODY (1 MiB) 413s rather than hanging
# or crashing the connection.
oversized_status=$(head -c 1200000 /dev/urandom | curl --http2 --insecure \
  --silent --output /dev/null --write-out '%{http_code}' -X POST \
  --data-binary @/dev/stdin "https://127.0.0.1:$port_h2proxy/api/big")
test "$oversized_status" = '413'

# Ordinary static-file serving (1e-1) still works on the very same
# connection a proxy route also matches on.
test "$(curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2proxy/still-static.txt")" = 'still static'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# Rapid-Reset-class abuse hardening (1e-3): a raw, stdlib-only (no h2/
# hyperframe pip dependency, matching the 1d WebSocket test's own
# stdlib-first precedent -- curl has no way to emit a bare RST_STREAM or
# skip HPACK, which is exactly what this needs to control directly) h2
# client that hand-encodes just enough of the wire format (the fixed
# connection preface, an empty initial SETTINGS frame, and HPACK's
# plain "literal header field without indexing -- new name"
# representation for a handful of short pseudo-headers, no Huffman or
# dynamic-table indexing needed) to drive real HEADERS/RST_STREAM frames
# at magnus directly. Exercises: a legitimate handful of sequential
# requests is never affected by either cap; a client that opens a
# stream and immediately RST_STREAMs it in a tight loop (the Rapid Reset
# / CVE-2023-44487 shape) gets its connection cut off well before
# reaching MAGNUS_H2_MAX_RESETS_PER_SECOND-many, let alone the full
# attempted count; a client that just opens streams as fast as possible
# (no resets at all) is independently capped by
# MAGNUS_H2_MAX_NEW_STREAMS_PER_SECOND the same way.
port_h2abuse=$((port + 43))
h2abuse_root="$web_root/h2abuse"
mkdir -p "$h2abuse_root"
printf '%s\n' 'h2abuse ok' >"$h2abuse_root/index.html"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/h2abuse-server.key" -out "$web_root/h2abuse-server.crt" \
  >/dev/null 2>&1
"$binary" --port "$port_h2abuse" --root "$h2abuse_root" \
  --tls-cert "$web_root/h2abuse-server.crt" --tls-key "$web_root/h2abuse-server.key" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2 --insecure --fail --silent \
    "https://127.0.0.1:$port_h2abuse/healthz" >/dev/null && break
  sleep 1
done

python3 -c "
import socket, ssl, sys

HOST = '127.0.0.1'
PORT = $port_h2abuse
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

def hpack_string(s):
    assert len(s) < 127
    return bytes([len(s)]) + s

def hpack_literal_new_name(name, value):
    return b'\x00' + hpack_string(name) + hpack_string(value)

def build_headers_block(pairs):
    return b''.join(hpack_literal_new_name(k, v) for k, v in pairs)

def frame(frame_type, flags, stream_id, payload=b''):
    length = len(payload)
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
        frame_type, flags]) + stream_id.to_bytes(4, 'big')
    return header + payload

PAIRS = [(b':method', b'GET'), (b':path', b'/index.html'),
    (b':scheme', b'https'), (b':authority', b'localhost')]

def headers_frame(stream_id, end_stream):
    flags = 0x04 | (0x01 if end_stream else 0)
    return frame(0x1, flags, stream_id, build_headers_block(PAIRS))

def rst_stream_frame(stream_id):
    return frame(0x3, 0, stream_id, (8).to_bytes(4, 'big'))  # CANCEL

def connect():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])
    raw = socket.create_connection((HOST, PORT), timeout=5)
    tls = ctx.wrap_socket(raw, server_hostname='localhost')
    assert tls.selected_alpn_protocol() == 'h2'
    tls.sendall(PREFACE + frame(0x4, 0, 0, b''))  # preface + empty SETTINGS
    return tls

def probe_alive(tls):
    tls.settimeout(1)
    try:
        return tls.recv(4096) != b''
    except OSError:
        return False

def run(mode, count):
    tls = connect()
    stream_id = 1
    sent = 0
    died = False
    for _ in range(count):
        try:
            if mode == 'reset':
                tls.sendall(headers_frame(stream_id, False))
                tls.sendall(rst_stream_frame(stream_id))
            else:
                tls.sendall(headers_frame(stream_id, True))
            sent += 1
            stream_id += 2
        except OSError:
            died = True
            break
    if not died:
        died = not probe_alive(tls)
    tls.close()
    return died, sent

# Legitimate: 10 sequential ordinary requests, each waited out fully --
# neither cap has any effect on traffic this ordinary.
tls = connect()
stream_id = 1
completed = 0
for _ in range(10):
    tls.sendall(headers_frame(stream_id, True))
    tls.settimeout(3)
    try:
        data = tls.recv(65536)
        if data:
            completed += 1
    except OSError:
        pass
    stream_id += 2
tls.close()
assert completed == 10, 'legitimate traffic affected: %d/10 completed' % completed
print('legitimate ok: %d/10' % completed)

died, sent = run('reset', 1000)
assert died, 'rapid-reset attack was not cut off at all'
assert sent < 1000, 'rapid-reset attack sent all 1000 without being cut off'
print('rapid-reset cut off after %d resets' % sent)

died, sent = run('flood', 1000)
assert died, 'new-stream flood was not cut off at all'
assert sent < 1000, 'new-stream flood sent all 1000 without being cut off'
print('stream-flood cut off after %d streams' % sent)
"

# Ordinary h2 traffic through the very same magnus instance, after both
# attack connections above: proves the caps are per-*connection*, not a
# global circuit-breaker that an attacker could use to deny service to
# every other client.
test "$(curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2abuse/index.html")" = 'h2abuse ok'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Graceful GOAWAY on shutdown (1e-3): a still-open h2 connection gets an
# actual GOAWAY frame (type 0x7) before the process exits on SIGTERM,
# not just an abrupt close -- parsed here at the bare frame-header level
# (3-byte length + 1-byte type + ...), which is all a well-behaved
# client needs to at least recognize what happened, without needing this
# test to also decode the GOAWAY payload itself.
port_h2goaway=$((port + 44))
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/h2goaway-server.key" -out "$web_root/h2goaway-server.crt" \
  >/dev/null 2>&1
"$binary" --port "$port_h2goaway" --root "$h2abuse_root" \
  --tls-cert "$web_root/h2goaway-server.crt" --tls-key "$web_root/h2goaway-server.key" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2 --insecure --fail --silent \
    "https://127.0.0.1:$port_h2goaway/healthz" >/dev/null && break
  sleep 1
done

goaway_out="$web_root/goaway-client.out"
python3 -c "
import socket, ssl, time

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2'])
raw = socket.create_connection(('127.0.0.1', $port_h2goaway), timeout=5)
tls = ctx.wrap_socket(raw, server_hostname='localhost')
assert tls.selected_alpn_protocol() == 'h2'
tls.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + bytes([0,0,0, 0x4,0, 0,0,0,0]))
print('READY', flush=True)

tls.settimeout(10)
buf = b''
goaway_seen = False
deadline = time.time() + 10
while time.time() < deadline:
    try:
        chunk = tls.recv(4096)
    except socket.timeout:
        continue
    if not chunk:
        break
    buf += chunk
    while len(buf) >= 9:
        length = (buf[0] << 16) | (buf[1] << 8) | buf[2]
        frame_type = buf[3]
        if len(buf) < 9 + length:
            break
        if frame_type == 0x7:
            goaway_seen = True
        buf = buf[9 + length:]
    if goaway_seen:
        break
print('GOAWAY_SEEN=%s' % goaway_seen)
" >"$goaway_out" 2>&1 &
goaway_client_pid=$!
for attempt in $(seq 1 20); do
  grep -q READY "$goaway_out" 2>/dev/null && break
  sleep 0.2
done
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
wait "$goaway_client_pid"
grep -q '^GOAWAY_SEEN=True$' "$goaway_out"

# HTTP/2 operational parity (1e-4): /healthz, /metrics, and per-client-IP
# rate limiting all now work the same way over h2 as they already do over
# HTTP/1.1 -- exercised with the exact same --rate-limit 0.5:2 shape (and
# the same burst-of-2-then-429-then-refill sequence) as the pre-existing
# M4 HTTP/1.1 rate-limit block above, so any behavioral drift between the
# two protocols would show up as a divergence from that established
# baseline, not just a fresh assumption about what "should" happen.
port_h2ops=$((port + 45))
h2ops_root="$web_root/h2ops"
mkdir -p "$h2ops_root"
printf '%s\n' 'h2ops static' >"$h2ops_root/hello.txt"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/h2ops-server.key" -out "$web_root/h2ops-server.crt" \
  >/dev/null 2>&1
"$binary" --port "$port_h2ops" --root "$h2ops_root" \
  --tls-cert "$web_root/h2ops-server.crt" --tls-key "$web_root/h2ops-server.key" \
  --rate-limit 0.5:2 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2 --insecure --fail --silent \
    "https://127.0.0.1:$port_h2ops/healthz" >/dev/null && break
  sleep 1
done

healthz_body=$(curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2ops/healthz")
test "$healthz_body" = 'magnus: ok'
head_healthz=$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' --head "https://127.0.0.1:$port_h2ops/healthz")
test "$head_healthz" = '200'

curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2ops/metrics" \
  | grep -Eq '^magnus_rate_limited_total [0-9]+$'

# /healthz and /metrics stay exempt from rate limiting over h2 too, so
# the full burst of 2 is still available for ordinary traffic: the first
# two requests to an ordinary static file succeed and the third is
# rejected -- and /healthz/metrics themselves keep answering throughout,
# even mid-exhaustion.
test "$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2ops/hello.txt")" = '200'
test "$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2ops/hello.txt")" = '200'
test "$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2ops/hello.txt")" = '429'
test "$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2ops/healthz")" = '200'
curl --http2 --insecure --fail --silent \
  "https://127.0.0.1:$port_h2ops/metrics" \
  | grep -Eq '^magnus_rate_limited_total [1-9][0-9]*$'

# The rate-limit bucket is genuinely shared across protocols, keyed by
# client IP alone: an HTTP/1.1 request from the same client, while the
# bucket is still exhausted, is rejected too -- not a separate h2-only
# limiter that a client could bypass by only ever using one protocol for
# its throttled traffic and the other for everything else.
test "$(curl --http1.1 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2ops/hello.txt")" = '429'

sleep 3
test "$(curl --http2 --insecure --silent --output /dev/null \
  --write-out '%{http_code}' "https://127.0.0.1:$port_h2ops/hello.txt")" = '200'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# h2c: cleartext HTTP/2 (1e-5), plain listener only -- the existing
# TLS+ALPN h2 path above is completely separate. Both RFC 9113 3.2/3.4
# entry points, via curl's own real support for each: prior knowledge
# (--http2-prior-knowledge, no HTTP/1.1 exchange at all) and Upgrade:
# h2c (--http2 against a plain http:// URL, which curl negotiates via
# the Upgrade header itself -- real independent verification that
# magnus's 101 response and the immediately-following h2 session are
# both actually well-formed, not just self-consistent with this
# project's own code). Reuses the exact same static/proxy/healthz/
# rate-limit dispatch already proven for TLS+ALPN h2 above, so this
# block only needs to prove the two *entry points* work, plus a handful
# of the most load-bearing behaviors end to end (a route match, HEAD,
# 404, ordinary HTTP/1.1 unaffected on the very same plain listener).
port_h2c=$((port + 46))
upstream_h2c=$((port + 47))
h2c_root="$web_root/h2c"
mkdir -p "$h2c_root"
printf '%s\n' 'h2c ok' >"$h2c_root/hello.txt"
python3 -c "
import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        payload = b'h2c proxied'
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('127.0.0.1', $upstream_h2c), Handler).serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
sleep 1
h2c_config="$web_root/h2c.conf"
cat > "$h2c_config" <<EOF
port = $port_h2c
root = $h2c_root
upstream = 127.0.0.1:$upstream_h2c:1
route = path_prefix=/api; action=proxy
EOF
"$binary" --config "$h2c_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2-prior-knowledge --fail --silent \
    "http://127.0.0.1:$port_h2c/healthz" >/dev/null && break
  sleep 1
done

# Prior knowledge: no HTTP/1.1 exchange at all.
version_pk=$(curl --http2-prior-knowledge --silent --output /dev/null \
  --write-out '%{http_version}' "http://127.0.0.1:$port_h2c/hello.txt")
test "$version_pk" = '2'
test "$(curl --http2-prior-knowledge --fail --silent \
  "http://127.0.0.1:$port_h2c/hello.txt")" = 'h2c ok'

# Upgrade: h2c -- curl itself negotiates the 101 handshake; a real
# HTTP/2 response must follow on the very same connection.
version_up=$(curl --http2 --silent --output /dev/null \
  --write-out '%{http_version}' "http://127.0.0.1:$port_h2c/hello.txt")
test "$version_up" = '2'
test "$(curl --http2 --fail --silent \
  "http://127.0.0.1:$port_h2c/hello.txt")" = 'h2c ok'

head_status=$(curl --http2-prior-knowledge --silent --output /dev/null \
  --write-out '%{http_code}' --head "http://127.0.0.1:$port_h2c/hello.txt")
test "$head_status" = '200'
not_found=$(curl --http2-prior-knowledge --silent --output /dev/null \
  --write-out '%{http_code}' "http://127.0.0.1:$port_h2c/missing.txt")
test "$not_found" = '404'

# Proxy dispatch (1e-2) reachable over both h2c entry points.
test "$(curl --http2-prior-knowledge --fail --silent \
  "http://127.0.0.1:$port_h2c/api/foo")" = 'h2c proxied'
test "$(curl --http2 --fail --silent \
  "http://127.0.0.1:$port_h2c/api/foo")" = 'h2c proxied'

# ALPN is unaffected: an ordinary HTTP/1.1 client on the very same plain
# listener works exactly as before h2c existed.
version_h1=$(curl --http1.1 --silent --output /dev/null \
  --write-out '%{http_version}' "http://127.0.0.1:$port_h2c/hello.txt")
test "$version_h1" = '1.1'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=

# Static response gzip: the same bounded, pre-compressed representation is
# negotiated independently for HTTP/1.1 and HTTP/2. Binary types and clients
# that do not offer gzip remain on their existing paths.
port_compression=$((port + 48))
compression_root="$web_root/compression"
mkdir -p "$compression_root"
for line in $(seq 1 200); do
  printf '<p>Magnus compression regression line %s</p>\n' "$line"
done >"$compression_root/page.html"
printf '\211PNG\r\n\032\nnot-really-an-image-but-a-binary-mime-type\n' \
  >"$compression_root/image.png"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/compression-server.key" \
  -out "$web_root/compression-server.crt" >/dev/null 2>&1
"$binary" --port "$port_compression" --root "$compression_root" \
  --tls-cert "$web_root/compression-server.crt" \
  --tls-key "$web_root/compression-server.key" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --insecure --fail --silent \
    "https://127.0.0.1:$port_compression/healthz" >/dev/null && break
  sleep 1
done

for protocol in --http1.1 --http2; do
  plain_headers="$web_root/plain-${protocol#--}.headers"
  gzip_headers="$web_root/gzip-${protocol#--}.headers"
  decoded_body="$web_root/decoded-${protocol#--}.html"
  curl "$protocol" --insecure --fail --silent --dump-header "$plain_headers" \
    --output "$decoded_body" \
    "https://127.0.0.1:$port_compression/page.html"
  ! grep -qi '^content-encoding: gzip' "$plain_headers"
  cmp "$compression_root/page.html" "$decoded_body"

  # Explicit -H rather than --compressed (which would now negotiate
  # Brotli, not gzip, against this curl build -- see the roadmap 2a-6
  # block below): decoded manually with the gzip CLI instead of relying
  # on libcurl's own transparent decompression, the same shape zstd's
  # own block already needs (its own decoder has no libcurl integration
  # at all) so all three encodings are verified identically here.
  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip' \
    --dump-header "$gzip_headers" --output "$web_root/gzip-${protocol#--}.out" \
    "https://127.0.0.1:$port_compression/page.html"
  grep -qi '^content-encoding: gzip' "$gzip_headers"
  grep -qi '^vary: Accept-Encoding' "$gzip_headers"
  gzip -dc "$web_root/gzip-${protocol#--}.out" | cmp "$compression_root/page.html" -

  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip' \
    --dump-header "$gzip_headers" --output /dev/null \
    "https://127.0.0.1:$port_compression/image.png"
  ! grep -qi '^content-encoding: gzip' "$gzip_headers"

  # Roadmap 2a-5: zstd is a second negotiable encoding, preferred over
  # gzip whenever a client offers both -- curl's own libcurl here has no
  # built-in zstd decoder, so the request/response is driven explicitly
  # and decoded with the zstd CLI instead, the same shape the gzip block
  # above now uses too.
  zstd_headers="$web_root/zstd-${protocol#--}.headers"
  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: zstd' \
    --dump-header "$zstd_headers" --output "$web_root/zstd-${protocol#--}.out" \
    "https://127.0.0.1:$port_compression/page.html"
  grep -qi '^content-encoding: zstd' "$zstd_headers"
  grep -qi '^vary: Accept-Encoding' "$zstd_headers"
  zstd -dc "$web_root/zstd-${protocol#--}.out" | cmp "$compression_root/page.html" -

  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip, zstd' \
    --dump-header "$zstd_headers" --output /dev/null \
    "https://127.0.0.1:$port_compression/page.html"
  grep -qi '^content-encoding: zstd' "$zstd_headers"

  # Roadmap 2a-6: Brotli ("br"), preferred over gzip but not over zstd,
  # whenever a client offers it. This curl build negotiates Brotli
  # transparently via --compressed (libcurl was built with brotli
  # support -- confirmed via `curl --version`), which doubles as live
  # confirmation that magnus's own preference-over-gzip behavior matches
  # what a real, unmodified browser/client would actually get back.
  brotli_headers="$web_root/brotli-${protocol#--}.headers"
  curl "$protocol" --insecure --fail --silent --compressed \
    --dump-header "$brotli_headers" --output "$decoded_body" \
    "https://127.0.0.1:$port_compression/page.html"
  grep -qi '^content-encoding: br' "$brotli_headers"
  grep -qi '^vary: Accept-Encoding' "$brotli_headers"
  cmp "$compression_root/page.html" "$decoded_body"

  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip, zstd, br' \
    --dump-header "$brotli_headers" --output /dev/null \
    "https://127.0.0.1:$port_compression/page.html"
  grep -qi '^content-encoding: zstd' "$brotli_headers"
done

curl --http1.1 --insecure --fail --silent -H 'Accept-Encoding: gzip' \
  "https://127.0.0.1:$port_compression/page.html" \
  | gzip -dc | cmp "$compression_root/page.html" -

# Roadmap 2a-7: streaming compression for a static file past
# MAGNUS_COMPRESSION_MAX_SIZE (8 MiB) -- magnus_compress_static()'s own
# buffer-then-compress shape refuses this file outright (same gate the
# plain/no-Accept-Encoding and HEAD checks below still exercise), so a
# GET offering a real encoding takes the new streaming path instead.
# Random content (not html-shaped like page.html above) is fine here --
# this block is about the framing/plumbing being correct at this size,
# not about ratio, which the ordinary compression blocks already cover.
# HTTP/1.1 only -- see magnus_prepare_streaming_compressed_file_
# response()'s own doc comment for why this first cut stops there.
head -c 9000000 /dev/urandom | base64 >"$compression_root/streaming.html"
stream_size=$(wc -c <"$compression_root/streaming.html")
test "$stream_size" -gt $((8 * 1024 * 1024))

stream_gzip_headers="$web_root/stream-gzip.headers"
curl --http1.1 --insecure --fail --silent -H 'Accept-Encoding: gzip' \
  --dump-header "$stream_gzip_headers" \
  --output "$web_root/stream.out.gz" \
  "https://127.0.0.1:$port_compression/streaming.html"
grep -qi '^content-encoding: gzip' "$stream_gzip_headers"
grep -qi '^vary: Accept-Encoding' "$stream_gzip_headers"
grep -qi '^connection: close' "$stream_gzip_headers"
! grep -qi '^content-length:' "$stream_gzip_headers"
gzip -dc "$web_root/stream.out.gz" | cmp "$compression_root/streaming.html" -

stream_zstd_headers="$web_root/stream-zstd.headers"
curl --http1.1 --insecure --fail --silent -H 'Accept-Encoding: zstd' \
  --dump-header "$stream_zstd_headers" \
  --output "$web_root/stream.out.zst" \
  "https://127.0.0.1:$port_compression/streaming.html"
grep -qi '^content-encoding: zstd' "$stream_zstd_headers"
! grep -qi '^content-length:' "$stream_zstd_headers"
zstd -dc "$web_root/stream.out.zst" | cmp "$compression_root/streaming.html" -

stream_brotli_headers="$web_root/stream-brotli.headers"
curl --http1.1 --insecure --fail --silent -H 'Accept-Encoding: br' \
  --dump-header "$stream_brotli_headers" \
  --output "$web_root/stream.out.br" \
  "https://127.0.0.1:$port_compression/streaming.html"
grep -qi '^content-encoding: br' "$stream_brotli_headers"
! grep -qi '^content-length:' "$stream_brotli_headers"
brotli -dc "$web_root/stream.out.br" | cmp "$compression_root/streaming.html" -

# No Accept-Encoding: the ordinary uncompressed relay handles a file
# this large exactly like it always has -- a real Content-Length, kept
# alive, completely unaffected by the streaming path existing now.
stream_plain_headers="$web_root/stream-plain.headers"
curl --http1.1 --insecure --fail --silent --dump-header "$stream_plain_headers" \
  --output "$web_root/stream.out.plain" \
  "https://127.0.0.1:$port_compression/streaming.html"
! grep -qi '^content-encoding:' "$stream_plain_headers"
grep -qi "^content-length: $stream_size" "$stream_plain_headers"
grep -qi '^connection: keep-alive' "$stream_plain_headers"
cmp "$compression_root/streaming.html" "$web_root/stream.out.plain"

# HEAD deliberately never takes the streaming path (see that function's
# own doc comment) -- still answers with the file's real, uncompressed
# Content-Length, same as any other HEAD on a static file.
stream_head_headers="$web_root/stream-head.headers"
curl --http1.1 --insecure --fail --silent --head -H 'Accept-Encoding: gzip' \
  --dump-header "$stream_head_headers" --output /dev/null \
  "https://127.0.0.1:$port_compression/streaming.html"
! grep -qi '^content-encoding:' "$stream_head_headers"
grep -qi "^content-length: $stream_size" "$stream_head_headers"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Proxy dispatch response compression, HTTP/1.1 and HTTP/2 (roadmap
# 2a-2/2a-3): unlike the static-file gzip block just above, this must go
# all the way through a real upstream fetch -- the compressed bytes come
# from a body that only exists once relayed through magnus_proxy_
# finish_compression()'s (h1) or magnus_h2_proxy_finish_compression()'s
# (h2) own buffer-then-compress path, not an mmap'd file. A response the
# client never asked to compress (no Accept-Encoding), a non-compressible
# content-type (image/png, gated exactly like the static-file path
# already is), and a body under MAGNUS_COMPRESSION_MIN_SIZE all stay on
# the ordinary streaming relay -- only the one eligible case takes the
# buffered path. TLS is needed here (unlike the plain-HTTP block this
# one replaces) purely so curl can negotiate --http2 against the same
# running instance the --http1.1 pass already covers.
port_compress_proxy_upstream=$((port + 128))
port_compress_proxy=$((port + 129))
compress_proxy_root="$web_root/compress-proxy"
mkdir -p "$compress_proxy_root"
for line in $(seq 1 200); do
  printf '<p>Magnus proxy compression regression line %s</p>\n' "$line"
done >"$compress_proxy_root/page.html"
printf '\211PNG\r\n\032\nnot-really-an-image-but-a-binary-mime-type\n' \
  >"$compress_proxy_root/image.png"
printf '<html>tiny</html>' >"$compress_proxy_root/tiny.html"
python3 -m http.server "$port_compress_proxy_upstream" --bind 127.0.0.1 \
  --directory "$compress_proxy_root" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent \
    "http://127.0.0.1:$port_compress_proxy_upstream/page.html" >/dev/null \
    && break
  sleep 1
done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/compress-proxy-server.key" \
  -out "$web_root/compress-proxy-server.crt" >/dev/null 2>&1
"$binary" --port "$port_compress_proxy" --root "$web_root" \
  --tls-cert "$web_root/compress-proxy-server.crt" \
  --tls-key "$web_root/compress-proxy-server.key" \
  --upstream "127.0.0.1:$port_compress_proxy_upstream" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --insecure --fail --silent \
    "https://127.0.0.1:$port_compress_proxy/healthz" >/dev/null && break
  sleep 1
done

for protocol in --http1.1 --http2; do
  plain_headers="$web_root/compress-proxy-plain-${protocol#--}.headers"
  gzip_headers="$web_root/compress-proxy-gzip-${protocol#--}.headers"
  decoded_body="$web_root/compress-proxy-decoded-${protocol#--}.html"

  curl "$protocol" --insecure --fail --silent --dump-header "$plain_headers" \
    --output "$decoded_body" \
    "https://127.0.0.1:$port_compress_proxy/proxy/page.html"
  ! grep -qi '^content-encoding: gzip' "$plain_headers"
  cmp "$compress_proxy_root/page.html" "$decoded_body"

  # Explicit -H rather than --compressed (which would now negotiate
  # Brotli against this curl build -- see the roadmap 2a-6 block below),
  # decoded manually with the gzip CLI, the same reasoning as the
  # static-file compression block above.
  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip' \
    --dump-header "$gzip_headers" \
    --output "$web_root/compress-proxy-gzip-${protocol#--}.out" \
    "https://127.0.0.1:$port_compress_proxy/proxy/page.html"
  grep -qi '^content-encoding: gzip' "$gzip_headers"
  grep -qi '^vary: Accept-Encoding' "$gzip_headers"
  gzip -dc "$web_root/compress-proxy-gzip-${protocol#--}.out" \
    | cmp "$compress_proxy_root/page.html" -

  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip' \
    --dump-header "$gzip_headers" --output /dev/null \
    "https://127.0.0.1:$port_compress_proxy/proxy/image.png"
  ! grep -qi '^content-encoding: gzip' "$gzip_headers"

  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip' \
    --dump-header "$gzip_headers" --output /dev/null \
    "https://127.0.0.1:$port_compress_proxy/proxy/tiny.html"
  ! grep -qi '^content-encoding: gzip' "$gzip_headers"

  # Roadmap 2a-5: zstd through the proxy dispatch path -- the same
  # buffer-then-compress machinery as gzip above, just a different
  # encoder/Content-Encoding, and (again) preferred over gzip when a
  # client offers both.
  zstd_headers="$web_root/compress-proxy-zstd-${protocol#--}.headers"
  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: zstd' \
    --dump-header "$zstd_headers" \
    --output "$web_root/compress-proxy-zstd-${protocol#--}.out" \
    "https://127.0.0.1:$port_compress_proxy/proxy/page.html"
  grep -qi '^content-encoding: zstd' "$zstd_headers"
  grep -qi '^vary: Accept-Encoding' "$zstd_headers"
  zstd -dc "$web_root/compress-proxy-zstd-${protocol#--}.out" \
    | cmp "$compress_proxy_root/page.html" -

  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip, zstd' \
    --dump-header "$zstd_headers" --output /dev/null \
    "https://127.0.0.1:$port_compress_proxy/proxy/page.html"
  grep -qi '^content-encoding: zstd' "$zstd_headers"

  # Roadmap 2a-6: Brotli through the proxy dispatch path -- --compressed
  # here doubles as live confirmation that a real client sees the same
  # preference-over-gzip the static-file block above already proved.
  brotli_headers="$web_root/compress-proxy-brotli-${protocol#--}.headers"
  curl "$protocol" --insecure --fail --silent --compressed \
    --dump-header "$brotli_headers" --output "$decoded_body" \
    "https://127.0.0.1:$port_compress_proxy/proxy/page.html"
  grep -qi '^content-encoding: br' "$brotli_headers"
  grep -qi '^vary: Accept-Encoding' "$brotli_headers"
  cmp "$compress_proxy_root/page.html" "$decoded_body"

  curl "$protocol" --insecure --fail --silent -H 'Accept-Encoding: gzip, zstd, br' \
    --dump-header "$brotli_headers" --output /dev/null \
    "https://127.0.0.1:$port_compress_proxy/proxy/page.html"
  grep -qi '^content-encoding: zstd' "$brotli_headers"
done

curl --http1.1 --insecure --fail --silent -H 'Accept-Encoding: gzip' \
  "https://127.0.0.1:$port_compress_proxy/proxy/page.html" \
  | gzip -dc | cmp "$compress_proxy_root/page.html" -

kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Real IP (roadmap 2b): PROXY protocol v1/v2 and Forwarded/X-Forwarded-For
# resolution, gated on trusted_proxies -- exercised via config-file mode
# (proving the config key, not just the CLI flag equivalent) with the
# resolved address fed into a source_cidr route so this proves the
# resolution actually reaches routing, not just access-log cosmetics.
port_realip=$((port + 49))
realip_root="$web_root/realip"
mkdir -p "$realip_root"
printf '%s\n' 'realip ok' >"$realip_root/hello.txt"
realip_config="$web_root/realip.conf"
cat > "$realip_config" <<EOF
port = $port_realip
root = $realip_root
trusted_proxies = 127.0.0.1/32
route = source_cidr=9.9.9.0/24; action=deny
EOF
"$binary" --config "$realip_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_realip/healthz" >/dev/null && break
  sleep 1
done

# X-Forwarded-For from a trusted peer resolves and reaches routing: a
# denied source_cidr becomes reachable through the header, proving this is
# real request-time resolution, not just an access-log cosmetic.
xff_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'X-Forwarded-For: 9.9.9.9' "http://127.0.0.1:$port_realip/hello.txt")
test "$xff_status" = '403'
test "$(curl --fail --silent -H 'X-Forwarded-For: 1.2.3.4' \
  "http://127.0.0.1:$port_realip/hello.txt")" = 'realip ok'

# Forwarded takes precedence over X-Forwarded-For when both are present.
forwarded_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Forwarded: for=9.9.9.9' -H 'X-Forwarded-For: 1.2.3.4' \
  "http://127.0.0.1:$port_realip/hello.txt")
test "$forwarded_status" = '403'

python3 - "$port_realip" <<'PYEOF'
import socket
import struct
import sys

port = int(sys.argv[1])

def expect(status_code, *sends):
    s = socket.create_connection(("127.0.0.1", port))
    for chunk in sends:
        s.sendall(chunk)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            more = s.recv(4096)
            if not more:
                break
            data += more
    finally:
        s.close()
    line = data.split(b"\r\n", 1)[0]
    assert status_code.encode() in line, "expected %s, got %r" % (status_code, line)

# PROXY v1 TCP4: resolved source 9.9.9.9 matches the deny route.
expect("403", b"PROXY TCP4 9.9.9.9 1.1.1.1 11111 " + str(port).encode() + b"\r\n",
       b"GET /hello.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

# PROXY v1 TCP4: an address outside the deny route's CIDR still works.
expect("200", b"PROXY TCP4 1.2.3.4 1.1.1.1 11111 " + str(port).encode() + b"\r\n",
       b"GET /hello.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

# PROXY v2 binary, AF_INET: same resolved-address enforcement.
sig = bytes([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A])
addr_block = (socket.inet_aton("9.9.9.9") + socket.inet_aton("1.1.1.1")
              + struct.pack("!H", 22222) + struct.pack("!H", port))
header = sig + bytes([0x21, 0x11]) + struct.pack("!H", len(addr_block)) + addr_block
expect("403", header,
       b"GET /hello.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

# A connection that never speaks PROXY protocol at all is unaffected --
# NOT_PROXY falls through to ordinary HTTP/1.1 processing of the exact
# same bytes.
expect("200", b"GET /hello.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

# A malformed preamble from a trusted peer is fatal: the connection is
# reset rather than misinterpreted as an HTTP request.
s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"PROXY GARBAGE_NOT_VALID\r\n")
try:
    data = s.recv(4096)
    assert data == b"", "expected connection reset/EOF, got %r" % data
except ConnectionResetError:
    pass
finally:
    s.close()

print("realip: proxy-protocol ok")
PYEOF

# The server must still be alive and serving normally after all of the
# above, including the malformed-preamble abuse case.
test "$(curl --fail --silent "http://127.0.0.1:$port_realip/hello.txt")" = 'realip ok'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# gRPC (roadmap 2c-1): a client h2 stream matched to action=grpc relays to
# an HTTP/2-native upstream over magnus's own second, client-role nghttp2
# session -- verified against a raw, stdlib-only (no h2/hyperframe pip
# dependency, matching 1e-3's own precedent) hand-rolled h2 "upstream"
# that only ever *encodes* frames, never decodes any (it does not need to
# understand magnus's own HPACK-compressed request to answer), so no
# hand-rolled HPACK decoder is needed either -- the actual gRPC semantics
# (grpc-status/grpc-message trailers, custom trailing metadata, RPC-level
# vs. gateway-level failure) were independently verified live against a
# real grpcio client and server (not part of this permanent suite, per
# the same no-new-pip-dependency precedent); this block instead proves
# the wire-level plumbing a curl-only regression *can* check: status,
# content-type, and the upstream's exact response bytes relayed
# byte-for-byte, an HTTP/1.1 request to the same route answered with an
# explicit error rather than silently mis-served, and the "always
# :status 200, even on total gateway failure" contract from a completely
# unreachable upstream.
port_grpc_fake_upstream=$((port + 50))
port_grpc=$((port + 51))
port_grpc_bad=$((port + 52))
port_grpc_stream_fake_upstream=$((port + 53))
port_grpc_stream=$((port + 54))
port_grpc_slow_fake_upstream=$((port + 55))
port_grpc_slow=$((port + 56))
port_grpc_multi_a=$((port + 57))
port_grpc_multi_b=$((port + 58))
port_grpc_multi=$((port + 59))

python3 - "$port_grpc_fake_upstream" >"$web_root/grpc-fake-upstream.log" 2>&1 <<'PYEOF' &
import socket
import sys
import threading

PORT = int(sys.argv[1])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_string(s):
    b = s.encode() if isinstance(s, str) else s
    assert len(b) < 127
    return bytes([len(b)]) + b


def hpack_literal_new_name(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def build_headers_block(pairs):
    return b"".join(hpack_literal_new_name(k, v) for k, v in pairs)


def frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
                     frame_type, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("peer closed early")
        data += chunk
    return data


def handle(conn):
    read_exact(conn, len(PREFACE))  # client connection preface
    stream_id = None
    end_stream_seen = False
    while not end_stream_seen:
        header = read_exact(conn, 9)
        length = (header[0] << 16) | (header[1] << 8) | header[2]
        frame_type = header[3]
        flags = header[4]
        sid = int.from_bytes(header[5:9], "big") & 0x7fffffff
        payload = read_exact(conn, length) if length else b""
        if frame_type == 0x1:  # HEADERS
            stream_id = sid
            if flags & 0x1:
                end_stream_seen = True
        elif frame_type == 0x0:  # DATA
            if flags & 0x1:
                end_stream_seen = True

    conn.sendall(frame(0x4, 0x0, 0))  # SETTINGS (empty)
    conn.sendall(frame(0x4, 0x1, 0))  # SETTINGS ACK

    resp_headers = build_headers_block([
        (":status", "200"),
        ("content-type", "application/grpc"),
    ])
    conn.sendall(frame(0x1, 0x4, stream_id, resp_headers))  # HEADERS, END_HEADERS

    grpc_payload = b"fake-upstream-payload"
    grpc_frame = bytes([0]) + len(grpc_payload).to_bytes(4, "big") + grpc_payload
    conn.sendall(frame(0x0, 0x0, stream_id, grpc_frame))  # DATA, no END_STREAM

    trailer = build_headers_block([
        ("grpc-status", "0"),
        ("grpc-message", ""),
    ])
    conn.sendall(frame(0x1, 0x4 | 0x1, stream_id, trailer))  # trailer HEADERS, END_STREAM


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(8)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
backend_pid=$!
sleep 1

"$binary" --port "$port_grpc" --grpc-upstream "127.0.0.1:$port_grpc_fake_upstream" \
  --route "path_prefix=/; action=grpc" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2-prior-knowledge --fail --silent \
    "http://127.0.0.1:$port_grpc/healthz" >/dev/null && break
  sleep 1
done

grpc_headers="$web_root/grpc.headers"
grpc_body="$web_root/grpc.body"
curl --http2-prior-knowledge --silent -X POST --dump-header "$grpc_headers" \
  --output "$grpc_body" "http://127.0.0.1:$port_grpc/echo.Echo/SayHello"
grep -qi '^HTTP/2 200' "$grpc_headers"
grep -qi '^content-type: application/grpc' "$grpc_headers"
grep -qi '^grpc-status: 0' "$grpc_headers"
printf '\000\000\000\000\025fake-upstream-payload' | cmp - "$grpc_body"

# HTTP/1.1 against the same action=grpc route: an explicit error, never
# silently mis-served as static/proxy.
h1_status=$(curl --http1.1 --silent --output /dev/null --write-out '%{http_code}' \
  -X POST "http://127.0.0.1:$port_grpc/echo.Echo/SayHello")
test "$h1_status" = '505'

"$binary" --port "$port_grpc_bad" --grpc-upstream "127.0.0.1:$((port_grpc_fake_upstream + 500))" \
  --route "path_prefix=/; action=grpc" 2>>"$log" &
backend2_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2-prior-knowledge --fail --silent \
    "http://127.0.0.1:$port_grpc_bad/healthz" >/dev/null && break
  sleep 1
done
# Total gateway failure (no reachable upstream at all) is still answered
# with :status 200 -- a real gRPC client treats any other :status as a
# *transport* failure, not the RPC-level outcome grpc-status conveys, so
# magnus must never send a raw 502/504 here (see magnus_h2_grpc_fail()'s
# own comment).
bad_status=$(curl --http2-prior-knowledge --silent --output /dev/null \
  --write-out '%{http_code}' -X POST \
  "http://127.0.0.1:$port_grpc_bad/echo.Echo/SayHello")
test "$bad_status" = '200'

# Streaming (roadmap 2c-2): the upstream leg sends its response DATA in
# two separately-timed chunks (a real sleep in between) before its
# trailer; a raw socket client (stdlib-only, reading the SAME connection
# it sent the request on) observes two separate recv()s with a
# measurable gap between them, proving magnus relayed each chunk to the
# real client as it arrived rather than buffering the whole response
# first (2c-1's own shape) -- the deeper RPC-level semantics of
# client-/server-streaming and bidi (multiple messages each direction,
# genuinely interleaved over time) were verified live against a real
# grpcio client and server, not part of this permanent suite, per the
# same no-new-pip-dependency precedent 2c-1 already established.
python3 - "$port_grpc_stream_fake_upstream" >"$web_root/grpc-stream-fake-upstream.log" 2>&1 <<'PYEOF' &
import socket
import sys
import threading
import time

PORT = int(sys.argv[1])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_string(s):
    b = s.encode() if isinstance(s, str) else s
    assert len(b) < 127
    return bytes([len(b)]) + b


def hpack_literal_new_name(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def build_headers_block(pairs):
    return b"".join(hpack_literal_new_name(k, v) for k, v in pairs)


def frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
                     frame_type, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("peer closed early")
        data += chunk
    return data


def handle(conn):
    read_exact(conn, len(PREFACE))
    stream_id = None
    end_stream_seen = False
    while not end_stream_seen:
        header = read_exact(conn, 9)
        length = (header[0] << 16) | (header[1] << 8) | header[2]
        frame_type = header[3]
        flags = header[4]
        sid = int.from_bytes(header[5:9], "big") & 0x7fffffff
        read_exact(conn, length) if length else b""
        if frame_type == 0x1:
            stream_id = sid
            if flags & 0x1:
                end_stream_seen = True
        elif frame_type == 0x0:
            if flags & 0x1:
                end_stream_seen = True

    conn.sendall(frame(0x4, 0x0, 0))
    conn.sendall(frame(0x4, 0x1, 0))

    resp_headers = build_headers_block([
        (":status", "200"),
        ("content-type", "application/grpc"),
    ])
    conn.sendall(frame(0x1, 0x4, stream_id, resp_headers))

    for chunk_text in ("first-chunk", "second-chunk"):
        payload = chunk_text.encode()
        grpc_frame = bytes([0]) + len(payload).to_bytes(4, "big") + payload
        conn.sendall(frame(0x0, 0x0, stream_id, grpc_frame))
        time.sleep(0.2)

    trailer = build_headers_block([("grpc-status", "0"), ("grpc-message", "")])
    conn.sendall(frame(0x1, 0x4 | 0x1, stream_id, trailer))


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(8)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
backend3_pid=$!
sleep 1

"$binary" --port "$port_grpc_stream" \
  --grpc-upstream "127.0.0.1:$port_grpc_stream_fake_upstream" \
  --route "path_prefix=/; action=grpc" 2>>"$log" &
backend4_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2-prior-knowledge --fail --silent \
    "http://127.0.0.1:$port_grpc_stream/healthz" >/dev/null && break
  sleep 1
done

python3 - "$port_grpc_stream" <<'PYEOF'
import socket
import sys
import time

port = int(sys.argv[1])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_string(s):
    b = s.encode() if isinstance(s, str) else s
    assert len(b) < 127
    return bytes([len(b)]) + b


def hpack_literal_new_name(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def build_headers_block(pairs):
    return b"".join(hpack_literal_new_name(k, v) for k, v in pairs)


def frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
                     frame_type, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


s = socket.create_connection(("127.0.0.1", port))
s.sendall(PREFACE)
s.sendall(frame(0x4, 0x0, 0))  # client SETTINGS (empty)
req_headers = build_headers_block([
    (":method", "POST"), (":scheme", "http"), (":authority", "x"),
    (":path", "/stream.Test/Chunks"), ("te", "trailers"),
    ("content-type", "application/grpc"),
])
s.sendall(frame(0x1, 0x4 | 0x1, 1, req_headers))  # END_HEADERS|END_STREAM, no body

arrivals = []
start = time.monotonic()
buf = b""


def recv_frame():
    global buf
    while len(buf) < 9:
        more = s.recv(4096)
        assert more, "connection closed early"
        buf += more
    length = (buf[0] << 16) | (buf[1] << 8) | buf[2]
    frame_type = buf[3]
    while len(buf) < 9 + length:
        more = s.recv(4096)
        assert more, "connection closed early"
        buf += more
    payload = buf[9:9 + length]
    buf = buf[9 + length:]
    return frame_type, payload


data_chunks = 0
while data_chunks < 2:
    frame_type, payload = recv_frame()
    if frame_type == 0x0:  # DATA
        data_chunks += 1
        arrivals.append(time.monotonic() - start)

gap = arrivals[1] - arrivals[0]
# The two chunks were sent 0.2s apart by the fake upstream; a generous
# floor (0.1s) comfortably separates genuine incremental relay from a
# buffer-then-send implementation, which would deliver both back-to-back
# (gap near zero) regardless of the upstream's own timing.
assert gap > 0.1, "response chunks arrived back-to-back, not streamed incrementally: gap=%r" % gap
print("grpc: response streaming gap=%.3fs (incremental, not buffered)" % gap)
PYEOF

kill -TERM "$backend4_pid" 2>/dev/null
wait "$backend4_pid" 2>/dev/null || true
backend4_pid=
kill -TERM "$backend3_pid" 2>/dev/null
wait "$backend3_pid" 2>/dev/null || true
backend3_pid=

# grpc-timeout deadline propagation (roadmap 2c-3): the upstream leg
# takes 3 real seconds to answer at all; a raw socket client (no
# grpc-python, no client-side timer of its own -- see this block's own
# comment on why that matters) sends grpc-timeout: 500m and asserts a
# response arrives well under 3s, proving magnus's own periodic sweep
# (magnus_expire_proxies()) enforced the client-supplied deadline rather
# than ever waiting on the (much later) upstream response. The deeper
# semantic content (a real client library decoding the response as
# DEADLINE_EXCEEDED, and an ample timeout letting the same slow-but-
# within-budget RPC succeed normally) was verified live against a real
# grpcio client, not part of this permanent suite, per the same
# no-new-pip-dependency precedent 2c-1 already established.
python3 - "$port_grpc_slow_fake_upstream" >"$web_root/grpc-slow-fake-upstream.log" 2>&1 <<'PYEOF' &
import socket
import sys
import threading
import time

PORT = int(sys.argv[1])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_string(s):
    b = s.encode() if isinstance(s, str) else s
    assert len(b) < 127
    return bytes([len(b)]) + b


def hpack_literal_new_name(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def build_headers_block(pairs):
    return b"".join(hpack_literal_new_name(k, v) for k, v in pairs)


def frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
                     frame_type, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("peer closed early")
        data += chunk
    return data


def handle(conn):
    read_exact(conn, len(PREFACE))
    stream_id = None
    end_stream_seen = False
    while not end_stream_seen:
        header = read_exact(conn, 9)
        length = (header[0] << 16) | (header[1] << 8) | header[2]
        frame_type = header[3]
        flags = header[4]
        sid = int.from_bytes(header[5:9], "big") & 0x7fffffff
        read_exact(conn, length) if length else b""
        if frame_type == 0x1:
            stream_id = sid
            if flags & 0x1:
                end_stream_seen = True
        elif frame_type == 0x0:
            if flags & 0x1:
                end_stream_seen = True

    conn.sendall(frame(0x4, 0x0, 0))
    conn.sendall(frame(0x4, 0x1, 0))
    time.sleep(3.0)
    try:
        resp_headers = build_headers_block([
            (":status", "200"), ("content-type", "application/grpc"),
        ])
        conn.sendall(frame(0x1, 0x4, stream_id, resp_headers))
        payload = b"too-late"
        grpc_frame = bytes([0]) + len(payload).to_bytes(4, "big") + payload
        conn.sendall(frame(0x0, 0x0, stream_id, grpc_frame))
        trailer = build_headers_block([("grpc-status", "0"), ("grpc-message", "")])
        conn.sendall(frame(0x1, 0x4 | 0x1, stream_id, trailer))
    except OSError:
        pass  # client (magnus) already gave up and closed -- expected


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(8)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
backend3_pid=$!
sleep 1

"$binary" --port "$port_grpc_slow" \
  --grpc-upstream "127.0.0.1:$port_grpc_slow_fake_upstream" \
  --route "path_prefix=/; action=grpc" 2>>"$log" &
backend4_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2-prior-knowledge --fail --silent \
    "http://127.0.0.1:$port_grpc_slow/healthz" >/dev/null && break
  sleep 1
done

python3 - "$port_grpc_slow" <<'PYEOF'
import socket
import sys
import time

port = int(sys.argv[1])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_string(s):
    b = s.encode() if isinstance(s, str) else s
    assert len(b) < 127
    return bytes([len(b)]) + b


def hpack_literal_new_name(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def build_headers_block(pairs):
    return b"".join(hpack_literal_new_name(k, v) for k, v in pairs)


def frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
                     frame_type, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        assert chunk, "connection closed early"
        data += chunk
    return data


s = socket.create_connection(("127.0.0.1", port))
s.sendall(PREFACE)
s.sendall(frame(0x4, 0x0, 0))
req_headers = build_headers_block([
    (":method", "POST"), (":scheme", "http"), (":authority", "x"),
    (":path", "/slow.Test/Wait"), ("te", "trailers"),
    ("content-type", "application/grpc"), ("grpc-timeout", "500m"),
])
s.sendall(frame(0x1, 0x4 | 0x1, 1, req_headers))

start = time.monotonic()
# Read frames (ignoring the two SETTINGS-shaped ones nghttp2 sends first)
# until something HEADERS/RST_STREAM-shaped for our stream arrives.
while True:
    header = read_exact(s, 9)
    length = (header[0] << 16) | (header[1] << 8) | header[2]
    frame_type = header[3]
    read_exact(s, length) if length else b""
    if frame_type in (0x1, 0x3):  # HEADERS or RST_STREAM
        break

elapsed = time.monotonic() - start
print("grpc: deadline response at t=%.3fs (upstream answers at 3.0s)" % elapsed)
assert elapsed < 2.0, (
    "response took %.3fs -- grpc-timeout: 500m was not enforced by magnus's "
    "own sweep (it waited for the slow upstream instead)" % elapsed)
PYEOF

kill -TERM "$backend4_pid" 2>/dev/null
wait "$backend4_pid" 2>/dev/null || true
backend4_pid=
kill -TERM "$backend3_pid" 2>/dev/null
wait "$backend3_pid" 2>/dev/null || true
backend3_pid=

# Routing/observability/affinity polish (roadmap 2c-4): two distinguishable
# fake upstreams (each answers with its own endpoint id in the response
# body) behind one magnus instance with two grpc_upstream entries and a
# route matched by `header_prefix:content-type=application/grpc` instead
# of a catch-all path_prefix -- proving the new condition actually gates
# dispatch, not just that action=grpc still works once matched.
magnus_grpc_multi_fake_upstream() {
  python3 - "$1" "$2" >>"$web_root/grpc-multi-upstream.log" 2>&1 <<'PYEOF' &
import socket
import sys
import threading

PORT = int(sys.argv[1])
ENDPOINT_ID = sys.argv[2]
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_string(s):
    b = s.encode() if isinstance(s, str) else s
    assert len(b) < 127
    return bytes([len(b)]) + b


def hpack_literal_new_name(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def build_headers_block(pairs):
    return b"".join(hpack_literal_new_name(k, v) for k, v in pairs)


def frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
                     frame_type, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("peer closed early")
        data += chunk
    return data


def handle(conn):
    # Loops for as many RPCs as arrive on this one connection, not just
    # one -- magnus pools/multiplexes its upstream gRPC connections
    # (roadmap 2c-5) rather than opening a fresh one per RPC, so the
    # affinity test below (repeat calls carrying the same sticky cookie)
    # genuinely exercises connection *reuse*, exactly like a real gRPC
    # server would ever expect. Sends its own initial SETTINGS once, right
    # after the connection preface, not per-RPC.
    read_exact(conn, len(PREFACE))
    conn.sendall(frame(0x4, 0x0, 0))
    conn.sendall(frame(0x4, 0x1, 0))
    while True:
        stream_id = None
        end_stream_seen = False
        while not end_stream_seen:
            header = read_exact(conn, 9)
            length = (header[0] << 16) | (header[1] << 8) | header[2]
            frame_type = header[3]
            flags = header[4]
            sid = int.from_bytes(header[5:9], "big") & 0x7fffffff
            read_exact(conn, length) if length else b""
            if frame_type == 0x1:
                stream_id = sid
                if flags & 0x1:
                    end_stream_seen = True
            elif frame_type == 0x0:
                if flags & 0x1:
                    end_stream_seen = True

        resp_headers = build_headers_block([
            (":status", "200"), ("content-type", "application/grpc"),
        ])
        conn.sendall(frame(0x1, 0x4, stream_id, resp_headers))
        payload = ("endpoint-" + ENDPOINT_ID).encode()
        grpc_frame = bytes([0]) + len(payload).to_bytes(4, "big") + payload
        conn.sendall(frame(0x0, 0x0, stream_id, grpc_frame))
        trailer = build_headers_block([("grpc-status", "0"), ("grpc-message", "")])
        conn.sendall(frame(0x1, 0x4 | 0x1, stream_id, trailer))


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(8)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
}
magnus_grpc_multi_fake_upstream "$port_grpc_multi_a" A
backend4_pid=$!
magnus_grpc_multi_fake_upstream "$port_grpc_multi_b" B
backend5_pid=$!
sleep 1

"$binary" --port "$port_grpc_multi" \
  --grpc-upstream "127.0.0.1:$port_grpc_multi_a:1" \
  --grpc-upstream "127.0.0.1:$port_grpc_multi_b:1" \
  --route "header_prefix:content-type=application/grpc; action=grpc" \
  --access-log on 2>>"$log" &
backend3_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2-prior-knowledge --fail --silent \
    "http://127.0.0.1:$port_grpc_multi/healthz" >/dev/null && break
  sleep 1
done

# header_prefix actually gates dispatch: a content-type carrying a codec
# suffix (never an exact match for "application/grpc") still matches, and
# a request with no grpc-shaped content-type at all falls through to
# ordinary (here: 404, no root configured) dispatch instead.
prefix_status=$(curl --http2-prior-knowledge --silent --output /dev/null \
  --write-out '%{http_code}' -X POST -H 'content-type: application/grpc+proto' \
  -H 'te: trailers' "http://127.0.0.1:$port_grpc_multi/echo.Echo/SayHello")
test "$prefix_status" = '200'
no_match_status=$(curl --http2-prior-knowledge --silent --output /dev/null \
  --write-out '%{http_code}' "http://127.0.0.1:$port_grpc_multi/echo.Echo/SayHello")
test "$no_match_status" = '404'

# Session affinity: capture the Set-Cookie magnus issues on a first call
# (no cookie jar yet), then confirm every subsequent call carrying it
# sticks to the exact same endpoint rather than round-robining -- proven
# by the response body itself naming which fake upstream answered.
cookie_jar="$web_root/grpc-affinity-cookies.txt"
first_body=$(curl --http2-prior-knowledge --fail --silent -X POST \
  -H 'content-type: application/grpc' -H 'te: trailers' \
  --data-binary $'\x00\x00\x00\x00\x00' -c "$cookie_jar" \
  "http://127.0.0.1:$port_grpc_multi/echo.Echo/SayHello" | tail -c 10)
for attempt in 1 2 3 4; do
  sticky_body=$(curl --http2-prior-knowledge --fail --silent -X POST \
    -H 'content-type: application/grpc' -H 'te: trailers' \
    --data-binary $'\x00\x00\x00\x00\x00' -b "$cookie_jar" \
    "http://127.0.0.1:$port_grpc_multi/echo.Echo/SayHello" | tail -c 10)
  test "$sticky_body" = "$first_body"
done

# grpc-status-aware access logging and /metrics: the access log line for
# a successful gRPC call carries a real grpc_status=0 field, and /metrics
# reports the same outcome under magnus_grpc_status_total{code="0"} --
# neither of which existed before 2c-4 (every gRPC response's wire
# :status is always 200, so status= alone could never distinguish success
# from failure for this traffic).
grep -q 'target=/echo\.Echo/SayHello.*grpc_status=0' "$log"
metrics_body=$(curl --silent "http://127.0.0.1:$port_grpc_multi/metrics")
echo "$metrics_body" | grep -q '^magnus_grpc_status_total{code="0"} [1-9][0-9]*$'
echo "grpc: routing/affinity/observability ok"

kill -TERM "$backend3_pid" 2>/dev/null
wait "$backend3_pid" 2>/dev/null || true
backend3_pid=
kill -TERM "$backend5_pid" 2>/dev/null
wait "$backend5_pid" 2>/dev/null || true
backend5_pid=
kill -TERM "$backend4_pid" 2>/dev/null
wait "$backend4_pid" 2>/dev/null || true
backend4_pid=

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend2_pid" 2>/dev/null
wait "$backend2_pid" 2>/dev/null || true
backend2_pid=
kill -TERM "$backend_pid" 2>/dev/null
wait "$backend_pid" 2>/dev/null || true
backend_pid=
echo "grpc: ok"

# Reverse-proxy cache (roadmap 2d-1): opt-in per route via
# `action=proxy; cache=on`. hits.txt below is a plain byte-counter file
# the fake upstream appends to on every request it actually receives --
# the simplest possible way to prove a HIT/REVALIDATED response never
# touched the upstream at all, without needing a stateful protocol of its
# own.
port_cache=$((port + 60))
upstream_cache=$((port + 61))
port_cache_off=$((port + 62))
hits_file="$web_root/cache-hits.txt"
: > "$hits_file"
python3 -c "
import http.server, threading

HITS_FILE = '$hits_file'
STATE = {'body': b'hello-v1', 'changed': False}
LOCK = threading.Lock()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _record(self):
        with LOCK, open(HITS_FILE, 'a') as f:
            f.write('x')

    def do_GET(self):
        self._record()
        with LOCK:
            body = STATE['body']
            changed = STATE['changed']
        if self.path == '/cacheable':
            self.send_response(200)
            self.send_header('Cache-Control', 'max-age=60')
            self.send_header('ETag', '\"v1\"')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/no-store':
            self.send_response(200)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/with-cookie':
            self.send_response(200)
            self.send_header('Cache-Control', 'max-age=60')
            self.send_header('Set-Cookie', 'sess=abc')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/revalidate':
            inm = self.headers.get('If-None-Match')
            if changed:
                newbody = b'hello-v2'
                self.send_response(200)
                self.send_header('Cache-Control', 'max-age=60')
                self.send_header('ETag', '\"v2\"')
                self.send_header('Content-Length', str(len(newbody)))
                self.end_headers()
                self.wfile.write(newbody)
            elif inm == '\"v1\"':
                self.send_response(304)
                self.send_header('Cache-Control', 'max-age=1')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Cache-Control', 'max-age=1')
                self.send_header('ETag', '\"v1\"')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        elif self.path == '/change':
            with LOCK:
                STATE['changed'] = True
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(('127.0.0.1', $upstream_cache), Handler).serve_forever()
" >/dev/null 2>&1 &
backend6_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$upstream_cache/cacheable" >/dev/null && break
  sleep 1
done

# --health-check-interval is pushed out to effectively "never, within this
# test's runtime": roadmap 2f's active probe is now a real HTTP GET that
# reaches this fake upstream's own request handler (unlike the pre-2f
# bare TCP connect(), which never did), so an unthrottled default would
# increment hits_file in the background and corrupt the exact-hit-count
# assertions below.
"$binary" --port "$port_cache" --upstream "127.0.0.1:$upstream_cache" \
  --route "path_prefix=/; action=proxy; cache=on" \
  --health-check-interval 3600 \
  --access-log on 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --http2-prior-knowledge --fail --silent \
    "http://127.0.0.1:$port_cache/healthz" >/dev/null && break
  sleep 1
done

# A fresh GET goes to the upstream and gets stored; a repeat GET is
# answered entirely from the cache -- X-Cache: HIT, identical body, and
# critically zero additional bytes in hits_file (the fake upstream's own
# per-request marker).
cache_body1="$web_root/cache-body1"
cache_hdrs1="$web_root/cache-hdrs1"
curl --silent --dump-header "$cache_hdrs1" --output "$cache_body1" \
  "http://127.0.0.1:$port_cache/cacheable"
grep -qi '^HTTP/1.1 200' "$cache_hdrs1"
! grep -qi '^X-Cache:' "$cache_hdrs1"
hits_after_first=$(wc -c < "$hits_file")

cache_body2="$web_root/cache-body2"
cache_hdrs2="$web_root/cache-hdrs2"
curl --silent --dump-header "$cache_hdrs2" --output "$cache_body2" \
  "http://127.0.0.1:$port_cache/cacheable"
grep -qi '^X-Cache: HIT' "$cache_hdrs2"
diff "$cache_body1" "$cache_body2"
test "$(wc -c < "$hits_file")" = "$hits_after_first"

# Same entry served to an HTTP/2 client too -- one shared cache, not one
# per protocol.
h2_hdrs="$web_root/cache-h2-hdrs"
h2_body="$web_root/cache-h2-body"
curl --http2-prior-knowledge --silent --dump-header "$h2_hdrs" \
  --output "$h2_body" "http://127.0.0.1:$port_cache/cacheable"
grep -qi '^x-cache: HIT' "$h2_hdrs"
diff "$cache_body1" "$h2_body"
test "$(wc -c < "$hits_file")" = "$hits_after_first"

# no-store, and a response carrying Set-Cookie, are never cached even
# though both are otherwise ordinary 200s -- every call reaches the
# upstream.
before=$(wc -c < "$hits_file")
curl --silent --output /dev/null "http://127.0.0.1:$port_cache/no-store"
curl --silent --output /dev/null "http://127.0.0.1:$port_cache/no-store"
curl --silent --output /dev/null "http://127.0.0.1:$port_cache/with-cookie"
curl --silent --output /dev/null "http://127.0.0.1:$port_cache/with-cookie"
test "$(wc -c < "$hits_file")" = "$((before + 4))"

# Revalidation: a stale entry with an ETag is revalidated via a
# conditional GET (If-None-Match) rather than re-fetched in full -- a 304
# from the origin refreshes freshness and is answered from the *cached*
# body (X-Cache: REVALIDATED), never a second full transfer.
curl --silent --output /dev/null "http://127.0.0.1:$port_cache/revalidate"
sleep 1.2
reval_hdrs="$web_root/cache-reval-hdrs"
reval_body="$web_root/cache-reval-body"
curl --silent --dump-header "$reval_hdrs" --output "$reval_body" \
  "http://127.0.0.1:$port_cache/revalidate"
grep -qi '^X-Cache: REVALIDATED' "$reval_hdrs"
test "$(cat "$reval_body")" = "hello-v1"

# If the origin decides to send fresh content instead of confirming a
# 304, that is treated as an ordinary fetch -- the new content replaces
# the stale entry, and a follow-up call now hits the *new* body.
curl --silent --output /dev/null "http://127.0.0.1:$port_cache/change"
sleep 1.2
curl --silent --output /dev/null "http://127.0.0.1:$port_cache/revalidate"
changed_hdrs="$web_root/cache-changed-hdrs"
changed_body="$web_root/cache-changed-body"
curl --silent --dump-header "$changed_hdrs" --output "$changed_body" \
  "http://127.0.0.1:$port_cache/revalidate"
grep -qi '^X-Cache: HIT' "$changed_hdrs"
test "$(cat "$changed_body")" = "hello-v2"

# /metrics reports real hit/miss/revalidation counters.
cache_metrics=$(curl --silent "http://127.0.0.1:$port_cache/metrics")
echo "$cache_metrics" | grep -qE '^magnus_cache_hits_total [1-9][0-9]*$'
echo "$cache_metrics" | grep -qE '^magnus_cache_revalidated_total [1-9][0-9]*$'

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# A route that never opts in (no cache= at all) never touches the cache,
# even for an otherwise-identical upstream/path -- opt-in is per route,
# never a global default.
"$binary" --port "$port_cache_off" --upstream "127.0.0.1:$upstream_cache" \
  --route "path_prefix=/; action=proxy" --health-check-interval 3600 \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_cache_off/healthz" >/dev/null && break
  sleep 1
done
before=$(wc -c < "$hits_file")
off_hdrs="$web_root/cache-off-hdrs"
curl --silent --dump-header "$off_hdrs" --output /dev/null \
  "http://127.0.0.1:$port_cache_off/cacheable"
curl --silent --dump-header "$off_hdrs" --output /dev/null \
  "http://127.0.0.1:$port_cache_off/cacheable"
! grep -qi '^X-Cache:' "$off_hdrs"
test "$(wc -c < "$hits_file")" = "$((before + 2))"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend6_pid" 2>/dev/null
wait "$backend6_pid" 2>/dev/null || true
backend6_pid=
echo "cache: hit/miss/revalidate/opt-in ok"

# Advanced load balancing (roadmap 2e-1): `--lb-policy least_conn|ip_hash`,
# both selected only for a *fresh* (non-sticky-cookie) pick -- see
# magnus_policy.h's own top comment. Three backends, labelled A/B/C by
# response body, with A alone answering /slow after a deliberate 2s delay
# so it can be driven "busy" on demand; B and C answer everything
# instantly. Endpoint order (A, B, C) is significant: with every endpoint
# idle, least_conn's own lowest-index tie-break always picks A first.
portA=$((port + 63))
portB=$((port + 64))
portC=$((port + 65))
for spec in "A:$portA" "B:$portB" "C:$portC"; do
  label=${spec%%:*}
  lb_port=${spec##*:}
  python3 -c "
import http.server, time

LABEL = b'$label'

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        if self.path == '/slow':
            time.sleep(2)
        self.send_response(200)
        self.send_header('Content-Length', str(len(LABEL)))
        self.end_headers()
        self.wfile.write(LABEL)
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(('127.0.0.1', $lb_port), Handler).serve_forever()
" >/dev/null 2>&1 &
  case "$label" in
    A) backend7_pid=$! ;;
    B) backend8_pid=$! ;;
    C) backend9_pid=$! ;;
  esac
done
for lb_port in "$portA" "$portB" "$portC"; do
  for attempt in 1 2 3 4 5; do
    curl --fail --silent "http://127.0.0.1:$lb_port/" >/dev/null && break
    sleep 1
  done
done

# least_conn: drive A busy via /slow in the background, wait (via /metrics'
# own magnus_upstream_active_requests gauge) until magnus itself has
# actually counted that request as in flight against A -- not a fixed
# sleep -- then two fresh requests must both avoid A, landing on B and C
# instead.
port_lc=$((port + 66))
"$binary" --port "$port_lc" --upstream "127.0.0.1:$portA" \
  --upstream "127.0.0.1:$portB" --upstream "127.0.0.1:$portC" \
  --lb-policy least_conn 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_lc/healthz" >/dev/null && break
  sleep 1
done
slow_body="$web_root/lb-slow-body"
curl --silent --output "$slow_body" "http://127.0.0.1:$port_lc/proxy/slow" &
slow_curl_pid=$!
busy=0
for attempt in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:$port_lc/metrics" \
      | grep -qE "^magnus_upstream_active_requests\{endpoint=\"127\.0\.0\.1:$portA\"\} [1-9]"; then
    busy=1
    break
  fi
  sleep 0.1
done
test "$busy" = 1
first=$(curl --fail --silent "http://127.0.0.1:$port_lc/proxy/")
second=$(curl --fail --silent "http://127.0.0.1:$port_lc/proxy/")
test "$first" != "A"
test "$second" != "A"
case "$first" in B|C) : ;; *) exit 1 ;; esac
case "$second" in B|C) : ;; *) exit 1 ;; esac
wait "$slow_curl_pid"
test "$(cat "$slow_body")" = "A"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# ip_hash: fresh (no MAGNUS_AFFINITY cookie, since each curl invocation
# here is cookie-jar-free) selections from the same source IP must all
# land on the same endpoint, consistently across both HTTP/1.1 and
# HTTP/2 -- one shared rendezvous-hash decision, not one per protocol.
port_ih=$((port + 67))
"$binary" --port "$port_ih" --upstream "127.0.0.1:$portA" \
  --upstream "127.0.0.1:$portB" --upstream "127.0.0.1:$portC" \
  --lb-policy ip_hash 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_ih/healthz" >/dev/null && break
  sleep 1
done
ih_h1a=$(curl --fail --silent "http://127.0.0.1:$port_ih/proxy/1")
ih_h1b=$(curl --fail --silent "http://127.0.0.1:$port_ih/proxy/2")
ih_h2a=$(curl --http2-prior-knowledge --fail --silent "http://127.0.0.1:$port_ih/proxy/3")
ih_h2b=$(curl --http2-prior-knowledge --fail --silent "http://127.0.0.1:$port_ih/proxy/4")
test "$ih_h1a" = "$ih_h1b"
test "$ih_h1a" = "$ih_h2a"
test "$ih_h1a" = "$ih_h2b"
case "$ih_h1a" in A|B|C) : ;; *) exit 1 ;; esac
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

kill -TERM "$backend7_pid" 2>/dev/null
wait "$backend7_pid" 2>/dev/null || true
backend7_pid=
kill -TERM "$backend8_pid" 2>/dev/null
wait "$backend8_pid" 2>/dev/null || true
backend8_pid=
kill -TERM "$backend9_pid" 2>/dev/null
wait "$backend9_pid" 2>/dev/null || true
backend9_pid=
echo "lb: least_conn/ip_hash ok"

# Active health check expansion (roadmap 2f): the `upstream` cluster's
# active probe is now a real HTTP/1.1 GET (health_check_path, success iff
# the response status equals health_check_expected_status) instead of a
# bare TCP connect() -- this backend accepts every connection but always
# answers 500 on "/" and 200 on "/ok", something a bare connect() probe
# could never have told apart. --health-check-interval/--timeout/
# --failure-threshold are all tightened for a fast, deterministic test
# instead of waiting out the multi-second defaults.
port_hc_backend=$((port + 68))
python3 -c "
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        status = 200 if self.path == '/ok' else 500
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.end_headers()
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(('127.0.0.1', $port_hc_backend), Handler).serve_forever()
" >/dev/null 2>&1 &
backend10_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_hc_backend/ok" >/dev/null && break
  sleep 1
done

# Default health_check_path ("/") hits the always-500 branch: active
# checking alone (no proxy traffic sent at all, same M3 discipline) must
# find this endpoint unhealthy even though it accepts every TCP connect.
port_hc_default=$((port + 69))
"$binary" --port "$port_hc_default" --upstream "127.0.0.1:$port_hc_backend" \
  --health-check-interval 1 --health-check-timeout 1 \
  --health-check-failure-threshold 2 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_hc_default/healthz" >/dev/null && break
  sleep 1
done
hc_unhealthy_seen=0
for attempt in $(seq 1 10); do
  sleep 1
  if curl --fail --silent "http://127.0.0.1:$port_hc_default/metrics" \
      | grep -Eq '^magnus_upstream_endpoints_healthy 0$'; then
    hc_unhealthy_seen=1
    break
  fi
done
test "$hc_unhealthy_seen" = 1
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Same backend, --health-check-path pointed at the 200-answering branch
# instead: the endpoint must stay healthy the whole time, proving the
# path/expected-status knobs actually reach the probe rather than the
# default silently winning.
port_hc_ok=$((port + 70))
"$binary" --port "$port_hc_ok" --upstream "127.0.0.1:$port_hc_backend" \
  --health-check-path /ok --health-check-interval 1 --health-check-timeout 1 \
  --health-check-failure-threshold 2 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_hc_ok/healthz" >/dev/null && break
  sleep 1
done
sleep 4
curl --fail --silent "http://127.0.0.1:$port_hc_ok/metrics" \
  | grep -Eq '^magnus_upstream_endpoints_healthy 1$'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend10_pid" 2>/dev/null
wait "$backend10_pid" 2>/dev/null || true
backend10_pid=

# The gRPC cluster gets active health checking too (TCP-connect only, no
# HTTP GET -- see magnus_health_tick()'s own comment on why): before this
# increment it had none at all, only whatever live traffic happened to
# reveal. Same M3 discipline -- no gRPC traffic sent, only the background
# probe can move magnus_grpc_upstream_healthy.
port_grpc_hc_backend=$((port + 71))
port_grpc_hc=$((port + 72))
"$binary" --port "$port_grpc_hc" \
  --grpc-upstream "127.0.0.1:$port_grpc_hc_backend" \
  --route "path_prefix=/; action=grpc" \
  --health-check-interval 1 --health-check-timeout 1 \
  --health-check-failure-threshold 2 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_grpc_hc/healthz" >/dev/null && break
  sleep 1
done
grpc_hc_unhealthy_seen=0
for attempt in $(seq 1 10); do
  sleep 1
  if curl --fail --silent "http://127.0.0.1:$port_grpc_hc/metrics" \
      | grep -Eq "^magnus_grpc_upstream_healthy\{endpoint=\"127\.0\.0\.1:$port_grpc_hc_backend\"\} 0\$"; then
    grpc_hc_unhealthy_seen=1
    break
  fi
done
test "$grpc_hc_unhealthy_seen" = 1

# Bringing up a plain listener on that port (not a real gRPC server --
# this cluster's active probe is TCP-connect-only, so a bare accept()
# loop is exactly what it is testing) flips it back to healthy purely via
# the background probe.
python3 -m http.server "$port_grpc_hc_backend" --bind 127.0.0.1 \
  --directory "$web_root" >/dev/null 2>&1 &
backend11_pid=$!
grpc_hc_recovered=0
for attempt in $(seq 1 10); do
  sleep 1
  if curl --fail --silent "http://127.0.0.1:$port_grpc_hc/metrics" \
      | grep -Eq "^magnus_grpc_upstream_healthy\{endpoint=\"127\.0\.0\.1:$port_grpc_hc_backend\"\} 1\$"; then
    grpc_hc_recovered=1
    break
  fi
done
test "$grpc_hc_recovered" = 1
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend11_pid" 2>/dev/null
wait "$backend11_pid" 2>/dev/null || true
backend11_pid=
echo "health-check: http-mode/path/expected-status/grpc-coverage ok"

# L4 TCP passthrough (roadmap 3a): a new listener type that never goes
# through magnus_http_parse() at all. portA/portB run a tiny labelled
# echo backend (sends "WELCOME:<label>\n" then echoes "<label>:<data>"
# per chunk received -- good enough to identify which endpoint served a
# given connection, but NOT byte-exact for a payload split across many
# chunks, which is what portPlain -- a true byte-for-byte echo, no
# label -- is for instead).
portA=$((port + 73))
portB=$((port + 74))
portPlain=$((port + 75))
# A and B are deliberately two separate processes, not two threads in one
# -- the health-check portion of this test later kills A on its own to
# simulate a dead backend, which must never take B down with it.
labelled_backend() {
  # exec, not a plain call: the health-check portion of this test kills
  # this backend by PID to simulate it going down, and $! after
  # backgrounding a function call is the subshell running the function,
  # not (without this) the python3 process underneath it -- TERM-ing the
  # subshell alone would leave python3 as an orphaned child still holding
  # the port open, exactly the kind of gap this test is meant to catch
  # elsewhere, not fall into itself.
  exec python3 -c "
import socket, threading

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $1))
s.listen(50)
def handle(conn):
    conn.sendall(b'WELCOME:$2\n')
    while True:
        data = conn.recv(4096)
        if not data:
            break
        conn.sendall(b'$2:' + data)
    conn.close()
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
"
}
labelled_backend "$portA" A >/dev/null 2>&1 &
backend12_pid=$!
labelled_backend "$portB" B >/dev/null 2>&1 &
backend13_pid=$!
python3 -c "
import socket, threading

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $portPlain))
s.listen(50)
def handle(conn):
    while True:
        data = conn.recv(65536)
        if not data:
            break
        conn.sendall(data)
    conn.close()
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
" >/dev/null 2>&1 &
backend14_pid=$!
for stream_port in "$portA" "$portB" "$portPlain"; do
  for attempt in 1 2 3 4 5; do
    python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', $stream_port), timeout=1)
s.close()
" 2>/dev/null && break
    sleep 1
  done
done

# round_robin (the default): two fresh connections against a two-endpoint
# stream cluster land on both endpoints, and a persistent connection stays
# on the one it was matched to for its whole lifetime (LB decides once
# per connection, not per message -- there is no per-message routing at
# L4 the way there is an HTTP request boundary at L7).
port_rr=$((port + 76))
port_rr_stream=$((port + 77))
"$binary" --port "$port_rr" --stream-listen "$port_rr_stream" \
  --stream-upstream "127.0.0.1:$portA" --stream-upstream "127.0.0.1:$portB" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_rr/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket

def welcome(port):
    s = socket.create_connection(('127.0.0.1', port), timeout=3)
    s.settimeout(3)
    label = s.recv(4096).decode().strip().split(':')[1]
    return s, label

s1, l1 = welcome($port_rr_stream)
s2, l2 = welcome($port_rr_stream)
assert {l1, l2} == {'A', 'B'}, (l1, l2)
# persistent connection: 5 messages all served by the same endpoint
s1.sendall(b'ping1')
r1 = s1.recv(4096).decode()
s1.sendall(b'ping2')
r2 = s1.recv(4096).decode()
assert r1.startswith(l1 + ':') and r2.startswith(l1 + ':'), (r1, r2)
s1.close()
s2.close()
print('stream: round_robin alternation + persistent-connection stickiness ok')
"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# ip_hash: fresh connections from the same client IP all land on the same
# endpoint (rendezvous hashing, same primitive roadmap 2e-1 already gave
# the h1/h2 proxy cluster -- reused unmodified here, no new LB code).
port_ih=$((port + 78))
port_ih_stream=$((port + 79))
"$binary" --port "$port_ih" --stream-listen "$port_ih_stream" \
  --stream-upstream "127.0.0.1:$portA" --stream-upstream "127.0.0.1:$portB" \
  --stream-lb-policy ip_hash 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_ih/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket

def welcome(port):
    s = socket.create_connection(('127.0.0.1', port), timeout=3)
    s.settimeout(3)
    label = s.recv(4096).decode().strip().split(':')[1]
    s.close()
    return label

labels = [welcome($port_ih_stream) for _ in range(4)]
assert len(set(labels)) == 1, labels
print('stream: ip_hash same-client determinism ok')
"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Byte-exact relay across many MAGNUS_PROXY_BUFFER (16KiB) refills, plus a
# half-close (client shuts its write side down mid-response) still
# delivering the rest of the response before a clean EOF -- the standard
# L4-proxy half-close semantics, not something HTTP has an equivalent of.
port_plain=$((port + 80))
port_plain_stream=$((port + 81))
"$binary" --port "$port_plain" --stream-listen "$port_plain_stream" \
  --stream-upstream "127.0.0.1:$portPlain" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_plain/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket, hashlib, os

s = socket.create_connection(('127.0.0.1', $port_plain_stream), timeout=10)
s.settimeout(10)
payload = os.urandom(300 * 1024)
s.sendall(payload)
s.shutdown(socket.SHUT_WR)
received = b''
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    received += chunk
s.close()
assert len(received) == len(payload), (len(received), len(payload))
assert hashlib.sha256(received).digest() == hashlib.sha256(payload).digest()
print('stream: byte-exact large-payload relay + half-close ok')
"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Active health check (roadmap 2f, extended to this cluster): killing
# backend A must be found by background probing alone -- no stream
# traffic sent at all, same M3/2f-1 discipline -- and a fresh listener on
# that port must be found again the same way. Also regression-covers the
# MAGNUS_OUTPUT_LIMIT/MAGNUS_METRICS_BUFFER bug this increment's own live
# testing found: a real deployment with the upstream+stream clusters both
# populated pushed /metrics' rendered body past the old 2048-byte ceiling,
# silently emptying the *entire* response rather than just truncating it
# -- checking that the response's own last-ever-emitted line
# (magnus_cache_bytes, cache always being the final block) is present and
# well-formed catches that regression directly.
port_hc_stream=$((port + 82))
port_hc_stream_listen=$((port + 83))
"$binary" --port "$port_hc_stream" --stream-listen "$port_hc_stream_listen" \
  --stream-upstream "127.0.0.1:$portA" --stream-upstream "127.0.0.1:$portB" \
  --health-check-interval 1 --health-check-timeout 1 \
  --health-check-failure-threshold 2 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_hc_stream/healthz" >/dev/null \
    && break
  sleep 1
done
kill -TERM "$backend12_pid"
wait "$backend12_pid" 2>/dev/null || true
backend12_pid=
stream_unhealthy_seen=0
for attempt in $(seq 1 10); do
  sleep 1
  if curl --fail --silent "http://127.0.0.1:$port_hc_stream/metrics" \
      | grep -qE "^magnus_stream_upstream_healthy\{endpoint=\"127\.0\.0\.1:$portA\"\} 0\$"; then
    stream_unhealthy_seen=1
    break
  fi
done
test "$stream_unhealthy_seen" = 1
metrics_intact=$(curl --fail --silent "http://127.0.0.1:$port_hc_stream/metrics")
echo "$metrics_intact" | grep -qE '^magnus_cache_bytes [0-9]+$'
labelled_backend "$portA" A >/dev/null 2>&1 &
backend12_pid=$!
stream_recovered_seen=0
for attempt in $(seq 1 10); do
  sleep 1
  if curl --fail --silent "http://127.0.0.1:$port_hc_stream/metrics" \
      | grep -qE "^magnus_stream_upstream_healthy\{endpoint=\"127\.0\.0\.1:$portA\"\} 1\$"; then
    stream_recovered_seen=1
    break
  fi
done
test "$stream_recovered_seen" = 1
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend12_pid" 2>/dev/null
wait "$backend12_pid" 2>/dev/null || true
backend12_pid=
kill -TERM "$backend13_pid" 2>/dev/null
wait "$backend13_pid" 2>/dev/null || true
backend13_pid=
kill -TERM "$backend14_pid" 2>/dev/null
wait "$backend14_pid" 2>/dev/null || true
backend14_pid=
echo "stream: TCP passthrough (round_robin/ip_hash/byte-exact/health-check) ok"

# TLS passthrough / SNI routing (roadmap 3b): a real TLS ClientHello,
# captured from Python's own ssl module (not hand-typed), is peeked at
# and routed by SNI without magnus ever terminating TLS -- the labelled
# backend's own "WELCOME:<label>\n" banner, followed by the raw
# ClientHello bytes echoed straight back, proves both which endpoint was
# picked *and* that the original ClientHello prefix reached it byte-for-
# byte unmodified (true passthrough, not a translation).
portSniA=$((port + 84))
portSniB=$((port + 85))
portSniDefault=$((port + 86))
labelled_backend "$portSniA" A >/dev/null 2>&1 &
backend15_pid=$!
labelled_backend "$portSniB" B >/dev/null 2>&1 &
backend16_pid=$!
labelled_backend "$portSniDefault" DEFAULT >/dev/null 2>&1 &
backend17_pid=$!
for sni_backend_port in "$portSniA" "$portSniB" "$portSniDefault"; do
  for attempt in 1 2 3 4 5; do
    python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', $sni_backend_port), timeout=1)
s.close()
" 2>/dev/null && break
    sleep 1
  done
done

port_sni=$((port + 87))
port_sni_stream=$((port + 88))
"$binary" --port "$port_sni" --stream-listen "$port_sni_stream" \
  --stream-upstream "127.0.0.1:$portSniDefault" \
  --stream-sni-route "site-a.test 127.0.0.1:$portSniA" \
  --stream-sni-route "*.wild.test 127.0.0.1:$portSniB" \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_sni/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket, ssl, threading

def capture_clienthello(hostname):
    captured = {}
    ready = threading.Event()
    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        captured['port'] = srv.getsockname()[1]
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        captured['bytes'] = conn.recv(65536)
        conn.close()
        srv.close()
    t = threading.Thread(target=server)
    t.start()
    ready.wait()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(('127.0.0.1', captured['port']), timeout=3)
    try:
        ctx.wrap_socket(raw, server_hostname=hostname)
    except Exception:
        pass
    t.join(timeout=3)
    return captured['bytes']

def send_and_read(payload, target):
    # A single recv() is not guaranteed to capture a large multi-part
    # response in one call -- loop until 'target' bytes have arrived (the
    # labelled backend's own two separate sendall()s: the welcome banner,
    # then the echoed payload) or the connection closes/times out.
    s = socket.create_connection(('127.0.0.1', $port_sni_stream), timeout=5)
    s.settimeout(5)
    s.sendall(payload)
    received = b''
    while len(received) < target:
        chunk = s.recv(65536)
        if not chunk:
            break
        received += chunk
    s.close()
    return received

ch_a = capture_clienthello('site-a.test')
resp_a = send_and_read(ch_a, len(b'WELCOME:A\nA:') + len(ch_a))
assert resp_a.startswith(b'WELCOME:A\n'), resp_a[:40]
assert resp_a[len(b'WELCOME:A\n'):] == b'A:' + ch_a, 'ClientHello not relayed byte-for-byte'

ch_wild = capture_clienthello('foo.wild.test')
resp_wild = send_and_read(ch_wild, len(b'WELCOME:B\n'))
assert resp_wild.startswith(b'WELCOME:B\n'), resp_wild[:40]

# The bare wildcard domain itself must NOT match '*.wild.test' (needs a
# label before the dot -- see magnus_sni_pattern_matches()'s own
# comment), and an unrelated hostname matches nothing either: both fall
# back to the default stream_upstream cluster.
ch_bare = capture_clienthello('wild.test')
resp_bare = send_and_read(ch_bare, len(b'WELCOME:DEFAULT\n'))
assert resp_bare.startswith(b'WELCOME:DEFAULT\n'), resp_bare[:40]

ch_other = capture_clienthello('unrelated.example.org')
resp_other = send_and_read(ch_other, len(b'WELCOME:DEFAULT\n'))
assert resp_other.startswith(b'WELCOME:DEFAULT\n'), resp_other[:40]

# Plain non-TLS traffic (MAGNUS_SNI_NOT_TLS) falls back the same way.
resp_http = send_and_read(b'GET / HTTP/1.1\r\nHost: site-a.test\r\n\r\n',
                          len(b'WELCOME:DEFAULT\n'))
assert resp_http.startswith(b'WELCOME:DEFAULT\n'), resp_http[:40]

print('stream: SNI exact/wildcard/no-match/non-TLS routing ok')
"
curl --fail --silent "http://127.0.0.1:$port_sni/metrics" \
  | grep -qE '^magnus_stream_sni_upstream_healthy\{pattern="site-a\.test",endpoint="127\.0\.0\.1:'"$portSniA"'"\} 1$'
curl --fail --silent "http://127.0.0.1:$port_sni/metrics" \
  | grep -qE '^magnus_stream_sni_upstream_healthy\{pattern="\*\.wild\.test",endpoint="127\.0\.0\.1:'"$portSniB"'"\} 1$'

# A client that never sends enough to resolve SNI at all (nothing sent,
# ever) is not held open forever -- MAGNUS_STREAM_PEEK_TIMEOUT_SECONDS
# gives up and falls back to the default cluster the same way an
# unmatched or malformed ClientHello does.
python3 -c "
import socket, time
s = socket.create_connection(('127.0.0.1', $port_sni_stream), timeout=15)
s.settimeout(15)
start = time.time()
banner = s.recv(4096)
elapsed = time.time() - start
assert banner.startswith(b'WELCOME:DEFAULT\n'), banner[:40]
assert 3 <= elapsed <= 10, elapsed
s.close()
print('stream: SNI peek-timeout fallback ok')
"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend15_pid" 2>/dev/null
wait "$backend15_pid" 2>/dev/null || true
backend15_pid=
kill -TERM "$backend16_pid" 2>/dev/null
wait "$backend16_pid" 2>/dev/null || true
backend16_pid=
kill -TERM "$backend17_pid" 2>/dev/null
wait "$backend17_pid" 2>/dev/null || true
backend17_pid=
echo "stream: TLS passthrough / SNI routing ok"

# PROXY protocol emission: the "PROXY protocol" line item from Phase 3's
# own roadmap headline, not covered by TCP passthrough (3a), TLS
# passthrough (3b), or UDP passthrough (3d) -- magnus here is the
# *emitter*, prefixing its own outbound connection to a backend with a
# preamble identifying the real (source IP, source port) a plain TCP
# relay would otherwise never reveal. Exercised against both the plain
# default stream cluster and an SNI-routed one (roadmap 3b combo), for
# both wire formats.
proxy_protocol_backend() {
  # Same exec discipline as labelled_backend above, for the same PID-kill
  # reason. Parses a PROXY protocol v1 (text) or v2 (binary) preamble off
  # the front of each connection -- if present -- and reports what it
  # found as a single "HDR:<mode>:<src_ip>:<src_port>\n" line (or
  # "HDR:none\n" when no recognizable preamble was present at all, the
  # off-by-default case), followed by the labelled echo of whatever bytes
  # came after the preamble -- same "<label>:<payload>" shape
  # labelled_backend's own plain echo already uses, so a passthrough
  # payload's byte-exactness is checked the same way.
  exec python3 -c "
import socket, threading

V2_SIG = bytes([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
                0x55, 0x49, 0x54, 0x0A])

def recv_exact(conn, n, buf):
    while len(buf) < n:
        chunk = conn.recv(4096)
        if not chunk:
            raise EOFError
        buf += chunk
    return buf

def handle(conn):
    try:
        buf = recv_exact(conn, 16, b'')
        if buf[:6] == b'PROXY ':
            while b'\r\n' not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    raise EOFError
                buf += chunk
            idx = buf.index(b'\r\n')
            parts = buf[:idx].decode().split()
            remainder = buf[idx + 2:]
            desc = 'v1:%s:%s' % (parts[2], parts[4])
        elif buf[:12] == V2_SIG:
            buf = recv_exact(conn, 16, buf)
            addr_len = (buf[14] << 8) | buf[15]
            buf = recv_exact(conn, 16 + addr_len, buf)
            src_addr = socket.inet_ntoa(buf[16:20])
            src_port = int.from_bytes(buf[24:26], 'big')
            remainder = buf[16 + addr_len:]
            desc = 'v2:%s:%s' % (src_addr, src_port)
        else:
            remainder = buf
            desc = 'none'
        conn.sendall(('HDR:%s\n' % desc).encode())
        if remainder:
            conn.sendall(b'$2:' + remainder)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(b'$2:' + data)
    except EOFError:
        pass
    except OSError:
        pass
    finally:
        conn.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $1))
s.listen(50)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
"
}
portPpDefault=$((port + 97))
portPpA=$((port + 98))
proxy_protocol_backend "$portPpDefault" DEFAULT >/dev/null 2>&1 &
backend20_pid=$!
proxy_protocol_backend "$portPpA" A >/dev/null 2>&1 &
backend21_pid=$!
for pp_backend_port in "$portPpDefault" "$portPpA"; do
  for attempt in 1 2 3 4 5; do
    python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', $pp_backend_port), timeout=1)
s.close()
" 2>/dev/null && break
    sleep 1
  done
done

port_pp_v1=$((port + 99))
port_pp_v1_stream=$((port + 100))
"$binary" --port "$port_pp_v1" --stream-listen "$port_pp_v1_stream" \
  --stream-upstream "127.0.0.1:$portPpDefault" \
  --stream-sni-route "site-a.test 127.0.0.1:$portPpA" \
  --stream-proxy-protocol v1 \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_pp_v1/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket, ssl, threading, time

def capture_clienthello(hostname):
    captured = {}
    ready = threading.Event()
    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        captured['port'] = srv.getsockname()[1]
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        captured['bytes'] = conn.recv(65536)
        conn.close()
        srv.close()
    t = threading.Thread(target=server)
    t.start()
    ready.wait()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(('127.0.0.1', captured['port']), timeout=3)
    try:
        ctx.wrap_socket(raw, server_hostname=hostname)
    except Exception:
        pass
    t.join(timeout=3)
    return captured['bytes']

def send_and_read(payload):
    # A single recv() is not guaranteed to capture the backend's two
    # separate sendall()s (the HDR line, then the labelled echo) in one
    # call -- poll with a short per-call timeout until the connection
    # goes quiet, same reasoning as the SNI test's own send_and_read.
    s = socket.create_connection(('127.0.0.1', $port_pp_v1_stream), timeout=5)
    s.settimeout(0.5)
    local_port = s.getsockname()[1]
    s.sendall(payload)
    received = b''
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            if received:
                break
            continue
        if not chunk:
            break
        received += chunk
    s.close()
    return local_port, received

# Plain non-TLS traffic falls back to the default stream_upstream cluster
# (no stream_sni_route matched a non-TLS payload) -- the preamble must
# still be the literal first bytes on the wire, ahead of the payload.
port1, resp1 = send_and_read(b'GET / HTTP/1.1\r\nHost: site-a.test\r\n\r\n')
expect_hdr1 = ('HDR:v1:127.0.0.1:%d\n' % port1).encode()
assert resp1.startswith(expect_hdr1), (expect_hdr1, resp1[:60])
assert resp1[len(expect_hdr1):] == b'DEFAULT:GET / HTTP/1.1\r\nHost: site-a.test\r\n\r\n', resp1

# SNI-matched traffic (roadmap 3b combo): a real captured TLS ClientHello
# routes to the A cluster, and still gets the PROXY preamble first,
# followed by the exact ClientHello bytes, unmodified, right after it.
ch_a = capture_clienthello('site-a.test')
port2, resp2 = send_and_read(ch_a)
expect_hdr2 = ('HDR:v1:127.0.0.1:%d\n' % port2).encode()
assert resp2.startswith(expect_hdr2), (expect_hdr2, resp2[:60])
assert resp2[len(expect_hdr2):] == b'A:' + ch_a, 'ClientHello not relayed byte-for-byte after PROXY header'

print('stream: PROXY protocol v1 emission (default + SNI-routed clusters, byte-exact) ok')
"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

port_pp_v2=$((port + 101))
port_pp_v2_stream=$((port + 102))
"$binary" --port "$port_pp_v2" --stream-listen "$port_pp_v2_stream" \
  --stream-upstream "127.0.0.1:$portPpDefault" \
  --stream-proxy-protocol v2 \
  2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_pp_v2/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket, time

s = socket.create_connection(('127.0.0.1', $port_pp_v2_stream), timeout=5)
s.settimeout(0.5)
local_port = s.getsockname()[1]
payload = b'v2-emission-byte-exact-payload'
s.sendall(payload)
received = b''
deadline = time.time() + 5
while time.time() < deadline:
    try:
        chunk = s.recv(65536)
    except socket.timeout:
        if received:
            break
        continue
    if not chunk:
        break
    received += chunk
s.close()
expect_hdr = ('HDR:v2:127.0.0.1:%d\n' % local_port).encode()
assert received.startswith(expect_hdr), (expect_hdr, received[:60])
assert received[len(expect_hdr):] == b'DEFAULT:' + payload, received
print('stream: PROXY protocol v2 emission (binary preamble, byte-exact) ok')
"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend20_pid" 2>/dev/null
wait "$backend20_pid" 2>/dev/null || true
backend20_pid=
kill -TERM "$backend21_pid" 2>/dev/null
wait "$backend21_pid" 2>/dev/null || true
backend21_pid=
echo "stream: PROXY protocol emission ok"

# UDP passthrough (roadmap 3d): a NAT-style session per (source IP,
# source port) tuple, no HTTP/TCP machinery involved at all. A tiny
# labelled UDP echo backend (send back "<label>:<payload>") identifies
# which endpoint served a given exchange, same idea as the TCP stream
# tests' own labelled_backend, just SOCK_DGRAM.
udp_backend() {
  exec python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $1))
while True:
    data, addr = s.recvfrom(65536)
    s.sendto(b'$2:' + data, addr)
"
}
portUdpA=$((port + 89))
portUdpB=$((port + 90))
udp_backend "$portUdpA" A >/dev/null 2>&1 &
backend18_pid=$!
udp_backend "$portUdpB" B >/dev/null 2>&1 &
backend19_pid=$!
for udp_backend_port in "$portUdpA" "$portUdpB"; do
  for attempt in 1 2 3 4 5; do
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(b'ping', ('127.0.0.1', $udp_backend_port))
s.recvfrom(4096)
" 2>/dev/null && break
    sleep 1
  done
done

# round_robin + session stickiness: two distinct clients (separate source
# ports) land on both endpoints, and repeated messages from the SAME
# client always land on whichever endpoint its first packet picked.
port_udp_rr=$((port + 91))
port_udp_rr_listen=$((port + 92))
"$binary" --port "$port_udp_rr" --udp-listen "$port_udp_rr_listen" \
  --udp-upstream "127.0.0.1:$portUdpA" --udp-upstream "127.0.0.1:$portUdpB" \
  --udp-session-idle 3 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_udp_rr/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket

def roundtrip(sock, payload):
    sock.settimeout(3)
    sock.sendto(payload, ('127.0.0.1', $port_udp_rr_listen))
    data, _ = sock.recvfrom(4096)
    return data

s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
r1 = roundtrip(s1, b'hello-1')
r2 = roundtrip(s2, b'hello-2')
assert {r1, r2} == {b'A:hello-1', b'B:hello-2'}, (r1, r2)
r1b = roundtrip(s1, b'hello-1b')
r1c = roundtrip(s1, b'hello-1c')
label1 = r1.split(b':')[0]
assert r1b == label1 + b':hello-1b' and r1c == label1 + b':hello-1c', (r1b, r1c)
s1.close()
s2.close()
print('udp: round_robin across clients + per-session stickiness ok')
"
curl --fail --silent "http://127.0.0.1:$port_udp_rr/metrics" \
  | grep -qE '^magnus_udp_sessions_total [1-9][0-9]*$'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# ip_hash: fresh sessions (separate sockets, same source IP) all land on
# the same endpoint -- keyed on client IP alone, same rendezvous-hashing
# primitive every other cluster in this file already reuses.
port_udp_ih=$((port + 93))
port_udp_ih_listen=$((port + 94))
"$binary" --port "$port_udp_ih" --udp-listen "$port_udp_ih_listen" \
  --udp-upstream "127.0.0.1:$portUdpA" --udp-upstream "127.0.0.1:$portUdpB" \
  --udp-lb-policy ip_hash 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_udp_ih/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket

def once():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(b'probe', ('127.0.0.1', $port_udp_ih_listen))
    data, _ = s.recvfrom(4096)
    s.close()
    return data.split(b':')[0]

labels = {once() for _ in range(4)}
assert len(labels) == 1, labels
print('udp: ip_hash same-client determinism ok')
"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Session cap (roadmap 3d's own "Section 12" memory bound): with
# udp-max-sessions capped at 2, a 3rd and 4th distinct client are simply
# dropped -- never evicting an already-active session to make room (see
# magnus_udp_session_t's own comment on why eviction itself would be a
# denial-of-service primitive against a trivially source-spoofable
# protocol).
port_udp_cap=$((port + 95))
port_udp_cap_listen=$((port + 96))
"$binary" --port "$port_udp_cap" --udp-listen "$port_udp_cap_listen" \
  --udp-upstream "127.0.0.1:$portUdpA" --udp-max-sessions 2 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_udp_cap/healthz" >/dev/null && break
  sleep 1
done
python3 -c "
import socket

ok = 0
dropped = 0
for i in range(4):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    s.sendto(f'client{i}'.encode(), ('127.0.0.1', $port_udp_cap_listen))
    try:
        s.recvfrom(4096)
        ok += 1
    except socket.timeout:
        dropped += 1
    s.close()
assert ok == 2, ok
assert dropped == 2, dropped
print('udp: max-sessions cap (drop, never evict) ok')
"
curl --fail --silent "http://127.0.0.1:$port_udp_cap/metrics" \
  | grep -qE '^magnus_udp_sessions_active 2$'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
kill -TERM "$backend18_pid" 2>/dev/null
wait "$backend18_pid" 2>/dev/null || true
backend18_pid=
kill -TERM "$backend19_pid" 2>/dev/null
wait "$backend19_pid" 2>/dev/null || true
backend19_pid=
echo "udp: UDP passthrough (round_robin/stickiness/ip_hash/session-cap) ok"

# Phase 4 (roadmap): a real ngtcp2 handshake, then real HTTP/3 requests
# against magnus's own QUIC listener's static-file (4b) and /healthz//
# /metrics (4c) dispatch, using the in-repo tests/quic-handshake-check.c
# client (see its own file header, and docs/phase4-spike-results.md for
# the external-reference-client verification this automated version
# followed up on). No proxy dispatch or compression over h3 yet -- see
# src/magnus_quic.h.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 1 -subj '/CN=localhost' \
  -keyout "$web_root/quic-server.key" -out "$web_root/quic-server.crt" \
  2>>"$log"
printf '%s\n' 'magnus quic static file' >"$web_root/quic-hello.txt"
# Position-dependent content, not a repeated byte -- this is the exact
# shape that caught a real bug the hard way (magnus_quic.c's own
# magnus_quic_stream_t comment): a chunked read_data callback let bytes
# get silently skipped/reordered while the total length stayed correct,
# which a same-byte-repeated fixture could never have caught since any
# reordering of identical bytes is indistinguishable. seq 1 5000 is
# ~150 KB, comfortably more than one packet and more than
# src/magnus_quic.c's own former per-chunk buffer size was.
for line_number in $(seq 1 5000); do
  printf 'line-%05d-abcdefghijklmnopqrstuvwxyz\n' "$line_number"
done >"$web_root/quic-large.txt"
# Phase 4e fixtures: a compressible (text/html) file well above the
# 256-byte minimum, and a binary (image/png) one of the same rough
# size -- the same shape the existing h1/h2 compression test above
# uses, so all three protocols are exercised against comparable
# fixtures.
for line_number in $(seq 1 200); do
  printf '<p>magnus quic compression regression line %s</p>\n' "$line_number"
done >"$web_root/quic-compress.html"
printf '\211PNG\r\n\032\nnot-really-an-image-but-a-binary-mime-type\n' \
  >"$web_root/quic-compress.png"
port_quic=$((port + 100))
port_quic_udp=$((port + 101))
"$binary" --port "$port_quic" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_udp" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_quic/healthz" >/dev/null && break
  sleep 1
done
quic_small_out=$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_udp" /quic-hello.txt)
printf '%s\n' "$quic_small_out" | grep -qE '^status: 200$'
printf '%s\n' "$quic_small_out" | tail -n +3 \
  | diff - "$web_root/quic-hello.txt"
# The large-file, byte-exact regression check for the bug described
# above.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-large.txt | tail -n +3 | diff - "$web_root/quic-large.txt"
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-does-not-exist.txt | grep -qE '^status: 404$'
# Phase 4c: /healthz and /metrics, sharing magnus_build_metrics() with
# the HTTP/1.1 and HTTP/2 paths (magnus_static.h) -- checked for real
# content, not just status, so a future change that made this endpoint
# return the *wrong* body without erroring would still fail here.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /healthz > "$web_root/quic-healthz-out"
grep -qE '^status: 200$' "$web_root/quic-healthz-out"
tail -n +3 "$web_root/quic-healthz-out" | grep -qE '^magnus: ok$'
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /metrics > "$web_root/quic-metrics-out"
grep -qE '^status: 200$' "$web_root/quic-metrics-out"
tail -n +3 "$web_root/quic-metrics-out" \
  | grep -qE '^magnus_requests_total [0-9]+$'
# A second, independent connection after the first's already been torn
# down exercises the listener handling that cleanly, not just a
# first-ever accept path.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-hello.txt | grep -qE '^status: 200$'
# Phase 4e: HTTP/3 static-file gzip compression, sharing
# magnus_accepts_gzip()/magnus_content_type_compressible()/
# magnus_gzip_compress() (src/magnus_compression.h) with the HTTP/1.1
# and HTTP/2 static paths -- same 256B..8MiB eligibility window, same
# compressible-MIME-type gate, same Vary: Accept-Encoding.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-compress.html gzip > "$web_root/quic-compress-gzip-out"
grep -qE '^status: 200$' "$web_root/quic-compress-gzip-out"
grep -qE '^content-encoding: gzip$' "$web_root/quic-compress-gzip-out"
grep -qiE '^vary: Accept-Encoding$' "$web_root/quic-compress-gzip-out"
tail -n +5 "$web_root/quic-compress-gzip-out" | gunzip \
  | diff - "$web_root/quic-compress.html"
# Without Accept-Encoding: gzip, the same resource comes back
# uncompressed -- negotiation actually depends on the request, not a
# blanket "always compress compressible types."
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-compress.html > "$web_root/quic-compress-plain-out"
grep -qE '^status: 200$' "$web_root/quic-compress-plain-out"
! grep -q '^content-encoding:' "$web_root/quic-compress-plain-out"
tail -n +3 "$web_root/quic-compress-plain-out" \
  | diff - "$web_root/quic-compress.html"
# A binary MIME type stays uncompressed even when the client offers
# gzip -- the content-type gate, not just the Accept-Encoding one.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-compress.png gzip > "$web_root/quic-compress-png-out"
grep -qE '^status: 200$' "$web_root/quic-compress-png-out"
! grep -q '^content-encoding:' "$web_root/quic-compress-png-out"
# Roadmap 2a-5: zstd, negotiated identically to gzip above -- same
# eligibility window/gate, just a different encoder/Content-Encoding.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-compress.html zstd > "$web_root/quic-compress-zstd-out"
grep -qE '^status: 200$' "$web_root/quic-compress-zstd-out"
grep -qE '^content-encoding: zstd$' "$web_root/quic-compress-zstd-out"
grep -qiE '^vary: Accept-Encoding$' "$web_root/quic-compress-zstd-out"
tail -n +5 "$web_root/quic-compress-zstd-out" | zstd -dc \
  | diff - "$web_root/quic-compress.html"
# Roadmap 2a-6: Brotli ("br"), same eligibility window/gate again.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_udp" \
  /quic-compress.html br > "$web_root/quic-compress-brotli-out"
grep -qE '^status: 200$' "$web_root/quic-compress-brotli-out"
grep -qE '^content-encoding: br$' "$web_root/quic-compress-brotli-out"
grep -qiE '^vary: Accept-Encoding$' "$web_root/quic-compress-brotli-out"
tail -n +5 "$web_root/quic-compress-brotli-out" | brotli -dc \
  | diff - "$web_root/quic-compress.html"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4c: admin channel isolation extended to the QUIC listener, same
# access-control boundary the main TCP listener already applies
# (roadmap 1e-4) -- /metrics withdrawn (falls through to the static
# path, 404s the same as any other nonexistent path), /healthz stays
# public.
port_quic_admin=$((port + 102))
port_quic_admin_udp=$((port + 103))
"$binary" --port "$port_quic_admin" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_admin_udp" \
  --admin-socket "$web_root/quic-admin.sock" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_quic_admin/healthz" >/dev/null \
    && break
  sleep 1
done
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_admin_udp" \
  /metrics | grep -qE '^status: 404$'
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_admin_udp" \
  /healthz | grep -qE '^status: 200$'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4d: HTTP/3 "/proxy" dispatch relayed to a real HTTP/1.1
# upstream -- the literal "/proxy" prefix stripped before forwarding
# (magnus_quic_proxy_start()'s own documented contract, matching
# magnus_proxy_pick_and_start()'s identical one for h1/h2), a
# byte-exact large streamed response (the same shape of fixture that
# caught 4b's own real bug, exercising this increment's backpressure/
# resume_stream path under real load), the backend's own 404 relayed
# through unmodified, and a clean 502 (plus the passive-health signal
# it feeds) when no backend is reachable at all.
port_quic_proxy_upstream=$((port + 104))
python3 -c "
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            # magnus's own active health check (magnus_health_tick(),
            # default path "/", expected status 200) probes this backend
            # on its own schedule, independent of and concurrent with
            # this script's own proxy requests -- answering it here
            # keeps that probe passing so it cannot spuriously flip the
            # endpoint unhealthy (magnus_cluster_result()'s own
            # failure_threshold counts active-check failures and this
            # script's own deliberate 502 case together) and race the
            # explicit backend-kill/502 assertion below.
            body = b'ok\n'
        elif self.path == '/quic-proxy-small.txt':
            body = b'magnus quic proxy file\n'
        elif self.path == '/quic-proxy-large.txt':
            body = b''.join(
                f'proxy-line-{n:05d}-abcdefghijklmnopqrstuvwxyz\n'.encode()
                for n in range(1, 5001))
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

http.server.HTTPServer(('127.0.0.1', $port_quic_proxy_upstream), Handler) \
    .serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent \
    "http://127.0.0.1:$port_quic_proxy_upstream/quic-proxy-small.txt" \
    >/dev/null && break
  sleep 1
done
port_quic_proxy=$((port + 105))
port_quic_proxy_udp=$((port + 106))
"$binary" --port "$port_quic_proxy" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_proxy_udp" \
  --upstream "127.0.0.1:$port_quic_proxy_upstream" \
  --health-check-failure-threshold 1 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_quic_proxy/healthz" >/dev/null \
    && break
  sleep 1
done
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_proxy_udp" \
  /proxy/quic-proxy-small.txt > "$web_root/quic-proxy-small-out"
grep -qE '^status: 200$' "$web_root/quic-proxy-small-out"
# tail -n +4, not +3: no client-presented cookie means a proxy-dispatched
# response now always issues one (roadmap 4h), adding a set-cookie
# line ahead of the body.
tail -n +4 "$web_root/quic-proxy-small-out" \
  | grep -qE '^magnus quic proxy file$'
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_proxy_udp" \
  /proxy/quic-proxy-large.txt > "$web_root/quic-proxy-large-out"
grep -qE '^status: 200$' "$web_root/quic-proxy-large-out"
python3 -c "
for n in range(1, 5001):
    print(f'proxy-line-{n:05d}-abcdefghijklmnopqrstuvwxyz')
" > "$web_root/quic-proxy-large-expected"
tail -n +4 "$web_root/quic-proxy-large-out" \
  | diff - "$web_root/quic-proxy-large-expected"
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_proxy_udp" \
  /proxy/quic-proxy-does-not-exist.txt | grep -qE '^status: 404$'
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_proxy_udp" \
  /proxy/quic-proxy-small.txt | grep -qE '^status: 502$'
curl -k --fail --silent "https://127.0.0.1:$port_quic_proxy/metrics" \
  | grep -qE '^magnus_upstream_healthy\{endpoint="127\.0\.0\.1:'"$port_quic_proxy_upstream"'"\} 0$'
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4f: the `route` table (host/path-prefix/method/header/
# header_prefix/cookie/query/source-CIDR matching, src/magnus_route.h)
# over HTTP/3, sharing magnus_route_matches() and magnus_routes[]/
# magnus_route_count (src/magnus_static.h) with HTTP/1.1 and HTTP/2 --
# condition-kind coverage itself (header/cookie/query/source_cidr, each
# already exercised for h1/h2 above and unit-tested directly in
# tests/test-route.c) is not re-proven per protocol; this block proves
# the *wiring*: a multi-condition route reaches the shared upstream
# cluster with the correct (unstripped) forward path, action=deny
# still denies, and action=grpc still answers its explicit 505 rather
# than silently falling through to static/proxy.
port_quic_route_upstream=$((port + 107))
python3 -c "
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ('route-matched path=' + self.path).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

http.server.HTTPServer(('127.0.0.1', $port_quic_route_upstream), Handler) \
    .serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent \
    "http://127.0.0.1:$port_quic_route_upstream/route-target" >/dev/null \
    && break
  sleep 1
done
port_quic_route=$((port + 108))
port_quic_route_udp=$((port + 109))
"$binary" --port "$port_quic_route" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_route_udp" \
  --upstream "127.0.0.1:$port_quic_route_upstream" \
  --grpc-upstream "127.0.0.1:$((port_quic_route_upstream + 500))" \
  --route "host=localhost; path_prefix=/route-target; action=proxy" \
  --route "path_prefix=/blocked; action=deny" \
  --route "path_prefix=/grpc-test; action=grpc" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_route/healthz" \
    >/dev/null && break
  sleep 1
done
# The route-matched request carries no literal "/proxy" prefix at all --
# only a matched route's own action=proxy gets it there, and with the
# *whole* target forwarded unstripped (matching
# magnus_proxy_pick_and_start()'s documented h1/h2 precedent), not a
# "/route-target"-with-something-stripped path.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_route_udp" \
  /route-target > "$web_root/quic-route-proxy-out"
grep -qE '^status: 200$' "$web_root/quic-route-proxy-out"
# tail -n +4, not +3 -- see the identical +4 note on the 4d proxy tests
# above (roadmap 4h's own unconditional set-cookie line).
tail -n +4 "$web_root/quic-route-proxy-out" \
  | grep -qE '^route-matched path=/route-target$'
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_route_udp" \
  /blocked | grep -qE '^status: 403$'
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_route_udp" \
  /grpc-test | grep -qE '^status: 505$'
# A path matching none of the three routes above still falls through to
# ordinary static dispatch, exactly as if the route table were empty.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_route_udp" \
  /quic-route-does-not-exist.txt | grep -qE '^status: 404$'
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4g: retry-on-connect-failure -- the first endpoint refuses
# every connection, so a request must transparently retry against the
# second (live) endpoint and still complete successfully instead of
# surfacing 502, mirroring M3's own identical h1/h2 retry budget
# (magnus_proxy_connect_failed()/magnus_h2_proxy_connect_failed(), same
# MAGNUS_PROXY_MAX_ATTEMPTS=2 -- see magnus_quic_proxy_start()'s and
# magnus_quic_proxy_fail()'s own comments for the synchronous/
# asynchronous split this mirrors).
port_quic_retry_upstream=$((port + 110))
port_quic_retry_dead=$((port + 111))
python3 -c "
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'good backend'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

http.server.HTTPServer(('127.0.0.1', $port_quic_retry_upstream), Handler) \
    .serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_quic_retry_upstream/" \
    >/dev/null && break
  sleep 1
done
port_quic_retry=$((port + 112))
port_quic_retry_udp=$((port + 113))
"$binary" --port "$port_quic_retry" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_retry_udp" \
  --upstream "127.0.0.1:$port_quic_retry_dead" \
  --upstream "127.0.0.1:$port_quic_retry_upstream" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_retry/healthz" \
    >/dev/null && break
  sleep 1
done
retried_ok=0
for attempt in 1 2 3 4; do
  "$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_retry_udp" \
    /proxy/anything | grep -qE '^status: 200$' && retried_ok=$((retried_ok + 1))
done
test "$retried_ok" -ge 1
kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4h: cookie-based session affinity -- a client with no
# MAGNUS_AFFINITY cookie gets round-robined and issued one over HTTP/3
# too; presenting that cookie back keeps every subsequent request on
# the same endpoint, and a killed sticky endpoint still fails over via
# the same connect-stage retry budget (roadmap 4g) with a refreshed
# cookie for the survivor -- mirroring M4's own identical h1/h2 test
# exactly.
port_quic_affinity_a=$((port + 114))
port_quic_affinity_b=$((port + 115))
mkdir -p "$web_root/quic-affinity-a" "$web_root/quic-affinity-b"
printf 'endpoint-a' > "$web_root/quic-affinity-a/id.txt"
printf 'endpoint-b' > "$web_root/quic-affinity-b/id.txt"
python3 -m http.server "$port_quic_affinity_a" --bind 127.0.0.1 \
  --directory "$web_root/quic-affinity-a" >/dev/null 2>&1 &
backend_pid=$!
python3 -m http.server "$port_quic_affinity_b" --bind 127.0.0.1 \
  --directory "$web_root/quic-affinity-b" >/dev/null 2>&1 &
backend2_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent "http://127.0.0.1:$port_quic_affinity_a/id.txt" \
    >/dev/null \
    && curl --fail --silent "http://127.0.0.1:$port_quic_affinity_b/id.txt" \
    >/dev/null && break
  sleep 1
done
port_quic_affinity=$((port + 116))
port_quic_affinity_udp=$((port + 117))
"$binary" --port "$port_quic_affinity" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_affinity_udp" \
  --upstream "127.0.0.1:$port_quic_affinity_a" \
  --upstream "127.0.0.1:$port_quic_affinity_b" \
  --health-check-failure-threshold 1 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_affinity/healthz" \
    >/dev/null && break
  sleep 1
done

"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_affinity_udp" /proxy/id.txt - \
  > "$web_root/quic-affinity-first-out"
sticky_cookie=$(sed -n 's/^set-cookie: \(MAGNUS_AFFINITY=[^;]*\);.*/\1/p' \
  "$web_root/quic-affinity-first-out")
test -n "$sticky_cookie"
sticky_endpoint=$(tail -1 "$web_root/quic-affinity-first-out")
for attempt in 1 2 3; do
  test "$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
    "$port_quic_affinity_udp" /proxy/id.txt - "$sticky_cookie" \
    | tail -1)" = "$sticky_endpoint"
done

# Affinity + retry budget together (roadmap 4g/4h): once the sticky
# endpoint's own backend is gone, the very same cookie must fail over
# to the surviving endpoint instead of the request failing, and the
# response must issue a refreshed cookie for it.
if [ "$sticky_endpoint" = "endpoint-a" ]; then
  kill -TERM "$backend_pid"
  wait "$backend_pid" 2>/dev/null || true
  backend_pid=
  expect_after=endpoint-b
else
  kill -TERM "$backend2_pid"
  wait "$backend2_pid" 2>/dev/null || true
  backend2_pid=
  expect_after=endpoint-a
fi
"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_affinity_udp" /proxy/id.txt - "$sticky_cookie" \
  > "$web_root/quic-affinity-failover-out"
grep -qE '^status: 200$' "$web_root/quic-affinity-failover-out"
grep -qE '^set-cookie: MAGNUS_AFFINITY=' "$web_root/quic-affinity-failover-out"
test "$(tail -1 "$web_root/quic-affinity-failover-out")" = "$expect_after"
[ -n "$backend_pid" ] && { kill -TERM "$backend_pid"
  wait "$backend_pid" 2>/dev/null || true; backend_pid=; }
[ -n "$backend2_pid" ] && { kill -TERM "$backend2_pid"
  wait "$backend2_pid" 2>/dev/null || true; backend2_pid=; }
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4i: reverse-proxy response caching for HTTP/3 proxy dispatch,
# sharing magnus_cache_lookup()/_store()/_revalidated() (src/magnus_cache.h)
# with HTTP/1.1 and HTTP/2 -- one cache, not one per protocol (proven
# below by an ordinary curl also seeing the entry an HTTP/3 request
# stored). Same fixture and same shape as the earlier M-series h1/h2
# cache test: a fresh GET goes to the upstream and gets stored, a
# repeat GET is answered entirely from the cache (X-Cache: HIT, zero
# additional hits against the fake upstream's own per-request marker),
# no-store/Set-Cookie responses are never cached, and a stale entry
# with an ETag revalidates via conditional GET (X-Cache: REVALIDATED
# on a 304, a fresh uncached response when the upstream's own content
# actually changed).
port_quic_cache_upstream=$((port + 118))
quic_cache_hits_file="$web_root/quic-cache-hits.txt"
: > "$quic_cache_hits_file"
python3 -c "
import http.server, threading

HITS_FILE = '$quic_cache_hits_file'
STATE = {'body': b'hello-v1', 'changed': False}
LOCK = threading.Lock()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _record(self):
        with LOCK, open(HITS_FILE, 'a') as f:
            f.write('x')

    def do_GET(self):
        self._record()
        with LOCK:
            body = STATE['body']
            changed = STATE['changed']
        if self.path == '/quic-cacheable':
            self.send_response(200)
            self.send_header('Cache-Control', 'max-age=60')
            self.send_header('ETag', '\"v1\"')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/quic-no-store':
            self.send_response(200)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/quic-with-cookie':
            self.send_response(200)
            self.send_header('Cache-Control', 'max-age=60')
            self.send_header('Set-Cookie', 'sess=abc')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/quic-revalidate':
            inm = self.headers.get('If-None-Match')
            if changed:
                newbody = b'hello-v2'
                self.send_response(200)
                self.send_header('Cache-Control', 'max-age=60')
                self.send_header('ETag', '\"v2\"')
                self.send_header('Content-Length', str(len(newbody)))
                self.end_headers()
                self.wfile.write(newbody)
            elif inm == '\"v1\"':
                self.send_response(304)
                self.send_header('Cache-Control', 'max-age=1')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Cache-Control', 'max-age=1')
                self.send_header('ETag', '\"v1\"')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        elif self.path == '/quic-change':
            with LOCK:
                STATE['changed'] = True
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(('127.0.0.1', $port_quic_cache_upstream), \
    Handler).serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent \
    "http://127.0.0.1:$port_quic_cache_upstream/quic-cacheable" >/dev/null \
    && break
  sleep 1
done
port_quic_cache=$((port + 119))
port_quic_cache_udp=$((port + 120))
# --health-check-interval pushed out to effectively "never, within this
# test's runtime" -- see the earlier h1/h2 cache block's own identical
# comment on why an unthrottled default corrupts the exact-hit-count
# assertions below.
"$binary" --port "$port_quic_cache" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_cache_udp" \
  --upstream "127.0.0.1:$port_quic_cache_upstream" \
  --route "path_prefix=/; action=proxy; cache=on" \
  --health-check-interval 3600 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_cache/healthz" \
    >/dev/null && break
  sleep 1
done

"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-cacheable > "$web_root/quic-cache-out1"
grep -qE '^status: 200$' "$web_root/quic-cache-out1"
! grep -q '^x-cache:' "$web_root/quic-cache-out1"
quic_cache_hits_after_first=$(wc -c < "$quic_cache_hits_file")

"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-cacheable > "$web_root/quic-cache-out2"
grep -qE '^x-cache: HIT$' "$web_root/quic-cache-out2"
test "$(tail -1 "$web_root/quic-cache-out1")" \
  = "$(tail -1 "$web_root/quic-cache-out2")"
test "$(wc -c < "$quic_cache_hits_file")" = "$quic_cache_hits_after_first"

# One shared cache, not one per protocol: an ordinary HTTP/1.1 request
# against the same running magnus instance also sees the entry HTTP/3
# just stored -- explicit Host: localhost (magnus_cache_lookup()'s own
# key is (host, target) exact match, and quic-handshake-check.c always
# sends :authority: localhost, not this connection's own 127.0.0.1:port)
# and --http1.1 (curl negotiates h2 over TLS by default when the server
# offers it, which would exercise the same cache from a different,
# already-covered protocol instead of the HTTP/1.1 this comment means).
curl -k --http1.1 --fail --silent -H "Host: localhost" \
  --dump-header "$web_root/quic-cache-h1-hdrs" --output /dev/null \
  "https://127.0.0.1:$port_quic_cache/quic-cacheable"
grep -qi '^X-Cache: HIT' "$web_root/quic-cache-h1-hdrs"
test "$(wc -c < "$quic_cache_hits_file")" = "$quic_cache_hits_after_first"

"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-no-store > "$web_root/quic-cache-no-store-1"
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-no-store > "$web_root/quic-cache-no-store-2"
! grep -q '^x-cache:' "$web_root/quic-cache-no-store-1"
! grep -q '^x-cache:' "$web_root/quic-cache-no-store-2"

"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-with-cookie > "$web_root/quic-cache-with-cookie-1"
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-with-cookie > "$web_root/quic-cache-with-cookie-2"
! grep -q '^x-cache:' "$web_root/quic-cache-with-cookie-1"
! grep -q '^x-cache:' "$web_root/quic-cache-with-cookie-2"

# Revalidation: a stale entry with an ETag is revalidated via a
# conditional GET rather than re-fetched wholesale -- X-Cache:
# REVALIDATED, identical body, on a 304; a genuinely changed upstream
# still gets a fresh, uncached response instead.
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-revalidate > "$web_root/quic-cache-reval-out1"
sleep 2
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-revalidate > "$web_root/quic-cache-reval-out2"
grep -qE '^x-cache: REVALIDATED$' "$web_root/quic-cache-reval-out2"
test "$(tail -1 "$web_root/quic-cache-reval-out1")" \
  = "$(tail -1 "$web_root/quic-cache-reval-out2")"

"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-change > /dev/null
sleep 2
"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_cache_udp" \
  /quic-revalidate > "$web_root/quic-cache-reval-out3"
! grep -q '^x-cache:' "$web_root/quic-cache-reval-out3"
test "$(tail -1 "$web_root/quic-cache-reval-out3")" = "hello-v2"

kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4j: upstream connection pooling for HTTP/3 proxy dispatch,
# sharing magnus_pool_checkout()/_checkin() (src/magnus_static.h) --
# the one shared, endpoint-keyed pool 1a already built -- with HTTP/1.1
# and HTTP/2, not a QUIC-local one. Same fixture-shape as 1a's own
# identical pool test: a backend that reports which specific TCP
# connection (by identity, assigned once per accept) each request
# arrived on. Several separate HTTP/3 requests all landing on the same
# connection id proves reuse; a plain HTTP/1.1 request landing on that
# *same* id afterward proves it is genuinely the one shared pool, not a
# second, QUIC-only one.
port_quic_pool_upstream=$((port + 121))
python3 -c "
import http.server, threading

lock = threading.Lock()
next_id = [0]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        super().setup()
        with lock:
            next_id[0] += 1
            self.conn_id = next_id[0]
    def do_GET(self):
        payload = ('id=' + str(self.conn_id)).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(('127.0.0.1', $port_quic_pool_upstream), \
    Handler).serve_forever()
" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent \
    "http://127.0.0.1:$port_quic_pool_upstream/quic-pool-x" >/dev/null && break
  sleep 1
done
port_quic_pool=$((port + 122))
port_quic_pool_udp=$((port + 123))
# --health-check-interval pushed out to effectively "never, within this
# test's runtime": magnus's own active health checker opens its own
# periodic probe connections to this same backend independent of
# anything under test here, which would otherwise consume a connection
# id that simply never appears in any of these responses -- harmless in
# principle (see 1a's own identical comment on this), but pushed out
# anyway to keep this block's own timing predictable.
"$binary" --port "$port_quic_pool" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_pool_udp" \
  --upstream "127.0.0.1:$port_quic_pool_upstream" \
  --health-check-interval 3600 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_pool/healthz" \
    >/dev/null && break
  sleep 1
done

quic_pool_baseline=$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_pool_udp" /proxy/quic-pool-x | tail -1)
for _ in 1 2 3 4 5; do
  test "$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
    "$port_quic_pool_udp" /proxy/quic-pool-x | tail -1)" \
    = "$quic_pool_baseline"
done

# One shared pool, not one per protocol: an ordinary HTTP/1.1 request
# against the same running magnus instance lands on that same pooled
# upstream connection id (-k https:// and --http1.1, not http:// --
# this instance's own --tls-cert/--tls-key make the main --port
# listener HTTPS-only, and curl negotiates h2 over TLS by default when
# the server offers it).
h1_pool_id=$(curl -k --http1.1 --fail --silent \
  "https://127.0.0.1:$port_quic_pool/proxy/quic-pool-x")
test "$h1_pool_id" = "$quic_pool_baseline"

kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4k: retry-based stateless address validation (RFC 9000 8.1.2)
# -- every QUIC connection above (4a through 4j) already went through
# a Retry round-trip transparently on every one of its own requests;
# this block is the one explicit assertion that a Retry is actually
# what happened, not merely that the requests still worked despite it.
# magnus_quic_retry_total (roadmap 4k's own new /metrics counter, see
# magnus_quic_send_retry() in src/magnus_quic.c) is incremented once
# per Retry packet actually sent, and read by the exact same
# magnus_build_metrics() every protocol's own /metrics already shares
# -- so it must read 0 before any QUIC connection has ever been
# attempted against this fresh instance, and it must have gone up by
# the time an HTTP/1.1 request reads it back afterward, proving it is
# one shared counter, not a QUIC-only one, same "one shared thing, not
# per-protocol" shape 4j's own pooling block above already proved for
# the connection pool.
port_quic_retry=$((port + 124))
port_quic_retry_udp=$((port + 125))
"$binary" --port "$port_quic_retry" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_retry_udp" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_retry/healthz" \
    >/dev/null && break
  sleep 1
done

retry_before=$(curl -k --http1.1 --fail --silent \
  "https://127.0.0.1:$port_quic_retry/metrics" \
  | sed -n 's/^magnus_quic_retry_total //p')
test "$retry_before" = 0

"$project_dir/build/quic-handshake-check" 127.0.0.1 "$port_quic_retry_udp" \
  /healthz >/dev/null

retry_after=$(curl -k --http1.1 --fail --silent \
  "https://127.0.0.1:$port_quic_retry/metrics" \
  | sed -n 's/^magnus_quic_retry_total //p')
test "$retry_after" -gt "$retry_before"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Phase 4l: connection migration / reactive path validation (RFC 9000
# 9.3). quic-handshake-check's own "migrate" mode (see its file header)
# completes one request, then rebinds to a fresh local UDP port and
# completes a SECOND, independent request over the SAME QUIC connection
# from there -- proving the read-path fix in
# magnus_quic_listener_service() (feed the packet's own actual
# recvfrom() path, not the connection's last-known one) actually lets
# ngtcp2's own PATH_CHALLENGE/PATH_RESPONSE validation run, not just
# that it compiles. magnus_quic_migration_total (the new /metrics
# counter magnus_quic_path_validation() increments) reads 0 before any
# path change and increases by the time the migrated request completes
# -- the same "shared counter, read back over HTTP/1.1" proof 4k's own
# block above already established for its own counter, applied to this
# one instead.
port_quic_migrate=$((port + 126))
port_quic_migrate_udp=$((port + 127))
"$binary" --port "$port_quic_migrate" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_migrate_udp" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_migrate/healthz" \
    >/dev/null && break
  sleep 1
done

migration_before=$(curl -k --http1.1 --fail --silent \
  "https://127.0.0.1:$port_quic_migrate/metrics" \
  | sed -n 's/^magnus_quic_migration_total //p')
test "$migration_before" = 0

migrate_status=$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_migrate_udp" /healthz - - migrate | head -1)
test "$migrate_status" = "status: 200"

migration_after=$(curl -k --http1.1 --fail --silent \
  "https://127.0.0.1:$port_quic_migrate/metrics" \
  | sed -n 's/^magnus_quic_migration_total //p')
test "$migration_after" -gt "$migration_before"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Proxy dispatch response compression, HTTP/3 (roadmap 2a-4): the third
# and final protocol -- same deferred-submission-until-compressed shape
# as h1 (2a-2)/h2 (2a-3), adapted to nghttp3's own frame-based,
# pull-driven response model (nghttp3_conn_submit_response(), deferred
# via stream->compress_pending exactly like h2's own submit_response2()
# is). Reuses compress_proxy_root's own fixture files (page.html/
# image.png/tiny.html) from the h1/h2 block above rather than
# recreating them.
port_quic_compress_proxy_upstream=$((port + 130))
port_quic_compress_proxy=$((port + 131))
port_quic_compress_proxy_udp=$((port + 132))
python3 -m http.server "$port_quic_compress_proxy_upstream" --bind 127.0.0.1 \
  --directory "$compress_proxy_root" >/dev/null 2>&1 &
backend_pid=$!
for attempt in 1 2 3 4 5; do
  curl --fail --silent \
    "http://127.0.0.1:$port_quic_compress_proxy_upstream/page.html" \
    >/dev/null && break
  sleep 1
done
"$binary" --port "$port_quic_compress_proxy" --root "$web_root" \
  --tls-cert "$web_root/quic-server.crt" --tls-key "$web_root/quic-server.key" \
  --quic-port "$port_quic_compress_proxy_udp" \
  --upstream "127.0.0.1:$port_quic_compress_proxy_upstream" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent \
    "https://127.0.0.1:$port_quic_compress_proxy/healthz" >/dev/null && break
  sleep 1
done

"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_compress_proxy_udp" /proxy/page.html gzip \
  > "$web_root/quic-compress-proxy-gzip-out"
grep -qE '^status: 200$' "$web_root/quic-compress-proxy-gzip-out"
grep -qE '^content-encoding: gzip$' "$web_root/quic-compress-proxy-gzip-out"
grep -qiE '^vary: Accept-Encoding$' "$web_root/quic-compress-proxy-gzip-out"
tail -n +6 "$web_root/quic-compress-proxy-gzip-out" | gunzip \
  | diff - "$compress_proxy_root/page.html"

"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_compress_proxy_udp" /proxy/page.html - \
  > "$web_root/quic-compress-proxy-plain-out"
grep -qE '^status: 200$' "$web_root/quic-compress-proxy-plain-out"
! grep -q '^content-encoding:' "$web_root/quic-compress-proxy-plain-out"
tail -n +4 "$web_root/quic-compress-proxy-plain-out" \
  | diff - "$compress_proxy_root/page.html"

"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_compress_proxy_udp" /proxy/image.png gzip \
  > "$web_root/quic-compress-proxy-png-out"
grep -qE '^status: 200$' "$web_root/quic-compress-proxy-png-out"
! grep -q '^content-encoding:' "$web_root/quic-compress-proxy-png-out"

"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_compress_proxy_udp" /proxy/tiny.html gzip \
  > "$web_root/quic-compress-proxy-tiny-out"
grep -qE '^status: 200$' "$web_root/quic-compress-proxy-tiny-out"
! grep -q '^content-encoding:' "$web_root/quic-compress-proxy-tiny-out"

# Roadmap 2a-5: zstd through the HTTP/3 proxy dispatch path -- same
# deferred-submission-until-compressed shape as gzip above, just a
# different encoder/Content-Encoding.
"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_compress_proxy_udp" /proxy/page.html zstd \
  > "$web_root/quic-compress-proxy-zstd-out"
grep -qE '^status: 200$' "$web_root/quic-compress-proxy-zstd-out"
grep -qE '^content-encoding: zstd$' "$web_root/quic-compress-proxy-zstd-out"
grep -qiE '^vary: Accept-Encoding$' "$web_root/quic-compress-proxy-zstd-out"
tail -n +6 "$web_root/quic-compress-proxy-zstd-out" | zstd -dc \
  | diff - "$compress_proxy_root/page.html"

# Roadmap 2a-6: Brotli through the HTTP/3 proxy dispatch path -- same
# deferred-submission-until-compressed shape as gzip/zstd above.
"$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_compress_proxy_udp" /proxy/page.html br \
  > "$web_root/quic-compress-proxy-brotli-out"
grep -qE '^status: 200$' "$web_root/quic-compress-proxy-brotli-out"
grep -qE '^content-encoding: br$' "$web_root/quic-compress-proxy-brotli-out"
grep -qiE '^vary: Accept-Encoding$' "$web_root/quic-compress-proxy-brotli-out"
tail -n +6 "$web_root/quic-compress-proxy-brotli-out" | brotli -dc \
  | diff - "$compress_proxy_root/page.html"

kill -TERM "$backend_pid"
wait "$backend_pid" 2>/dev/null || true
backend_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

# Real IP, HTTP/3 (roadmap 2b, extended here): Forwarded/X-Forwarded-For
# resolution reaching source_cidr route matching over QUIC -- the exact
# same config-file-mode proof (a resolved address makes a denied
# source_cidr reachable/unreachable) the HTTP/1.1 realip block above
# already gives, now for HTTP/3. PROXY protocol v1/v2 has no QUIC
# analogue and stays untested here for that same reason (see
# magnus_quic_stream_t's own effective_client_address comment).
port_quic_realip=$((port + 133))
port_quic_realip_udp=$((port + 134))
quic_realip_root="$web_root/quic-realip"
mkdir -p "$quic_realip_root"
printf '%s\n' 'quic realip ok' >"$quic_realip_root/hello.txt"
quic_realip_config="$web_root/quic-realip.conf"
cat > "$quic_realip_config" <<EOF
port = $port_quic_realip
root = $quic_realip_root
tls_cert = $web_root/quic-server.crt
tls_key = $web_root/quic-server.key
quic_listen = $port_quic_realip_udp
trusted_proxies = 127.0.0.1/32
route = source_cidr=9.9.9.0/24; action=deny
EOF
"$binary" --config "$quic_realip_config" 2>>"$log" &
server_pid=$!
for attempt in 1 2 3 4 5; do
  curl -k --fail --silent "https://127.0.0.1:$port_quic_realip/healthz" \
    >/dev/null && break
  sleep 1
done

# X-Forwarded-For from a trusted peer resolves and reaches routing: a
# denied source_cidr becomes reachable through the header, proving this
# is real request-time resolution over QUIC, not just an access-log
# cosmetic.
test "$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_realip_udp" /hello.txt - - - 9.9.9.9 | head -1)" \
  = "status: 403"
test "$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_realip_udp" /hello.txt - - - 1.2.3.4 | tail -1)" \
  = "quic realip ok"
# No X-Forwarded-For at all: routes against the raw QUIC peer address
# (127.0.0.1 here), which the deny CIDR does not match either.
test "$("$project_dir/build/quic-handshake-check" 127.0.0.1 \
  "$port_quic_realip_udp" /hello.txt | tail -1)" = "quic realip ok"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
echo "quic: handshake + HTTP/3 static/healthz/metrics GET/404, admin isolation, proxy dispatch GET/404/502 + byte-exact streamed payloads, static-file gzip compression, route table proxy/deny/grpc-505 dispatch, connect-failure retry, cookie-based session affinity, reverse-proxy response caching, upstream connection pooling, retry-based stateless address validation, connection migration/reactive path validation, proxy dispatch response compression, Real-IP-aware source_cidr matching ok (Phase 4b/4c/4d/4e/4f/4g/4h/4i/4j/4k/4l/2a-4/2b, see src/magnus_quic.h)"
