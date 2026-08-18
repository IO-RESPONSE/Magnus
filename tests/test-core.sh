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

# M2: upstream response headers are sanitized -- hop-by-hop headers dropped,
# framing normalized to a single Connection: close, via marker present.
proxy_headers=$(curl --fail --silent --dump-header - --output /dev/null \
  "http://127.0.0.1:$port/proxy/hello.txt")
test "$(printf '%s' "$proxy_headers" | grep -ic '^Connection:')" = 1
printf '%s' "$proxy_headers" | grep -qi '^Connection: close'
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
