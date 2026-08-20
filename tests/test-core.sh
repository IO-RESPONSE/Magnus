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
