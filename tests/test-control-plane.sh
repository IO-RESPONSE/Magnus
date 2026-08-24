#!/usr/bin/env bash
# Integration coverage for the M5 control plane: magnusd supervising one
# magnus child, driven by magnusctl over the Unix control socket.
# tests/test-config.c already covers magnus_config.c's schema/validation
# in isolation; this script covers the parts that only exist once magnusd
# and a real magnus process are both running.
set -euo pipefail
[ -n "${TRACE:-}" ] && set -x

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
magnus_bin="$project_dir/build/magnus"
magnusd_bin="$project_dir/build/magnusd"
magnusctl_bin="$project_dir/build/magnusctl"
port=${MAGNUS_CP_TEST_PORT:-19500}
work=$(mktemp -d)
config="$work/magnus.conf"
socket="$work/magnusd.sock"
audit="$work/audit.log"
log="$work/magnusd.log"

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    cp "$log" /tmp/magnus-test-control-plane-failure.log 2>/dev/null || true
    echo "test-control-plane.sh failed; magnusd stderr preserved at" \
         "/tmp/magnus-test-control-plane-failure.log" >&2
  fi
  if [ -n "${magnusd_pid:-}" ]; then
    kill -TERM "$magnusd_pid" >/dev/null 2>&1 || true
    wait "$magnusd_pid" 2>/dev/null || true
  fi
  pkill -f "^$magnus_bin --config $config\$" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/root"
printf 'root-v1\n' > "$work/root/hello.txt"
cat > "$config" <<EOF
port = $port
root = $work/root
EOF

ctl() { "$magnusctl_bin" "$@" --socket "$socket"; }

# magnusctl check works standalone, without any daemon running at all.
"$magnusctl_bin" check "$config" | grep -q '^OK:'
bad_config="$work/bad.conf"
printf 'port = %s\nbogus_key = x\n' "$port" > "$bad_config"
if "$magnusctl_bin" check "$bad_config" 2>/dev/null; then
  echo "expected magnusctl check to reject an unknown key" >&2
  exit 1
fi

"$magnusd_bin" --config "$config" --magnus-binary "$magnus_bin" \
  --socket "$socket" --audit-log "$audit" 2>"$log" &
magnusd_pid=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "$socket" ] && break
  sleep 1
done
test -S "$socket"

status1=$(ctl status)
printf '%s\n' "$status1" | grep -q '^OK '
printf '%s\n' "$status1" | grep -q 'last_action=start last_result=ok'
child_pid=$(printf '%s' "$status1" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
test -n "$child_pid"

test "$(curl --fail --silent "http://127.0.0.1:$port/hello.txt")" = 'root-v1'

# A live upgrade: root changes, request must reflect it after reload, and
# magnus is reloaded in place (SIGHUP), not respawned -- same pid.
mkdir -p "$work/root-v2"
printf 'root-v2\n' > "$work/root-v2/hello.txt"
staged="$work/staged.conf"
printf 'port = %s\nroot = %s\n' "$port" "$work/root-v2" > "$staged"
reload_out=$(ctl reload --config "$config" "$staged")
printf '%s\n' "$reload_out" | grep -q '^OK '
body=""
for attempt in 1 2 3 4 5; do
  body=$(curl --fail --silent "http://127.0.0.1:$port/hello.txt" || true)
  [ "$body" = 'root-v2' ] && break
  sleep 1
done
test "$body" = 'root-v2'
status2=$(ctl status)
test "$(printf '%s' "$status2" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')" = "$child_pid"

# Rejected reload (unknown key, caught locally by magnusctl -- no daemon
# round trip at all) must leave both the live config file and the running
# server untouched.
if ctl reload --config "$config" "$bad_config" 2>/dev/null; then
  echo "expected reload with an invalid staged config to fail" >&2
  exit 1
fi
grep -q "root = $work/root-v2" "$config"
test "$(curl --fail --silent "http://127.0.0.1:$port/hello.txt")" = 'root-v2'

# Rejected reload (port change -- valid config, but magnusd itself refuses
# it) must revert the config file back to what is actually running, not
# leave the rejected content in place.
bad_port_config="$work/badport.conf"
printf 'port = %s\nroot = %s\n' "$((port + 1))" "$work/root-v2" > "$bad_port_config"
reload_bad=$(ctl reload --config "$config" "$bad_port_config" || true)
printf '%s\n' "$reload_bad" | grep -q '^REJECTED'
grep -q "port = $port$" "$config"
test "$(curl --fail --silent "http://127.0.0.1:$port/hello.txt")" = 'root-v2'

# Crash detection: killing the supervised child must be noticed and
# repaired automatically, from the last successfully-applied config (so
# root-v2 survives the restart), without magnusctl's help.
kill -9 "$child_pid"
restarted_pid=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  status3=$(ctl status 2>/dev/null || true)
  candidate=$(printf '%s' "$status3" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
  if [ -n "$candidate" ] && [ "$candidate" != "$child_pid" ] \
      && kill -0 "$candidate" 2>/dev/null; then
    restarted_pid=$candidate
    break
  fi
done
test -n "$restarted_pid"
test "$(curl --fail --silent "http://127.0.0.1:$port/hello.txt")" = 'root-v2'
grep -q 'action=supervise config_hash=.* result=crashed' "$audit"
grep -q 'action=supervise config_hash=.* result=ok detail="restarted after crash"' "$audit"

# Audit log must have a complete, honest trail: the start, the successful
# reload, and the crash/restart pair. The two rejected reloads above were
# caught before ever reaching magnusd (one locally by magnusctl, one by
# magnusd without touching the child), so they are correctly absent from
# audit here -- only the port-change rejection reaches magnusd itself.
grep -q '^ts=[0-9]* actor=[^ ]* action=start .* result=ok$' "$audit"
grep -q 'action=reload .* result=ok$' "$audit"
grep -q 'action=reload .* result=rejected detail="port change' "$audit"

# Drain (roadmap 5d-1, Runtime API expansion): distinct from both
# reload (config swap, keeps accepting) and shutdown (unconditional) --
# stops accepting *new* connections while an already-open one keeps
# being served normally, and /healthz on that already-open connection
# flips to 503 so an external load balancer's own readiness probe (not
# just this process's own listener backlog) also stops routing new
# traffic here. Verified with a raw socket (not curl) specifically so
# the same TCP connection can be reused across the before/after check --
# curl's own short-lived-by-default connections cannot observe this.
python3 -c "
import socket, subprocess, time, sys

port = $port
sock_path = '$socket'
ctl_bin = '$magnusctl_bin'

s = socket.create_connection(('127.0.0.1', port), timeout=5)
s.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
before = s.recv(4096)
assert before.split(b'\r\n')[0] == b'HTTP/1.1 200 OK', before

out = subprocess.run([ctl_bin, 'drain', '--socket', sock_path],
                     capture_output=True, text=True, check=True)
assert out.stdout.startswith('OK'), out.stdout
time.sleep(1)

# same already-open connection now sees 503
s.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
after = s.recv(4096)
assert after.split(b'\r\n')[0] == b'HTTP/1.1 503 Service Unavailable', after
s.close()

# a brand-new connection is refused/times out at the listener itself
try:
    s2 = socket.create_connection(('127.0.0.1', port), timeout=2)
    s2.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
    s2.settimeout(2)
    data = s2.recv(4096)
    assert False, 'new connection during drain unexpectedly got: %r' % data
except (socket.timeout, ConnectionRefusedError, OSError):
    pass

print('drain: persistent-connection 503 + new-connection refusal ok')
"
status4=$(ctl status)
printf '%s\n' "$status4" | grep -q 'last_action=drain last_result=ok'
grep -q 'action=drain .* result=ok$' "$audit"

# The drained child is no longer reachable at all (confirmed above) --
# not itself a useful state to leave running, and it would make the
# final "magnus no longer answers after shutdown" check below
# meaningless (it already wouldn't answer, drained or not). Killing it
# lets magnusd's own crash detection (already proven above) respawn a
# fresh, non-draining child, so that final check still actually proves
# something. Capture the currently-live pid via STATUS itself here --
# not the $child_pid/$restarted_pid captured earlier in this script,
# either of which may already be stale by this point.
drained_pid=$(printf '%s' "$status4" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
test -n "$drained_pid"
kill -9 "$drained_pid" >/dev/null 2>&1 || true
respawned_pid=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  status5=$(ctl status 2>/dev/null || true)
  candidate=$(printf '%s' "$status5" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
  if [ -n "$candidate" ] && [ "$candidate" != "$drained_pid" ] \
      && kill -0 "$candidate" 2>/dev/null; then
    respawned_pid=$candidate
    break
  fi
done
test -n "$respawned_pid"
test "$(curl --fail --silent "http://127.0.0.1:$port/hello.txt")" = 'root-v2'

ctl shutdown | grep -q '^OK'
for attempt in 1 2 3 4 5; do
  kill -0 "$magnusd_pid" 2>/dev/null || break
  sleep 1
done
if kill -0 "$magnusd_pid" 2>/dev/null; then
  echo "magnusd did not stop after shutdown" >&2
  exit 1
fi
magnusd_pid=
if curl --silent --max-time 1 -o /dev/null "http://127.0.0.1:$port/healthz" 2>/dev/null; then
  echo "magnus is still answering after magnusd shutdown" >&2
  exit 1
fi
