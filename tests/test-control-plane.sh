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
