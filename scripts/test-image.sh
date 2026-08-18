#!/usr/bin/env bash
set -euo pipefail

image=${MAGNUS_IMAGE:-ioresponse/magnus:0.2-edge}
name=magnus-image-test

cleanup() {
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" 2>&1 || true
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$name" --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1::8080 "$image" >/dev/null

for attempt in 1 2 3 4 5 6 7 8 9 10; do
  status=$(docker inspect "$name" --format '{{.State.Health.Status}}')
  [ "$status" = healthy ] && break
  sleep 2
done

test "${status:-}" = healthy
docker exec "$name" /usr/sbin/magnus --version
docker exec "$name" /lib64/ld-linux-x86-64.so.2 --list /usr/sbin/magnus
docker exec "$name" wget -q -O - http://127.0.0.1:8080/healthz
port=$(docker port "$name" 8080/tcp | sed -n 's/.*://p')
headers=$(curl --silent --show-error --dump-header - --output /dev/null \
  "http://127.0.0.1:$port/")
printf '%s' "$headers" | grep -qi '^Server: Magnus/'
printf '%s' "$headers" | grep -qi '^X-Magnus-Engine: native-c17/0.1'
printf '%s' "$headers" | grep -Eqi '^X-Magnus-Request-Id: [0-9a-f]{32}'
first_id=$(printf '%s' "$headers" | sed -n 's/^X-Magnus-Request-Id: \([0-9A-F]*\).*/\1/ip')
second_id=$(curl --silent --show-error --dump-header - --output /dev/null \
  "http://127.0.0.1:$port/" | sed -n 's/^X-Magnus-Request-Id: \([0-9A-F]*\).*/\1/ip')
test -n "$first_id"
test -n "$second_id"
test "$first_id" != "$second_id"
test "$(docker inspect "$name" --format '{{.Config.User}}')" = '65534:65534'
test "$(docker inspect "$name" --format '{{.HostConfig.ReadonlyRootfs}}')" = true
