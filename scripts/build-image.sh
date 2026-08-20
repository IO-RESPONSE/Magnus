#!/usr/bin/env bash
set -euo pipefail

image=${MAGNUS_IMAGE:-ioresponse/magnus:1.9.0}
base_image=${BASE_IMAGE:-ioresponse/glibc71-base:poc}

mkdir -p dist
docker build \
  --build-arg "BASE_IMAGE=$base_image" \
  --tag "$image" .
docker image inspect "$image" > dist/magnus-image-inspect.json
docker image save "$image" | gzip -9 > dist/magnus-image.tar.gz
docker image inspect "$image" --format \
  'image={{.RepoTags}} id={{.Id}} size={{.Size}} architecture={{.Architecture}}'
