#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

test -s "$project_dir/README.md"
test -s "$project_dir/LICENSE"
test -s "$project_dir/THIRD_PARTY_NOTICES.md"
test -s "$project_dir/src/magnus.c"
test -s "$project_dir/src/magnus_phase.c"
test -s "$project_dir/src/magnus_phase.h"
make -C "$project_dir" clean all
printf '%s\n' 'native Magnus static project checks passed'
