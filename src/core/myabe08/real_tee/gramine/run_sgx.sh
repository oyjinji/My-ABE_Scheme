#!/usr/bin/env bash
set -euo pipefail
build_dir="${MYABE08_SGX_DEBUG_BUILD_DIR:-/tmp/myabe08-sgx-debug-build-v2}"
test -f "$build_dir/myabe08_tee.manifest.sgx"
test -f "$build_dir/myabe08_tee.sig"
cd "$build_dir"
exec gramine-sgx myabe08_tee
