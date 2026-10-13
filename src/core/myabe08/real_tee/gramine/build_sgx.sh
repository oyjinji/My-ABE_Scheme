#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
build_dir="${MYABE08_SGX_DEBUG_BUILD_DIR:-/tmp/myabe08-sgx-debug-build-v2}"
ra_mode="${MYABE08_SGX_REMOTE_ATTESTATION:-none}"
if [[ "$ra_mode" != none && "$ra_mode" != dcap ]]; then
  echo "unsupported Gramine remote-attestation mode" >&2
  exit 2
fi
if [[ "$ra_mode" == dcap && "$build_dir" == /tmp/myabe08-sgx-debug-build-v2 ]]; then
  echo "DCAP probe requires a separate TEST build directory" >&2
  exit 2
fi
mkdir -p "$build_dir"
key="$build_dir/test-signing-key.pem"
if [ ! -e "$key" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -pkeyopt rsa_keygen_pubexp:3 -out "$key" >/dev/null 2>&1
  chmod 600 "$key"
fi
template="$repo_root/src/core/myabe08/real_tee/gramine/myabe08_tee.manifest.template"
site="$(python3.8 -B -c 'import site;print(site.getusersitepackages())')"
gramine-manifest -Drepo="$repo_root" -Dsite="$site" -Dra_mode="$ra_mode" "$template" "$build_dir/myabe08_tee.manifest"
gramine-sgx-sign --manifest "$build_dir/myabe08_tee.manifest" \
  --output "$build_dir/myabe08_tee.manifest.sgx" \
  --sigfile "$build_dir/myabe08_tee.sig" --key "$key" >/dev/null
gramine-sgx-sigstruct-view --output-format json "$build_dir/myabe08_tee.sig" > "$build_dir/sigstruct.json"
python3.8 -B - "$build_dir" "$ra_mode" <<'PY'
import hashlib,json,pathlib,sys
d=pathlib.Path(sys.argv[1]); s=json.loads((d/'sigstruct.json').read_text())
ra_mode=sys.argv[2]
manifest=(d/'myabe08_tee.manifest.sgx').read_bytes()
result={'profile':'SGX_DEBUG_GRAMINE_V1','debug':s['debug_enclave'],
        'mrenclave':s['mr_enclave'],'mrsigner':s['mr_signer'],
        'isv_prod_id':s['isv_prod_id'],'isv_svn':s['isv_svn'],
        'signed_manifest_sha256':hashlib.sha256(manifest).hexdigest(),
        'entrypoint':'core.myabe08.real_tee.service',
        'remote_attestation':ra_mode,'test_bootstrap_only':True}
(d/'build_audit.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
PY
