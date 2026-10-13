"""Read-only, canonical source/spec/environment provenance for a run."""
from __future__ import annotations

import gc
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from urllib.request import urlopen

from .workloads import sha256_json

REPO = Path(__file__).resolve().parents[4]
SOURCE = REPO / 'src/core/myabe08'
SPEC = REPO.parents[1] / 'Doc/ABE-Scheme-08.md'
EXPECTED_SPEC_SHA256 = 'd52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85'


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def code_manifest():
    files = []
    for path in sorted(SOURCE.rglob('*')):
        if (not path.is_file() or path.is_symlink() or
            any(part in ('__pycache__', '.pytest_cache', 'artifacts') for part in path.parts) or
            path.suffix == '.pyc'):
            continue
        files.append(dict(path=path.relative_to(SOURCE).as_posix(),
                          size_bytes=path.stat().st_size, sha256=file_sha256(path)))
    return dict(source_root=str(SOURCE), files=files,
                tree_sha256=sha256_json(files))


def spec_manifest():
    digest = file_sha256(SPEC)
    if digest != EXPECTED_SPEC_SHA256:
        raise ValueError('ABE-Scheme-08 specification hash mismatch: run rejected')
    return dict(path=str(SPEC), sha256=digest)


def _git(*args):
    result = subprocess.run(('git',) + args, cwd=REPO, capture_output=True,
                            text=True, timeout=5, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def git_provenance():
    status = _git('status', '--porcelain')
    return dict(repository_path=str(REPO), head_commit=_git('rev-parse', 'HEAD'),
                branch=_git('branch', '--show-current'),
                status_porcelain=status, dirty=bool(status))


def _read(path, default=None):
    try:
        return Path(path).read_text(errors='replace').strip()
    except OSError:
        return default


def _cpuinfo():
    text = _read('/proc/cpuinfo', '')
    blocks = [x for x in text.split('\n\n') if x.strip()]
    first = dict(line.split(':', 1) for line in blocks[0].splitlines()
                 if ':' in line) if blocks else {}
    first = {key.strip(): value.strip() for key, value in first.items()}
    cores = set()
    for block in blocks:
        fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
        fields = {key.strip(): value.strip() for key, value in fields.items()}
        if 'physical id' in fields and 'core id' in fields:
            cores.add((fields['physical id'], fields['core id']))
    return dict(model_name=first.get('model name'), vendor_id=first.get('vendor_id'),
        family=first.get('cpu family'), model=first.get('model'),
        stepping=first.get('stepping'), microcode=first.get('microcode'),
        logical_cpu_count=len(blocks) or os.cpu_count(),
        physical_core_count=len(cores) if cores else None)


def _os_release():
    text = _read('/etc/os-release', '')
    result = {}
    for line in text.splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            result[key] = value.strip('"')
    return result


def _versions():
    names = {'py_ecc': 'py-ecc', 'cryptography': 'cryptography',
             'Charm': 'charm-crypto', 'PyYAML': 'PyYAML', 'numpy': 'numpy',
             'pandas': 'pandas', 'pytest': 'pytest', 'gramine': 'gramine'}
    result = {}
    for label, distribution in names.items():
        try:
            result[label] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            result[label] = 'NOT_INSTALLED'
    return result


def _gramine_version():
    try:
        result = subprocess.run(('gramine-sgx', '--version'), capture_output=True,
                                text=True, timeout=5, check=False)
        return (result.stdout or result.stderr).strip().splitlines()[0][:160]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return 'UNAVAILABLE'


def _pccs_reachable():
    try:
        with urlopen('https://localhost:8081/sgx/certification/v4/rootcacrl',
                     timeout=3) as response:
            return response.status == 200
    except Exception:
        return False


def environment_manifest(*, build_dir=None):
    os_release = _os_release()
    mem = _read('/proc/meminfo', '')
    matched = re.search(r'^MemTotal:\s+(\d+) kB', mem, re.MULTILINE)
    selected_build = Path(build_dir) if build_dir is not None else Path(
        os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                       '/tmp/myabe08-sgx-ra-probe'))
    build = selected_build / 'build_audit.json'
    try:
        audit = json.loads(build.read_text())
    except (OSError, ValueError):
        audit = {}
    cgroup = _read('/proc/1/cgroup', '')
    container = (Path('/.dockerenv').exists() or
                 any(x in cgroup for x in ('docker', 'kubepods', 'containerd')))
    return dict(os=platform.system(), os_release=os_release,
        kernel=platform.release(), architecture=platform.machine(),
        container_detected=container, cpu=_cpuinfo(),
        memory_total_bytes=int(matched.group(1)) * 1024 if matched else None,
        bios_version=_read('/sys/class/dmi/id/bios_version'),
        microcode_sysfs=_read('/sys/devices/system/cpu/cpu0/microcode/version'),
        python=dict(version=platform.python_version(), executable=sys.executable,
                    packages=_versions(), gc_enabled=gc.isenabled()),
        pairing=dict(profile='SECURITY_PROFILE_BLS12_381', curve='BLS12-381',
            backend='py_ecc', backend_version=_versions()['py_ecc'],
            security_level='approximately 128-bit classical',
            serialization_profile='MYABE08_ENCODING_V1',
            blocked_comparator='FABEO_COMPAT_PROFILE/Charm/MNT224'),
        sgx=dict(gramine_version=_gramine_version(),
            build_directory=str(selected_build.resolve()),
            device_nodes={name: Path(name).exists() for name in
                ('/dev/sgx_enclave', '/dev/sgx_provision', '/dev/isgx')},
            debug=audit.get('debug'), mrenclave=audit.get('mrenclave'),
            mrsigner=audit.get('mrsigner'),
            manifest_sha256=audit.get('signed_manifest_sha256')),
        pccs=dict(reachable=_pccs_reachable(),
                  deployment_mode='MANUAL_FROM_OFFICIAL_DEB_IN_CONTAINER',
                  cache_mode='LAZY'),
        cpu_affinity_count=len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None)


def environment_fingerprint(environment):
    return sha256_json(environment)
