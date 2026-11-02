#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build and run the implemented native integration checks without external networking."""
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('--reference', type=Path, help='pinned TruffleHog executable; run all reference comparisons too')
    scope.add_argument('--native-only', action='store_true', help='explicitly omit upstream comparisons')
    parser.add_argument('--build-dir', type=Path, default=ROOT / 'build')
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    for tool in ('make', 'unshare', 'ip', 'setpriv'):
        if not shutil.which(tool):
            parser.error(f'{tool} is required; run inside the development environment')
    reference = args.reference.resolve() if args.reference else None
    if reference and not reference.is_file():
        parser.error('reference executable does not exist')
    build = args.build_dir.resolve()
    state = ROOT / 'state'
    state.mkdir(exist_ok=True)
    # This is the same flock used by manual builds and benchmarks.
    with (state / 'build.lock').open('a') as lock, tempfile.TemporaryDirectory(prefix='integration-home-', dir=state) as home:
        fcntl.flock(lock, fcntl.LOCK_EX)
        env = {**os.environ, 'HOME': home, 'LANG': 'C.UTF-8'}
        def run(command):
            print('+ ' + ' '.join(map(str, command)), flush=True)
            subprocess.run(['unshare', '--user', '--map-root-user', '--net', 'bash', '-eu', '-c',
                            'ip link set dev lo up; exec "$@"', 'briar-integration', *map(str, command)],
                           cwd=ROOT, env=env, check=True)
        make = ['make', '-s', f'-j{args.jobs}', f'BUILD_DIR={build}']
        run([*make, 'all'])
        binary = build / 'briar'
        digest = hashlib.sha256(binary.read_bytes()).digest()
        run([*make, 'check'])
        if reference:
            run([sys.executable, ROOT / 'tests/core/cli_failures.py', binary, '--reference', reference])
            run([sys.executable, ROOT / 'tests/cli_reference.py', '--native', binary,
                 '--reference', reference, '--jobs', args.jobs])
        if hashlib.sha256(binary.read_bytes()).digest() != digest:
            raise SystemExit('native executable changed during integration checks')
    print('PASS: implemented native integration checks' +
          (' and pinned-reference comparisons' if reference else '; upstream comparisons explicitly omitted'))
    print('This is not full TruffleHog parity. See docs/INTEGRATION_TESTING.md for scope and gaps.')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode if error.returncode > 0 else 1)
