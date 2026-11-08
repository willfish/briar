#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check the actual shipped image and drive its static executable offline."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_IMAGE_BYTES = 10_000_000


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    image, test_image, revision, output = sys.argv[1:]
    metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image]))[0]
    size = metadata['Size']
    if not 0 < size <= MAX_IMAGE_BYTES:
        raise SystemExit(f'Runtime image is {size} bytes; limit is {MAX_IMAGE_BYTES}')
    if metadata['Os'] != 'linux' or metadata['Architecture'] != 'amd64':
        raise SystemExit('Only the Linux amd64 release image is supported')
    if metadata['Config']['Labels']['org.opencontainers.image.revision'] != revision:
        raise SystemExit('Runtime image does not match the requested source revision')
    if metadata['Config']['User'] != '65532:65532':
        raise SystemExit('Runtime image must run as the unprivileged shipped user')
    print(f'Runtime image: {size} bytes (limit {MAX_IMAGE_BYTES})', flush=True)
    dist = Path(output).resolve()
    dist.mkdir(parents=True, exist_ok=True)
    binary = dist / 'briar'
    container = subprocess.check_output(['docker', 'create', '--platform=linux/amd64', '--network=none', image], text=True).strip()
    try:
        run(['docker', 'cp', f'{container}:/briar', str(binary)])
    finally:
        run(['docker', 'rm', container], stdout=subprocess.DEVNULL)
    # Python and OS test helpers live in the test image, never the scratch image.
    run(['docker', 'run', '--rm', '--platform=linux/amd64', '--network=none', '--read-only', '--cap-drop=ALL',
         '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,exec,size=512m',
         '--volume', f'{dist}:/artifact:ro', test_image, 'bash', '-euo', 'pipefail', '-c',
         'python3 tests/core/e2e.py /artifact/briar\n'
         'python3 tests/core/cli_failures.py /artifact/briar'])
    with tempfile.TemporaryDirectory(prefix='briar-image-') as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        token = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0'
        for name, text, expected in (
            ('clean.txt', 'ordinary source with no credential\n', 0),
            ('finding.txt', 'abyssale ' + token + '\n', 183),
        ):
            path = root / name
            path.write_text(text)
            path.chmod(0o644)
            result = subprocess.run(
                ['docker', 'run', '--rm', '--platform=linux/amd64', '--network=none', '--read-only', '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--volume', f'{root}:/src:ro', image, '--', name],
                capture_output=True, text=True, timeout=30)
            if result.returncode != expected:
                raise AssertionError(f'{name}: exit {result.returncode}, expected {expected}: {result.stderr}')
            if token in result.stdout + result.stderr or path.read_text() != text:
                raise AssertionError('Runtime hook disclosed credentials or changed its input')
            if expected and ('Abyssale' not in result.stdout or 'potential secret' not in result.stdout):
                raise AssertionError('Runtime hook omitted the expected location-only finding')
            if not expected and (result.stdout or result.stderr):
                raise AssertionError('Clean runtime hook must be quiet')
    print('PASS: shipped executable and non-root runtime image; offline, redacted, immutable inputs', flush=True)


if __name__ == '__main__':
    main()
