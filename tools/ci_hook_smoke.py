#!/usr/bin/env python3
"""Real pre-commit Docker hook in a disposable consumer, using synthetic data."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(args, cwd, expected=0):
    if args[0] == 'git':
        args = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', *args[1:]]
    p = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
    if p.returncode != expected:
        raise AssertionError(f'{args[0]} exited {p.returncode}, expected {expected}:\n{p.stdout}')
    return p.stdout


def main():
    repo = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='briar-consumer-') as tmp:
        root = Path(tmp)
        run(['git', 'init', '-q'], root)
        run(['git', 'config', 'user.name', 'Briar CI'], root)
        run(['git', 'config', 'user.email', 'ci@example.invalid'], root)
        # try-repo writes a manifest referencing the exact local repository HEAD.
        (root / 'fixture.txt').write_text('ordinary source with no credential\n')
        run(['git', 'add', 'fixture.txt'], root)
        output = run(['pre-commit', 'try-repo', repo, 'briar', '--all-files'], root)
        if 'Passed' not in output:
            raise AssertionError('Clean hook did not pass: ' + output)
        # Construct a synthetic matching token, never a real provider credential.
        token = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0'
        payload = 'abyssale ' + token + '\n'
        (root / 'fixture.txt').write_text(payload)
        run(['git', 'add', 'fixture.txt'], root)
        output = run(['pre-commit', 'try-repo', repo, 'briar', '--all-files'], root, expected=1)
        if 'Failed' not in output or 'Abyssale' not in output or token in output:
            raise AssertionError('Finding outcome or redaction contract failed: ' + output)
        if (root / 'fixture.txt').read_text() != payload:
            raise AssertionError('Hook modified its input')
        print('Real repository Docker hook: clean pass, synthetic finding rejected, no credential disclosure, input unchanged')
        # Exercise pre-commit's tag selection without publishing a fake release.
        upstream = root / 'tagged-upstream'
        upstream.mkdir()
        run(['git', 'init', '-q'], upstream)
        run(['git', 'config', 'user.name', 'Briar CI'], upstream)
        run(['git', 'config', 'user.email', 'ci@example.invalid'], upstream)
        (upstream / '.pre-commit-hooks.yaml').write_text(Path(repo, '.pre-commit-hooks.yaml').read_text())
        run(['git', 'add', '.pre-commit-hooks.yaml'], upstream)
        run(['git', 'commit', '-qm', 'first hook release'], upstream)
        run(['git', 'tag', 'v0.1.0'], upstream)
        run(['git', 'commit', '--allow-empty', '-qm', 'next tested release'], upstream)
        run(['git', 'tag', 'v0.1.1'], upstream)
        consumer = root / 'tagged-consumer'
        consumer.mkdir()
        run(['git', 'init', '-q'], consumer)
        remote = upstream.as_uri()
        config = consumer / '.pre-commit-config.yaml'
        config.write_text(f'repos:\n  - repo: {remote}\n    rev: v0.1.0\n    hooks:\n      - id: briar\n')
        run(['pre-commit', 'autoupdate', '--repo', remote], consumer)
        if 'rev: v0.1.1' not in config.read_text():
            raise AssertionError('pre-commit autoupdate did not select the newer stable release tag')
        print('Real pre-commit autoupdate: v0.1.0 advanced to v0.1.1 in an isolated tagged fixture')


if __name__ == '__main__':
    main()
