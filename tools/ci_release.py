#!/usr/bin/env python3
"""Stable release planning; publication is restricted to green master CI."""
import re
import subprocess
import sys

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


def version(tag):
    match = TAG.fullmatch(tag)
    return tuple(map(int, match.groups())) if match else None


def plan(tags, head_tags):
    stable = {tag: parsed for tag in tags if (parsed := version(tag)) is not None}
    current = {tag: parsed for tag in head_tags if (parsed := version(tag)) is not None}
    if current:
        return max(current, key=current.__getitem__)
    if not stable:
        return 'v0.1.0'
    major, minor, patch = max(stable.values())
    return f'v{major}.{minor}.{patch + 1}'


def main():
    tags = subprocess.check_output(['git', 'tag', '--list'], text=True).splitlines()
    head = subprocess.check_output(['git', 'tag', '--points-at', 'HEAD'], text=True).splitlines()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    master = subprocess.check_output(['git', 'rev-parse', 'refs/remotes/origin/master'], text=True).strip()
    # The workflow refreshes origin/master immediately before planning. A retry
    # of an older run must never mint a newer version from older source.
    stable = [tag for tag in tags if version(tag) is not None]
    latest = max(stable, key=version) if stable else None
    if commit != master or (latest and subprocess.run(
            ['git', 'merge-base', '--is-ancestor', latest, commit], check=False).returncode):
        print('Skip stale release: source must be current master and include the latest stable tag', file=sys.stderr)
        print('publish=false')
        return
    # GITHUB_OUTPUT syntax. Validated semver only, never arbitrary tag text.
    print('publish=true')
    print('tag=' + plan(tags, head))


if __name__ == '__main__':
    main()
