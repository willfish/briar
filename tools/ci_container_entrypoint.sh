#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -eo pipefail
# Generated from the pinned flake at image build time. No runtime Nix downloads.
# shellcheck disable=SC1091
source /etc/briar-test-env
set -u
export HOME=/tmp/briar-home TMPDIR=/tmp
mkdir -p "$HOME"
python3 - <<'PY'
import socket
import subprocess

if {name for _, name in socket.if_nameindex()} != {'lo'}:
    raise SystemExit('Tests require docker run --network=none')
for family in ('-4', '-6'):
    if subprocess.check_output(['ip', family, 'route', 'show', 'default']).strip():
        raise SystemExit('Tests must not have an external default route')
PY
exec "$@"
