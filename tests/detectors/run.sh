#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/../.."
make build/tests/detectors/test_detectors
exec build/tests/detectors/test_detectors
