# Native scan performance, 2026-11-02

These synthetic measurements cover Briar's current limited CLI, not the unfinished
TruffleHog migration. All six workloads produced stable, identical complete JSON
findings. Small scans benefit substantially from lower startup cost; the larger
scan gives a more conservative result. These are not universal throughput ratios.

| Workload | Files | Selected detectors | Findings | Briar median | TruffleHog median | Speedup |
|---|---:|---:|---:|---:|---:|---:|
| 8 MiB Abyssale, broad selection | 128 | 891 | 128 | 60.3 ms | 987.0 ms | 16.37x |
| 8 MiB Abyssale, narrow selection | 128 | 1 | 128 | 56.1 ms | 980.9 ms | 17.49x |
| 8 MiB mixed source | 128 | 891 | 176 | 63.3 ms | 1008.0 ms | 15.92x |
| 8 MiB mixed encoded | 128 | 891 | 176 | 71.5 ms | 1013.6 ms | 14.17x |
| 8 MiB dense keywords, no valid secrets | 128 | 891 | 0 | 159.8 ms | 1014.0 ms | 6.35x |
| 128 MiB mixed source | 2048 | 891 | 2816 | 661.9 ms | 1258.6 ms | 1.90x |

AMD Ryzen Threadripper 7960X; pinned TruffleHog 3.97.2 with 16 workers versus
serial Briar. Each row uses five measured runs after one warmup, alternating
execution order, warm filesystem cache, network isolation, fresh empty HOME,
and verification disabled. Wall time includes startup, namespace setup and JSON
output. Every file is exactly 64 KiB, within the unchanged source cap.

[Machine-readable evidence](2026-11-02-performance.json) retains individual runs,
corpus hashes, the detector selection and hashes of the tested source and binary.
The tested worktree is based on `f83a96a`; all rows use the same native binary.
Recorded RSS is the child's fork/exec and namespace high-water, not an isolated
scanner working set: inherited runner pages particularly affect the large corpus.
Do not interpret those RSS values as deployment memory requirements.

The main changes are a shared keyword automaton, optional ASCII-prefix regex JIT,
faster decoder scans, exact false-positive candidate rejection and hashed result
identities. Filtering, keyword windows and first-result ordering remain intact;
non-ASCII prefix matching keeps the compatibility path. No detector coverage,
source-limit or verification changes are represented by these speedups.

## Reproduce

Run this from the repository root to generate the synthetic inputs under ignored
`state/`. It uses the committed synthetic fixtures, not live credentials:

```sh
direnv exec . python3 - <<'PY'
import base64, sys
from pathlib import Path
sys.path.insert(0, 'tests')
import cli_reference
cases = {c[0]: c[1] for c in cli_reference.fixtures()}
names = ['abyssale_normal', 'abuseipdb_normal', 'adafruitio_normal',
         'pool_positive_mailgun_stdin', 'pool_positive_openai_stdin',
         'pool_positive_pinecone_stdin', 'pool_positive_snykkey_stdin',
         'pool_positive_sendgrid_stdin']
root = Path('state/performance-repro')
for name in ('original', 'mixed-source', 'mixed-encoded', 'keyword-dense'):
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    for i in range(128):
        line = b'function calculateValue(input) { return input + 17; }\n'
        if name == 'original': line = b'~'
        if name == 'keyword-dense':
            line = b'abyssale abuseipdb adafruit mailgun openai pinecone snyk sendgrid\n'
        filler = (line * (65536 // len(line) + 1))[:65536]
        value = cases['abyssale_normal' if name == 'original' else names[i % 8]]
        if name == 'mixed-encoded':
            value = base64.b64encode(value) if i % 2 else ''.join('\\u%04x' % c for c in value).encode()
        prefix = filler[:512] + b'\n' + value + b'\n'
        payload = filler if name == 'keyword-dense' else prefix + filler[:65536-len(prefix)]
        (directory / f'{i:03d}.txt').write_bytes(payload)
large = root / 'mixed-source-128mib-files'
large.mkdir(exist_ok=True)
for i in range(2048):
    (large / f'{i:04d}.txt').write_bytes((root / 'mixed-source' / f'{i % 128:03d}.txt').read_bytes())
PY

direnv exec . flock state/build.lock bash -eu -c '
  make -s -j4 all
  selectors=$(python3 -c '\''import json; print(json.load(open("docs/benchmarks/2026-11-02-performance.json"))["selectors"])'\'')
  python3 tools/latency.py --corpus state/performance-repro/mixed-source-128mib-files \
    --detectors "$selectors" --runs 5 --timeout 180 --reference-concurrency 16 \
    --label throughput --out state/latency/throughput.json
'
```

Select the other generated directories to reproduce the remaining broad rows.
For the narrow row, use `original` with `--detectors 239`.
