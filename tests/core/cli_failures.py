#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise OS/process failures against the real CLI, not an embedded main()."""
import argparse
import array
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import termios
import time
import unittest

BINARY = None
REFERENCE = None
OPTIONS = ['--json', '--no-verification', '--include-detectors=239']
KEY = b'b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y4z'[:40]
SOURCE = b'abyssale ' + KEY + b'\n'


class CliFailures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='briar-cli-failures-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        home = self.directory / 'home'
        home.mkdir()
        self.env = {'HOME': str(home), 'PATH': os.environ['PATH'], 'LANG': 'C.UTF-8'}

    def invoke(self, args, *, source=SOURCE, **kwargs):
        return subprocess.run([str(BINARY), *args], input=source, capture_output=True,
                              cwd=self.directory, env=self.env, timeout=10, **kwargs)

    def failed(self, result, diagnostic):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertIn(diagnostic.encode(), result.stderr)
        self.assertNotIn(KEY, result.stderr)

    def test_argument_failures(self):
        cases = [
            ([], 'missing source command'),
            (OPTIONS, 'missing source command'),
            (['filesystem', *OPTIONS], 'requires explicit regular files'),
            (['stdin', *OPTIONS, 'unexpected-path'], 'stdin takes no paths'),
            (['stdin', *OPTIONS, '--results='], 'empty --results selection'),
            (['stdin', *OPTIONS, '--results=verified,invalid'], 'invalid --results selection'),
        ]
        for option in ('--include-detectors', '--exclude-detectors', '--results'):
            cases.append((['stdin', *OPTIONS, option], 'unsupported or incomplete CLI option'))
        for selector in ('239.x1', '239.v', '239.v2147483648', '239.v1extra'):
            cases.append((['stdin', *OPTIONS, '--include-detectors=' + selector], 'invalid detector version selector'))
        for selector in (' , \t,', '239', 'all'):
            option = '--include-detectors=' if selector.startswith(' ') else '--exclude-detectors='
            cases.append((['stdin', *OPTIONS, option + selector], 'no enabled implemented detectors selected'))
        for args, diagnostic in cases:
            with self.subTest(args=args):
                self.failed(self.invoke(args), diagnostic)

    def test_option_terminator_and_separate_values(self):
        path = self.directory / '--fail'
        path.write_bytes(SOURCE)
        result = self.invoke(['--json', '--no-verification', '--include-detectors', 'Abyssale.v0',
                              '--results', 'unverified', 'filesystem', '--', path.name])
        self.assertEqual(result.returncode, 0)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['Raw'], KEY.decode())
        self.assertEqual(path.read_bytes(), SOURCE)

    def test_filesystem_failures_rollback_earlier_findings(self):
        good = self.directory / 'good.txt'
        good.write_bytes(SOURCE)
        fifo = self.directory / 'pipe'
        os.mkfifo(fifo)
        peer = socket.socket(socket.AF_UNIX)
        self.addCleanup(peer.close)
        address = self.directory / 'socket'
        peer.bind(str(address))
        cases = [
            (self.directory / KEY.decode() / 'missing.txt', 'cannot open filesystem input parent'),
            (good / 'child', 'cannot open filesystem input parent'),
            (fifo, 'not regular'),
            (address, 'cannot open filesystem input'),
            (Path('/dev/null'), 'not regular'),
        ]
        for path, diagnostic in cases:
            with self.subTest(path=path.name):
                self.failed(self.invoke(['filesystem', str(good), str(path), *OPTIONS]), diagnostic)
                self.assertEqual(good.read_bytes(), SOURCE)

    def test_serval_offline_outputs(self):
        # Generate synthetic, non-sequential fixtures: upstream's sequential
        # examples are intentionally rejected by the engine's common FP filter.
        import random
        import zlib
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        rng = random.Random(5528)
        secrets = []
        for tag in ('pk', 'wk', 'mk'):
            payload = tag + '_' + ''.join(rng.choice(alphabet) for _ in range(43))
            crc = zlib.crc32(payload.encode())
            checksum = ''
            for _ in range(6):
                crc, digit = divmod(crc, 62)
                checksum = alphabet[digit] + checksum
            secrets.append(('svl_secret_' + payload + checksum).encode())
        options = ['--json', '--no-verification', '--include-detectors=1078']
        path = self.directory / 'serval.txt'
        for secret, kind in zip(secrets, ('public_api', 'worker', 'managed_worker')):
            with self.subTest(kind=kind):
                source = b'\nsecret="' + secret + b'"\n'
                path.write_bytes(source)
                result = self.invoke(['filesystem', *options, '--', path.name])
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['Raw'], secret.decode())
                self.assertEqual(rows[0]['RawV2'], '')
                self.assertEqual(rows[0]['SecretParts'], {'client_secret': secret.decode()})
                self.assertEqual(rows[0]['ExtraData'], {'key_type': kind})
                self.assertFalse(rows[0]['Verified'])
                self.assertIn(b'limited native slice', result.stderr)
                self.assertNotIn(secret, result.stderr)
                excluded = self.invoke(['stdin', *options, '--exclude-detectors=Serval'], source=secret)
                self.assertEqual(excluded.returncode, 1)
                self.assertEqual(excluded.stdout, b'')
                self.assertNotIn(secret, excluded.stderr)
                hook = self.invoke(['pre-commit', '--', path.name])
                self.assertEqual(hook.returncode, 183, hook.stderr)
                self.assertIn(b'Serval', hook.stdout)
                self.assertIn(b'"serval.txt":2: Serval (PLAIN)', hook.stdout)
                self.assertNotIn(secret, hook.stdout + hook.stderr)
                self.assertEqual(hook.stderr, b'')
                self.assertEqual(path.read_bytes(), source)
                # Invalid checksum must be a quiet clean hook run, not a failure.
                path.write_bytes(secret[:-1] + (b'1' if secret[-1:] == b'0' else b'0') + b'\n')
                clean = self.invoke(['pre-commit', '--', path.name])
                self.assertEqual((clean.returncode, clean.stdout, clean.stderr), (0, b'', b''))
                # Failure after an earlier finding must not print any findings.
                path.write_bytes(source)
                failure = self.invoke(['pre-commit', '--', path.name, 'missing.txt'])
                self.assertEqual(failure.returncode, 1)
                self.assertEqual(failure.stdout, b'')
                self.assertNotIn(secret, failure.stderr)

    def test_stream_large_files(self):
        path = self.directory / 'large.txt'
        for size in (65535, 65536, 65537, 71680, 74752, 2 * 1024 * 1024):
            with self.subTest(size=size):
                source = bytearray((b'.\n' * ((size + 1) // 2))[:size])
                offsets = [size - len(SOURCE)]
                if size > 74752:
                    offsets.insert(0, 7 * 10240 - 16)  # Secret crosses a content boundary after 64 KiB.
                for offset in offsets:
                    source[offset:offset + len(SOURCE)] = SOURCE
                path.write_bytes(source)
                result = self.invoke(['filesystem', *OPTIONS, '--', path.name])
                self.assertEqual(result.returncode, 0)
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual([r['Raw'] for r in rows], [KEY.decode()] * len(offsets))
                self.assertEqual([r['SourceMetadata']['Data']['Filesystem']['line'] for r in rows],
                                 [source[:offset].count(b'\n') + 1 for offset in offsets])
                hook = self.invoke(['pre-commit', '--', path.name])
                self.assertEqual(hook.returncode, 183)
                self.assertIn(f'Found {len(offsets)} potential secret'.encode(), hook.stdout)
                self.assertNotIn(KEY, hook.stdout + hook.stderr)
                self.assertEqual(path.read_bytes(), source)
        path.write_bytes(b'.\n' * (1024 * 1024))
        result = self.invoke(['pre-commit', '--', path.name])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_stream_short_pipe_reads(self):
        source = bytearray(b'.\n' * (80 * 1024))
        # Distinct keys avoid stdin's intentional first-result-wins deduplication.
        encoded = base64.b64encode(b'abyssale ' + KEY[::-1] + b'\n')
        for offset, value in ((7 * 10240 - 16, SOURCE), (9 * 10240 - 8, encoded)):
            source[offset:offset + len(value)] = value
        expected = self.invoke(['stdin', *OPTIONS], source=source)
        self.assertEqual(expected.returncode, 0)
        rows = [json.loads(line) for line in expected.stdout.splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['DecoderName'] for row in rows}, {'PLAIN', 'BASE64'})
        process = self.process(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.ready(process)
        at = 0
        while at < len(source):
            for size in (1, 13, 4091, 19, 511):
                part = source[at:at + size]
                process.stdin.write(part)
                process.stdin.flush()
                at += len(part)
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stdout, expected.stdout)

    def test_permission_denied(self):
        # A user-namespace root may still have DAC override. Drop that capability
        # rather than silently skipping this boundary when tests run as root.
        self.assertIsNotNone(shutil.which('setpriv'), 'util-linux setpriv is required')
        path = self.directory / KEY.decode()
        path.write_bytes(SOURCE)
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        result = subprocess.run(['setpriv', '--bounding-set=-dac_override,-dac_read_search',
                                 str(BINARY), 'filesystem', str(path), *OPTIONS],
                                cwd=self.directory, env=self.env, capture_output=True, timeout=10)
        self.failed(result, 'cannot open filesystem input')

    def test_stdin_read_error(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            result = subprocess.run([str(BINARY), 'stdin', *OPTIONS], stdin=fd,
                                    capture_output=True, env=self.env, timeout=10)
        finally:
            os.close(fd)
        self.failed(result, 'input read failed')

    def test_full_output_device(self):
        with open('/dev/full', 'wb') as sink:
            result = subprocess.run([str(BINARY), 'stdin', *OPTIONS], input=SOURCE,
                                    stdout=sink, stderr=subprocess.PIPE, env=self.env, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'cannot write JSON output', result.stderr)
        self.assertNotIn(KEY, result.stderr)

    def test_nonblocking_output(self):
        for used in (0, 2048, 4096):
            with self.subTest(used=used):
                read_fd, write_fd = os.pipe()
                try:
                    self.assertEqual(fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096), 4096)
                    os.set_blocking(write_fd, False)
                    os.set_blocking(read_fd, False)
                    os.write(write_fd, b'x' * used)
                    result = subprocess.run([str(BINARY), 'stdin', *OPTIONS], input=SOURCE,
                                            stdout=write_fd, stderr=subprocess.PIPE, env=self.env, timeout=10)
                    self.assertFalse(os.get_blocking(write_fd), 'scanner changed a shared descriptor flag')
                    if used == 4096:
                        self.assertEqual(result.returncode, 1)
                        self.assertIn(b'cannot write JSON output', result.stderr)
                    else:
                        # POLLOUT can be false while the last pipe page still has
                        # room for this write. Preserve actual nonblocking writes.
                        self.assertEqual(result.returncode, 0)
                        row = json.loads(os.read(read_fd, 4096)[used:])
                        self.assertEqual(row['Raw'], KEY.decode())
                finally:
                    os.close(write_fd)
                    os.close(read_fd)

    def wait_for(self, predicate, message):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail(message)

    def process(self, **kwargs):
        process = subprocess.Popen([str(BINARY), 'stdin', *OPTIONS], env=self.env,
                                   stdin=subprocess.PIPE, **kwargs)
        def finish():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        self.addCleanup(finish)
        return process

    def ready(self, process):
        self.assertTrue(select.select([process.stderr], [], [], 5)[0], 'scanner startup timed out')
        self.assertTrue(process.stderr.readline().startswith(b'briar: limited native slice'))

    def test_cancel_waiting_for_input(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                process = self.process(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.ready(process)
                # SIGTERM cancels after several scanned windows, not just a read
                # of the first window. Buffered findings must still be discarded.
                source = SOURCE if signum == signal.SIGINT else SOURCE + b'.\n' * 65536
                process.stdin.write(source)
                process.stdin.flush()  # Keep stdin open, including after cancellation.
                self.assertFalse(select.select([process.stdout], [], [], 0.1)[0])
                process.send_signal(signum)
                process.wait(timeout=5)
                stdout, stderr = process.communicate(timeout=5)
                self.failed(subprocess.CompletedProcess([], process.returncode, stdout, stderr), 'context canceled')

    def test_cancel_blocked_stdout(self):
        source = b''.join(b'abyssale ' + hashlib.sha256(f'integration-{i}'.encode()).hexdigest()[:40].encode()
                          + b'\n' for i in range(150))
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                process = self.process(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.ready(process)
                process.stdin.write(source)
                process.stdin.close()
                process.stdin = None
                def blocked():
                    available = array.array('i', [0])
                    fcntl.ioctl(process.stdout, termios.FIONREAD, available, True)
                    channel = Path(f'/proc/{process.pid}/wchan').read_text()
                    # Pipe page slots can fill before its nominal byte capacity.
                    # After output starts and stdin closes, this wait is output I/O.
                    return available[0] > 0 and ('poll' in channel or 'pipe_write' in channel)
                self.wait_for(blocked, 'scanner did not block on its output pipe')
                process.send_signal(signum)
                process.wait(timeout=5)  # Do not drain stdout to rescue a stuck writer.
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 1)
                self.assertTrue(stdout)  # Output failures cannot retract bytes already written.
                self.assertIn(b'cannot write JSON output', stderr)

    def test_cancel_blocked_stderr(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                read_fd, write_fd = os.pipe()
                try:
                    os.set_blocking(write_fd, False)
                    while True:
                        try:
                            os.write(write_fd, b'x' * 4096)
                        except BlockingIOError:
                            break
                    os.set_blocking(write_fd, True)
                    process = self.process(stdout=subprocess.PIPE, stderr=write_fd)
                    def handlers_installed():
                        status = Path(f'/proc/{process.pid}/status').read_text()
                        caught = int(next(line.split()[1] for line in status.splitlines()
                                          if line.startswith('SigCgt:')), 16)
                        return bool(caught & (1 << (signum - 1)))
                    self.wait_for(handlers_installed, 'cancellation handler was not installed')
                    process.send_signal(signum)
                    process.wait(timeout=5)
                    stdout, _ = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 1)
                    self.assertEqual(stdout, b'')
                finally:
                    os.close(write_fd)
                    os.close(read_fd)

    def test_findings_exit_status(self):
        for source, extra, expected in (
            (SOURCE, [], 183), (b'', [], 0), (SOURCE, ['--results=verified'], 0),
            (SOURCE, ['--results=unverified'], 183),
        ):
            with self.subTest(extra=extra, empty=not source):
                result = self.invoke([*OPTIONS, '--fail', *extra, 'stdin'], source=source)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(bool(result.stdout), expected == 183)

    def test_pre_commit_safe_findings(self):
        for name in ('--fail', 'with spaces.txt', 'with\nnewline.txt', 'with\x1b[31mescape.txt'):
            with self.subTest(name=name):
                path = self.directory / name
                path.write_bytes(SOURCE)
                result = self.invoke(['pre-commit', '--', name])
                self.assertEqual(result.returncode, 183)
                self.assertNotIn(KEY, result.stdout + result.stderr)
                self.assertEqual(result.stderr, b'')
                self.assertEqual(result.stdout.decode().splitlines(), [
                    'Found 1 potential secret (offline, not verified):',
                    f'  {json.dumps(name)}:1: Abyssale (PLAIN)', '',
                    'Remove real credentials, stage the changes, and retry. Credential values are hidden.',
                ])
                machine = self.invoke(['pre-commit', '--json', '--', name])
                self.assertEqual(machine.returncode, 183)
                self.assertNotIn(KEY, machine.stdout + machine.stderr)
                rows = [json.loads(line) for line in machine.stdout.splitlines()]
                self.assertEqual(len(rows), 1)
                self.assertEqual(set(rows[0]), {'SourceMetadata', 'DetectorType', 'DetectorName', 'DecoderName'})
                self.assertEqual(rows[0]['DetectorName'], 'Abyssale')
                self.assertEqual(rows[0]['SourceMetadata']['Data']['Filesystem'], {'file': name, 'line': 1})
                self.assertEqual(path.read_bytes(), SOURCE)
        (self.directory / 'clean.txt').write_bytes(b'ordinary text\n')
        for extra in ([], ['--json']):
            result = self.invoke(['pre-commit', *extra, '--', 'clean.txt'])
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_pre_commit_guards(self):
        (self.directory / 'secret.txt').write_bytes(SOURCE)
        for extra, diagnostic in (
            (['--results=verified'], 'result suppression'),
            (['--filter-unverified'], 'result suppression'),
            (['--include-detectors='], 'explicit --include-detectors'),
            (['--include-detectors=all'], 'all-detector scans are unavailable'),
            (['--exclude-detectors=all'], 'no enabled implemented detectors'),
            (['--include-detectors=notimplemented'], 'unknown detector'),
        ):
            with self.subTest(extra=extra):
                self.failed(self.invoke(['pre-commit', *extra, '--', 'secret.txt']), diagnostic)
        result = self.invoke(['pre-commit', '--include-detectors=239', '--json', '--', 'secret.txt'])
        self.assertEqual(result.returncode, 183)
        self.assertNotIn(KEY, result.stdout + result.stderr)
        result = self.invoke(['pre-commit', '--exclude-detectors=239', '--', 'secret.txt'])
        self.assertEqual((result.returncode, result.stdout), (0, b''))
        self.failed(self.invoke(['pre-commit']), 'requires explicit regular files')

    def test_pre_commit_rollback(self):
        (self.directory / 'secret.txt').write_bytes(b'.\n' * 65536 + SOURCE)
        (self.directory / 'link.txt').symlink_to('secret.txt')
        for name in ('missing.txt', 'link.txt'):
            for extra in ([], ['--json']):
                with self.subTest(name=name, extra=extra):
                    self.failed(self.invoke(['pre-commit', *extra, '--', 'secret.txt', name]), 'cannot open')

    def test_pre_commit_full_output_device(self):
        (self.directory / 'secret.txt').write_bytes(SOURCE)
        with open('/dev/full', 'wb') as sink:
            result = subprocess.run([str(BINARY), 'pre-commit', '--', 'secret.txt'],
                                    cwd=self.directory, stdout=sink, stderr=subprocess.PIPE,
                                    env=self.env, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'cannot write pre-commit output', result.stderr)
        self.assertNotIn(KEY, result.stderr)

    def test_shared_upstream_outcomes(self):
        if not REFERENCE:
            self.skipTest('pass --reference for pinned upstream exit/outcome comparisons')
        cases = [
            ([*OPTIONS, '--fail', 'stdin'], SOURCE, 183),
            ([*OPTIONS, '--fail', 'stdin'], b'', 0),
            ([*OPTIONS, '--fail', '--results=verified', 'stdin'], SOURCE, 0),
            (['--briar-invalid-option', 'stdin'], b'', 1),
            (['briar-invalid-command'], b'', 1),
        ]
        for args, source, code in cases:
            with self.subTest(args=args, empty=not source):
                actual = self.invoke(args, source=source)
                expected = subprocess.run([str(REFERENCE), '--no-update', '--concurrency=1', *args],
                                          input=source, capture_output=True, env=self.env, timeout=30)
                self.assertEqual(actual.returncode, code)
                self.assertEqual(expected.returncode, code)
                # No diagnostic-text normalization hides an exit or finding mismatch.
                self.assertEqual([json.loads(line) for line in actual.stdout.splitlines()],
                                 [json.loads(line) for line in expected.stdout.splitlines()])
                if code == 1:
                    self.assertTrue(actual.stderr)
                    self.assertTrue(expected.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--reference', type=Path, help='run only the shared upstream exit/outcome comparisons')
    args = parser.parse_args()
    BINARY = args.binary.resolve()
    REFERENCE = args.reference.resolve() if args.reference else None
    # Never let a reference option turn this into a live-provider test.
    if REFERENCE:
        assert {name for _, name in socket.if_nameindex()} == {'lo'}, 'use an isolated network namespace'
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import cli_reference
        cli_reference.check_reference_version(REFERENCE)
    names = unittest.defaultTestLoader.getTestCaseNames(CliFailures)
    names = [name for name in names if (name == 'test_shared_upstream_outcomes') == bool(REFERENCE)]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(CliFailures(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
