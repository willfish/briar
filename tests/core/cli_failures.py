#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise OS/process failures against the real CLI, not an embedded main()."""
import argparse
import array
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
        large = self.directory / 'large.txt'
        large.write_bytes(SOURCE + b'x' * 65536)
        fifo = self.directory / 'pipe'
        os.mkfifo(fifo)
        peer = socket.socket(socket.AF_UNIX)
        self.addCleanup(peer.close)
        address = self.directory / 'socket'
        peer.bind(str(address))
        cases = [
            (self.directory / KEY.decode() / 'missing.txt', 'cannot open filesystem input parent'),
            (good / 'child', 'cannot open filesystem input parent'),
            (large, 'exceeds the 64 KiB source cap'),
            (fifo, 'not regular'),
            (address, 'cannot open filesystem input'),
            (Path('/dev/null'), 'not regular'),
        ]
        for path, diagnostic in cases:
            with self.subTest(path=path.name):
                self.failed(self.invoke(['filesystem', str(good), str(path), *OPTIONS]), diagnostic)
                self.assertEqual(good.read_bytes(), SOURCE)
        self.assertEqual(large.stat().st_size, len(SOURCE) + 65536)

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
                process.stdin.write(SOURCE)
                process.stdin.flush()  # Keep stdin open, including after cancellation.
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
