import importlib.util
from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ci_release', ROOT / 'tools/ci_release.py')
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    @contextmanager
    def repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args):
                return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', '-c', 'user.name=CI', '-c', 'user.email=ci@example.invalid', '-C', tmp, *args], text=True).strip()
            git('init', '-q')
            git('commit', '--allow-empty', '-qm', 'initial')
            git('update-ref', 'refs/remotes/origin/master', 'HEAD')
            yield tmp, git

    def output(self, tmp):
        return subprocess.check_output(['python3', str(ROOT / 'tools/ci_release.py')], cwd=tmp, text=True).strip()

    def test_initial_stable_release(self):
        self.assertEqual(release.plan([], []), 'v0.1.0')

    def test_bump_highest_stable_patch_numerically(self):
        self.assertEqual(release.plan(['v0.1.9', 'v0.1.10', 'v0.1.2'], []), 'v0.1.11')
        self.assertEqual(release.plan(['v1.9.0', 'v2.0.3'], []), 'v2.0.4')

    def test_ignore_prereleases_and_non_semver(self):
        self.assertEqual(release.plan(['v9.0.0-rc.1', 'v01.2.3', 'notes', 'v0.1.0'], []), 'v0.1.1')

    def test_rerun_keeps_existing_head_tag(self):
        self.assertEqual(release.plan(['v0.1.0', 'v0.1.1'], ['v0.1.1']), 'v0.1.1')

    def test_output_is_single_validated_tag(self):
        self.assertEqual(release.plan(['tag\nmalicious=value', 'v0.1.0'], []), 'v0.1.1')

    def test_real_git_tag_round_trip(self):
        with self.repository() as (tmp, git):
            output = self.output(tmp)
            self.assertEqual(output, 'publish=true\ntag=v0.1.0')
            git('tag', 'v0.1.0')
            self.assertEqual(self.output(tmp), output)
            git('commit', '--allow-empty', '-qm', 'next')
            git('update-ref', 'refs/remotes/origin/master', 'HEAD')
            self.assertEqual(self.output(tmp), 'publish=true\ntag=v0.1.1')

    def test_older_failed_run_cannot_release_after_newer_version(self):
        with self.repository() as (tmp, git):
            git('tag', 'v0.1.0')
            git('commit', '--allow-empty', '-qm', 'older failed run')
            old = git('rev-parse', 'HEAD')
            git('commit', '--allow-empty', '-qm', 'newer released run')
            git('tag', 'v0.1.1')
            git('update-ref', 'refs/remotes/origin/master', 'HEAD')
            git('checkout', '--detach', '-q', old)
            self.assertEqual(self.output(tmp), 'publish=false')

    def test_current_master_cannot_release_without_latest_stable_ancestor(self):
        with self.repository() as (tmp, git):
            original = git('rev-parse', 'HEAD')
            git('commit', '--allow-empty', '-qm', 'released history')
            git('tag', 'v0.1.1')
            git('checkout', '--detach', '-q', original)
            git('commit', '--allow-empty', '-qm', 'different history')
            git('update-ref', 'refs/remotes/origin/master', 'HEAD')
            self.assertEqual(self.output(tmp), 'publish=false')


if __name__ == '__main__':
    unittest.main()
