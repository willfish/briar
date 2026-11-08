import importlib.util
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
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args):
                return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', '-C', tmp, *args], text=True).strip()
            git('init', '-q')
            git('-c', 'user.name=CI', '-c', 'user.email=ci@example.invalid', 'commit', '--allow-empty', '-qm', 'initial')
            script = str(ROOT / 'tools/ci_release.py')
            output = subprocess.check_output(['python3', script], cwd=tmp, text=True).strip()
            self.assertEqual(output, 'tag=v0.1.0')
            git('tag', 'v0.1.0')
            self.assertEqual(subprocess.check_output(['python3', script], cwd=tmp, text=True).strip(), output)
            git('-c', 'user.name=CI', '-c', 'user.email=ci@example.invalid', 'commit', '--allow-empty', '-qm', 'next')
            self.assertEqual(subprocess.check_output(['python3', script], cwd=tmp, text=True).strip(), 'tag=v0.1.1')


if __name__ == '__main__':
    unittest.main()
