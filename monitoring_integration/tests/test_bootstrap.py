import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from prepare_upstream import FILES, prepare


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=HERE / 'tests')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sources = self.root / 'sources.json'
        self.sources.write_text(json.dumps({'origin/member-2': 'a' * 40, 'origin/member3': 'b' * 40}))

    @patch('prepare_upstream.subprocess.check_output', return_value=b'synthetic test dependency\n')
    def test_recreates_only_required_files_and_is_repeatable(self, git):
        output = self.root / 'upstream'
        first = prepare(output, self.sources, self.root)
        second = prepare(output, self.sources, self.root)
        self.assertEqual(first['created'], 11)
        self.assertEqual(second['created'], 0)
        self.assertEqual(second['already_matching'], 11)
        self.assertEqual(len([p for p in output.rglob('*') if p.is_file()]), 11)

    @patch('prepare_upstream.subprocess.check_output', return_value=b'from pinned source\n')
    def test_different_existing_source_is_preserved(self, git):
        output = self.root / 'upstream'
        path = output / 'member2/cnpro/configs/CORE-SW_security_acls.cfg'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'local change to preserve\n')
        with self.assertRaises(ValueError): prepare(output, self.sources, self.root)
        self.assertEqual(path.read_bytes(), b'local change to preserve\n')
        self.assertFalse((output / 'member3').exists())

    @patch('prepare_upstream.subprocess.check_output')
    def test_invalid_commit_rejected_before_git(self, git):
        self.sources.write_text(json.dumps({'origin/member-2': '--bad-ref'}))
        with self.assertRaises(ValueError): prepare(self.root / 'out', self.sources, self.root)
        git.assert_not_called()

    def test_real_pinned_sources_are_available(self):
        result = prepare(self.root / 'real', HERE / 'sources.json', HERE.parent)
        self.assertEqual(result['created'], sum(len(names) for _, names in FILES.values()))
        self.assertTrue((self.root / 'real/member3/policy_engine/policy_engine.py').is_file())


if __name__ == '__main__':
    unittest.main()
