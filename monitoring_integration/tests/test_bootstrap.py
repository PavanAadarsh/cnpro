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
        self.sources.write_text(json.dumps({'origin/member1-network-architecture': 'd' * 40, 'origin/member-2': 'a' * 40, 'origin/member3': 'b' * 40}))

    @patch('prepare_upstream.subprocess.check_output', return_value=b'synthetic test dependency\n')
    def test_recreates_only_required_files_and_is_repeatable(self, git):
        output = self.root / 'upstream'
        first = prepare(output, self.sources, self.root)
        second = prepare(output, self.sources, self.root)
        expected = sum(len(names) for _, names in FILES.values())
        self.assertEqual(first['created'], expected)
        self.assertEqual(second['created'], 0)
        self.assertEqual(second['already_matching'], expected)
        self.assertEqual(len([p for p in output.rglob('*') if p.is_file()]), expected)

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

    def test_refresh_archives_previous_pin_and_refuses_user_edits(self):
        self.sources.write_text(json.dumps({'origin/member1-network-architecture': 'd' * 40, 'origin/member-2': 'a' * 40, 'origin/member3': 'c' * 40,
            'previous_sources': {'origin/member3': 'b' * 40}}))
        output = self.root / 'upstream'
        target = output / 'member3/README.md'
        target.parent.mkdir(parents=True)
        target.write_bytes(b'previous pinned version')
        def blob(args, **kwargs):
            return b'previous pinned version' if args[-1].startswith('b' * 40 + ':') else b'new pinned version'
        with patch('prepare_upstream.subprocess.check_output', side_effect=blob):
            result = prepare(output, self.sources, self.root, refresh=True)
            archived = Path(result['backup_directory']) / 'member3/README.md'
            self.assertEqual(archived.read_bytes(), b'previous pinned version')
            self.assertEqual(target.read_bytes(), b'new pinned version')
            self.assertEqual(result['updated'], 1)
            target.write_bytes(b'user edit that must survive')
            with self.assertRaises(ValueError): prepare(output, self.sources, self.root, refresh=True)
            self.assertEqual(target.read_bytes(), b'user edit that must survive')


if __name__ == '__main__':
    unittest.main()
