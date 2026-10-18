import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluate import calculate, analyze, audit, new_run


class EvaluationTests(unittest.TestCase):
    def test_metrics(self):
        m = calculate(dict(probes_sent=4, probes_received=3, rtt_ms=[1, 2, 3],
                           legitimate_attempted=5, legitimate_succeeded=4,
                           transition_attempted=2, transition_succeeded=1,
                           transferred_bytes=1000000, transfer_seconds=2,
                           condition_at='2026-10-18T00:00:00+00:00',
                           detected_at='2026-10-18T00:00:01+00:00',
                           effective_denial_at='2026-10-18T00:00:03+00:00'))
        self.assertEqual(m['packet_loss_pct'], 25)
        self.assertEqual(m['latency_ms'], 2)
        self.assertEqual(m['throughput_mbps'], 4)
        self.assertEqual(m['detection_ms'], 1000)
        self.assertEqual(m['response_ms'], 2000)
        self.assertEqual(m['success_pct'], 80)
        self.assertEqual(m['disruption_pct'], 50)

    def test_missing_and_failed_probes(self):
        self.assertTrue(all(v is None for v in calculate({}).values()))
        m = calculate(dict(probes_sent=4, probes_received=0))
        self.assertEqual(m['packet_loss_pct'], 100)
        self.assertIsNone(m['latency_ms'])
        self.assertIsNone(calculate(dict(probes_sent=0, probes_received=0))['packet_loss_pct'])

    def test_invalid(self):
        for row in [dict(probes_sent=1, probes_received=2), dict(probes_sent=-1),
                    dict(rtt_ms=[float('nan')]), dict(transferred_bytes=1, transfer_seconds=0),
                    dict(detected_at='2026-01-01T00:00:00', condition_at='2026-01-01T00:00:00'),
                    dict(condition_at='2026-01-02T00:00:00Z', detected_at='2026-01-01T00:00:00Z')]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                calculate(row)

    def test_import_and_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            root = Path(d)
            (root / 'probe.txt').write_text('unit-test fixture: failed probes; not network evidence')
            row = dict(scenario='fixture', configuration='static', trial=1,
                       start_at='2026-10-18T00:00:00Z', end_at='2026-10-18T00:00:01Z',
                       status='measured', notes='synthetic unit test only', evidence=['probe.txt'],
                       probes_sent=4, probes_received=0)
            source = root / 'in.json'
            source.write_text(json.dumps([row]))
            first = analyze(source, root / 'out')
            second = analyze(source, root / 'out')
            self.assertNotEqual(first, second)
            summary = json.loads((first / 'summary.json').read_text())
            self.assertEqual(next(x for x in summary if x['metric'] == 'packet_loss_pct')['mean'], 100)
            self.assertTrue((first / 'evidence/0-probe.txt').exists())
            source.write_text(json.dumps([row, row]))
            with self.assertRaises(ValueError): analyze(source, root / 'out')
            row['evidence'] = ['absent.txt']
            source.write_text(json.dumps([row]))
            with self.assertRaises(FileNotFoundError): analyze(source, root / 'out')
            source.write_text('{broken')
            with self.assertRaises(ValueError): analyze(source, root / 'out')

    def test_unique_output(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            self.assertNotEqual(new_run(d), new_run(d))

    def test_recovery(self):
        self.assertEqual(calculate(dict(recovery_condition_at='2026-10-18T00:00:00Z',
                                        restored_at='2026-10-18T00:00:02Z'))['recovery_ms'], 2000)

    def test_chart_and_failed_exclusion(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            root = Path(d)
            (root / 'fixture.txt').write_text('Synthetic chart validation only')
            rows = [dict(scenario='fixture', configuration=c, trial=1,
                         start_at='2026-10-18T00:00:00Z', end_at='2026-10-18T00:00:01Z',
                         status='measured', notes='unit test only', evidence=['fixture.txt'],
                         probes_sent=4, probes_received=2) for c in ('static', 'adaptive')]
            rows.append({**rows[0], 'trial': 2, 'status': 'failed', 'probes_received': 0})
            source = root / 'input.json'
            source.write_text(json.dumps(rows))
            output = analyze(source, root / 'out')
            self.assertTrue(list(output.glob('comparison-*.svg')))
            values = json.loads((output / 'summary.json').read_text())
            self.assertEqual(next(s for s in values if s['metric'] == 'packet_loss_pct' and s['configuration'] == 'static')['n'], 1)
            rows[0]['evidence'] = ['../outside.txt']
            source.write_text(json.dumps(rows))
            with self.assertRaises(ValueError): analyze(source, root / 'out')

    def test_repository_audit(self):
        result = audit()
        self.assertTrue(result['source_sha256'])
        self.assertIn('routing_enabled', result)


if __name__ == '__main__':
    unittest.main()
