import unittest
from finding_investigation_engine import normalize, summary


class TestInvestigationEngine(unittest.TestCase):
    def test_deduplication_and_categories(self):
        injection = {'check_id': 'go.command-injection', 'path': 'fake/a.go',
                     'start': {'line': 17}, 'extra': {'severity': 'WARNING'}}
        auth = {'check_id': 'go.authorization-rule', 'path': 'fake/b.go',
                'start': {'line': 5}, 'extra': {'severity': 'ERROR'}}
        findings = normalize({'results': [injection, injection, auth]})
        self.assertEqual(len(findings), 2)
        s = summary(findings)
        self.assertEqual(s['unique_unverified_matches'], 2)
        self.assertEqual(s['by_category']['command execution'], 1)
        self.assertEqual(s['by_category']['access control'], 1)
        self.assertEqual(s['independently_reproduced_vulnerabilities'], 0)

    def test_analysis_errors_not_hidden(self):
        with self.assertRaises(ValueError):
            normalize({'results': [], 'errors': [{'message': 'parse problem'}]})

    def test_empty(self):
        self.assertEqual(summary(normalize({'results': []}))['unique_unverified_matches'], 0)


if __name__ == '__main__':
    unittest.main()
