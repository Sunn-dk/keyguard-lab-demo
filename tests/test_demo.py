import unittest

from main import run_detection


class DemoTest(unittest.TestCase):
    def test_bundled_sample(self):
        count, alerts = run_detection()
        self.assertEqual(count, 6)
        self.assertEqual(
            [(alert.severity, alert.score) for alert in alerts],
            [("HIGH", 6), ("MEDIUM", 3), ("LOW", 1)],
        )
