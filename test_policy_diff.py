import unittest

from policy_diff import compare


class DiffTests(unittest.TestCase):
    def test_changes(self):
        report={"candidates":[{"id":"a"},{"id":"b"},{"id":"c"}]}
        result=compare(report,["a","old"],["b"])
        self.assertEqual([r["id"] for r in result["added"]],["b"])
        self.assertEqual([r["id"] for r in result["removed"]],["a","old"])
        self.assertEqual([r["id"] for r in result["previous_not_observed"]],["old"])
        self.assertEqual([r["id"] for r in result["unapproved_observed"]],["a","c"])
    def test_unknown(self):
        with self.assertRaises(ValueError):
            compare({"candidates":[]},[],["unknown"])
    def test_invalid(self):
        with self.assertRaises(ValueError):
            compare({"candidates":[]},{},[])
