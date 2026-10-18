"""Mutation sensitivity checks of the *same* contract used with compiled toks."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.security.control_id_probe_contract import assert_probe_contract

CONTROL_ID = 1002
SAMPLES = [f"sample-{n}" for n in range(70)]


class FakeTokenizer:
    def __init__(self, *, leak_none=False, positive_count=65):
        self.leak_none = leak_none
        self.positive_count = positive_count

    def encode(self, text, *, added_tokens, add_special_tokens):
        assert add_special_tokens is False
        idx = int(text.split("-")[-1])
        if added_tokens == "none":
            return [CONTROL_ID] if self.leak_none and idx == 31 else [42]
        if added_tokens == "all":
            return [CONTROL_ID] if idx < self.positive_count else [42]
        raise AssertionError("unexpected recognition mode")


class ProbeContractTests(unittest.TestCase):
    def test_positive_and_none_modes(self):
        report = assert_probe_contract(FakeTokenizer(), SAMPLES, CONTROL_ID,
                                       expected_positive_count=65, model="synthetic")
        self.assertEqual(report["none_mode_witness_count"], 0)
        self.assertEqual(report["positive_control_witness_count"], 65)

    def test_deliberate_none_mode_leak_exercises_the_failure_branch(self):
        with self.assertRaisesRegex(AssertionError, "added_tokens=none witnesses"):
            assert_probe_contract(FakeTokenizer(leak_none=True), SAMPLES, CONTROL_ID,
                                  expected_positive_count=65, model="synthetic")

    def test_wrong_positive_counts_are_rejected_not_merely_reported(self):
        for value in (0, 1, 64, 66, 70):
            with self.subTest(value=value), self.assertRaisesRegex(AssertionError, "pinned expected 65"):
                assert_probe_contract(FakeTokenizer(positive_count=value), SAMPLES,
                                      CONTROL_ID, expected_positive_count=65, model="synthetic")

    def test_wrong_control_id_is_detected(self):
        with self.assertRaisesRegex(AssertionError, "positive recognition count"):
            assert_probe_contract(FakeTokenizer(), SAMPLES, CONTROL_ID + 10,
                                  expected_positive_count=65, model="synthetic")

    def test_duplicate_or_empty_samples_are_rejected(self):
        for items in ([], [SAMPLES[0]] * 70):
            with self.subTest(items=items[:2]), self.assertRaisesRegex(AssertionError, "empty or duplicate"):
                assert_probe_contract(FakeTokenizer(), items, CONTROL_ID,
                                      expected_positive_count=65, model="synthetic")


if __name__ == "__main__":
    unittest.main()
