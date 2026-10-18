"""Proof-of-math and negative-input tests for the K6 occupancy research tool."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.bench.k6_grid_density import DENSE_BYTES, LOW, ModelError, analyze, pair_tokens


def model(vocab, merges, kind="BPE"):
    return {"model": {"type": kind, "vocab": vocab, "merges": merges}}


def survey(doc):
    return analyze(doc, "f" * 64)


class K6OccupancyTests(unittest.TestCase):
    def test_counts_unique_pairs_and_low_id_gate(self):
        d = model({"a": 0, "b": 1, "c": 1024, "z": 2000},
                  ["a b", "b a", "a c", "a b"])
        r = survey(d)
        self.assertEqual(r["merge_records"], 4)
        self.assertEqual(r["distinct_merge_pairs"], 3)
        self.assertEqual(r["duplicate_pair_records"], 1)
        self.assertEqual(r["low_id_distinct_pairs"], 2)
        self.assertEqual(r["nonempty_left_rows"], 2)
        self.assertEqual(r["low_id_limit_exclusive"], 1024)
        self.assertEqual(r["bytes_theoretical"]["dense_u32_grid"], 4 * 1024 * 1024)
        self.assertEqual(r["bytes_theoretical"]["bitmap_plus_u32_prios_and_row_offsets"],
                         128 * 1024 + 4 * 2 + (LOW + 1) * 4)
        self.assertEqual(
            r["bytes_theoretical"]["bitmap_plus_u16_word_prefix_u32_prios_and_row_offsets"],
            128 * 1024 + 32 * 1024 + 4 * 2 + (LOW + 1) * 4
        )

    def test_split_and_array_merge_forms(self):
        self.assertEqual(pair_tokens("aa bb", 0), ("aa", "bb"))
        self.assertEqual(pair_tokens(["aa", "bb"], 0), ("aa", "bb"))
        r = survey(model({"aa": 0, "bb": 1}, [["aa", "bb"]]))
        self.assertEqual(r["low_id_distinct_pairs"], 1)

    def test_ambiguous_strings_fail_closed(self):
        for item in ("a b c", "a  b", " a", "a ", "ab", [1, 2], ["a"], None):
            with self.subTest(item=item):
                with self.assertRaises(ModelError):
                    pair_tokens(item, 0)

    def test_bad_ids_and_unknown_parts_fail_closed(self):
        for val in (True, "1", -1, 2**40):
            with self.subTest(val=val):
                with self.assertRaises(ModelError):
                    survey(model({"a": val, "b": 1}, ["a b"]))
        with self.assertRaisesRegex(ModelError, "spelling"):
            survey(model({"a": 0}, ["a missing"]))

    def test_other_algorithms_fail_closed(self):
        with self.assertRaisesRegex(ModelError, "not a BPE"):
            survey(model({"a": 0}, [], kind="Unigram"))
        with self.assertRaises(ModelError):
            survey({"model": {"type": "BPE", "vocab": {"a": 0}}})
        with self.assertRaises(ModelError):
            survey({"model": {"type": "BPE", "vocab": {"a": 0}, "merges": {}}})

    def test_zero_merges_is_accounted_for_not_invented(self):
        r = survey(model({"a": 0}, []))
        self.assertEqual(r["low_id_density"], 0)
        self.assertEqual(r["low_id_distinct_pairs"], 0)
        self.assertEqual(r["bytes_theoretical"]["dense_u32_grid"], DENSE_BYTES)

    def test_cli_emits_source_digest(self):
        d = model({"a": 0, "b": 1}, ["a b"])
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "tokenizer.json"
            raw = json.dumps(d).encode("utf-8")
            f.write_bytes(raw)
            p = subprocess.run([sys.executable, str(ROOT / "tools/bench/k6_grid_density.py"),
                                str(f)], capture_output=True, text=True, check=False)
            self.assertEqual(p.returncode, 0, p.stderr)
            data = json.loads(p.stdout)
            self.assertEqual(data["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(data["source_name"], "tokenizer.json")


if __name__ == "__main__":
    unittest.main()
