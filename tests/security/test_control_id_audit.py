"""Negative controls and schema checks for tools/security/control_id_audit.py.

No third-party packages and no downloaded model files are required.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.security.control_id_audit import AuditError, audit, model_ids  # noqa: E402

CONTROL = "<|ctrl|>"


def document(model, idx=7, special=True):
    return {
        "model": model,
        "added_tokens": [{"content": CONTROL, "id": idx, "special": special}],
        "normalizer": None,
        "pre_tokenizer": None,
        "post_processor": None,
    }


def check(doc, names=None):
    return audit(doc, [CONTROL] if names is None else names, "f" * 64)


class ControlIdAuditTests(unittest.TestCase):
    def test_byte_bpe_disjoint(self):
        d = document({"type": "BPE", "vocab": {"a": 0, "ab": 2}})
        r = check(d)
        self.assertEqual(r["status"], "disjoint")
        self.assertEqual(r["controls"][0]["verdict"], "vocab_disjoint")
        self.assertEqual(r["model_vocab_ids"], 2)
        self.assertFalse(r["encoding_mode"]["add_special_tokens"])

    def test_overlap_is_inconclusive_not_a_proof_of_reachability(self):
        d = document({"type": "BPE", "vocab": {"a": 0, "<|ctrl|>": 7}})
        r = check(d)
        self.assertEqual(r["status"], "inconclusive")
        self.assertEqual(r["controls"][0]["verdict"], "vocab_overlap")

    def test_wordpiece(self):
        d = document({"type": "WordPiece", "vocab": {"[UNK]": 0, "a": 1},
                      "unk_token": "[UNK]"})
        self.assertEqual(check(d)["status"], "disjoint")

    def test_unigram_indices_include_unknown(self):
        d = document({"type": "Unigram", "vocab": [["<unk>", 0.0], ["hi", -1.0]],
                      "unk_id": 0}, idx=1)
        self.assertEqual(check(d)["status"], "inconclusive")
        d["added_tokens"][0]["id"] = 3
        self.assertEqual(check(d)["status"], "disjoint")

    def test_reserved_name_must_be_explicit_and_special(self):
        d = document({"type": "BPE", "vocab": {"a": 0}})
        with self.assertRaisesRegex(AuditError, "supply at least"):
            check(d, [])
        with self.assertRaisesRegex(AuditError, "not found"):
            check(d, ["<|not-a-flagged-control|>"])
        d["added_tokens"][0]["special"] = False
        with self.assertRaisesRegex(AuditError, "not found"):
            check(d)

    def test_fail_closed_on_unknown_models_and_malformed_ids(self):
        for model in ({"type": "WordLevel", "vocab": {"a": 0}},
                      {"type": "BPE", "vocab": {"a": True}},
                      {"type": "BPE", "vocab": {"a": -1}},
                      {"type": "BPE", "vocab": {"a": "1"}},
                      {"type": "WordPiece", "vocab": {"a": 1}, "unk_token": "[UNK]"},
                      {"type": "Unigram", "vocab": [["a", 1.0]], "unk_id": 2},
                      {"type": "Unigram", "vocab": {"a": 0}}):
            with self.subTest(model=model):
                with self.assertRaises(AuditError):
                    check(document(model))
        with self.assertRaises(AuditError):
            model_ids(None)

    def test_conflicting_added_names_are_rejected(self):
        d = document({"type": "BPE", "vocab": {"a": 0}})
        d["added_tokens"].append({"content": CONTROL, "id": 8, "special": True})
        with self.assertRaisesRegex(AuditError, "conflicting"):
            check(d)

    def test_cli_reports_overlap_without_claiming_safe(self):
        d = document({"type": "BPE", "vocab": {"a": 7}})
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "tokenizer.json"
            blob = json.dumps(d).encode("utf-8")
            f.write_bytes(blob)
            cmd = [sys.executable, str(ROOT / "tools/security/control_id_audit.py"),
                   str(f), "--control", CONTROL]
            p = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(p.returncode, 0, p.stderr)
            r = json.loads(p.stdout)
            self.assertEqual(r["status"], "inconclusive")
            self.assertEqual(r["source_sha256"], hashlib.sha256(blob).hexdigest())
            p = subprocess.run(cmd + ["--require-disjoint"], capture_output=True,
                               text=True, check=False)
            self.assertEqual(p.returncode, 1)
            self.assertEqual(json.loads(p.stdout)["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
