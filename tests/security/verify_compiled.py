#!/usr/bin/env python3
"""Cross-check the static control-ID audit against the compiled toks C/Python ABI.

Finite probes can reveal a reachable control ID; they cannot establish
unreachability. This checker does not claim prompt-injection resistance.
"""
import gc
import hashlib
import json
import os
import sys
from pathlib import Path

import toks

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.security.control_id_audit import audit

TARGETS = {
    "gpt2": "<|endoftext|>",
    "llama3": "<|eot_id|>",
    "qwen38": "<|im_start|>",
    "o200k": "<|start|>",
    "gemma4": "<|turn>",
}


def probes(marker: str) -> list[str]:
    prefixes = ("", "a", " ", "\n", "\t", "user:", "~" * 3, "\\", "漢字")
    suffixes = ("", "b", " ", "\n", "assistant", "|>", "~" * 3)
    cases = {p + marker + s for p in prefixes for s in suffixes}
    cases.update((marker * 2, marker * 3, marker[: max(1, len(marker) // 2)],
                  "Hello world", "", "foo" * 100, marker.upper(), marker.lower()))
    return sorted(cases)


def main() -> None:
    root = Path(os.path.expanduser(os.environ.get(
        "TOKS_TOKENIZER_CACHE", "~/.cache/toks/tokenizers")))
    outputs = []
    for name, marker in TARGETS.items():
        path = root / name
        raw = path.read_bytes()
        report = audit(json.loads(raw), [marker], hashlib.sha256(raw).hexdigest())
        entry = report["controls"][0]
        tok = toks.Tokenizer.from_file(path)
        actual = tok.token_to_id(marker)
        flags = tok.id_flags(entry["id"])
        if actual != entry["id"]:
            raise AssertionError(f"{name}: compiled token_to_id {actual} != {entry['id']}")
        if not flags & toks.ID_SPECIAL:
            raise AssertionError(f"{name}: compiled ID {entry['id']} has no special flag")
        samples = probes(marker)
        witnesses = []
        positive = []
        for sample in samples:
            ids = tok.encode(sample, added_tokens="none", add_special_tokens=False)
            if entry["id"] in ids:
                witnesses.append(sample)
            if entry["id"] in tok.encode(sample, added_tokens="all", add_special_tokens=False):
                positive.append(sample)
        # A finite regression contract, NOT a universal unreachability proof:
        # any newly observed witness fails CI, even for the two overlapping
        # model vocabularies (GPT-2 and Gemma 4).
        if witnesses:
            raise AssertionError(f"{name}: {len(witnesses)} unexpected ordinary-mode witnesses")
        # Ensure the very same harness detects the special ID when the
        # tokenizer is explicitly allowed to recognize its literal marker.
        if not positive:
            raise AssertionError(f"{name}: positive control detected no special token IDs")
        outputs.append({
            "name": name, "source_sha256": report["source_sha256"],
            "compiled_version": toks.__version__,
            "control": marker, "id": entry["id"],
            "static_status": report["status"], "compiled_id_matches": True,
            "probes": len(samples),
            "marker_bearing_inputs": sum(marker in s for s in samples),
            "ordinary_mode_witnesses": witnesses[:10],
            "ordinary_mode_witness_count": len(witnesses),
            "positive_control_all_mode_witness_count": len(positive),
            "limitation": "Finite string probes, some containing literal markers; zero ordinary-mode witnesses is not universal control isolation",
        })
        print(name, report["status"], "compiled ID verified", len(samples),
              "mixed marker/control probes,", len(witnesses), "ordinary-mode witnesses,",
              len(positive), "positive controls", flush=True)
        del tok
        gc.collect()
    out = Path("build/security/compiled-audit.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(outputs, sort_keys=True, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
