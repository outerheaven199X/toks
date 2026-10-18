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
from tools.security.control_id_probe_contract import assert_probe_contract

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
        contract = assert_probe_contract(tok, samples, entry["id"],
                                         expected_positive_count=65, model=name)
        outputs.append({
            "name": name, "source_sha256": report["source_sha256"],
            "compiled_version": toks.__version__,
            "control": marker, "id": entry["id"],
            "static_status": report["status"], "compiled_id_matches": True,
            "probes": len(samples),
            "marker_bearing_inputs": sum(marker in s for s in samples),
            "none_mode_witness_count": contract["none_mode_witness_count"],
            "positive_control_all_mode_witness_count": contract["positive_control_witness_count"],
            "expected_positive_control_count": contract["expected_positive_control_count"],
            "limitation": "Finite string probes, some containing literal markers; zero ordinary-mode witnesses is not universal control isolation",
        })
        print(name, report["status"], "compiled ID verified", len(samples),
              "mixed marker/control probes,",
              contract["none_mode_witness_count"], "added_tokens=none witnesses,",
              contract["positive_control_witness_count"], "positive controls (exactly 65 required)",
              flush=True)
        del tok
        gc.collect()
    out = Path("build/security/compiled-audit.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(outputs, sort_keys=True, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
