#!/usr/bin/env python3
"""Cross-check the static control-ID audit against the compiled toks C/Python ABI.

Finite probes can reveal a reachable control ID; they cannot establish
unreachability. This checker does not claim prompt-injection resistance.
"""
import gc
import hashlib
import json
import os
from pathlib import Path

import toks

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
        for sample in samples:
            ids = tok.encode(sample, added_tokens="none", add_special_tokens=False)
            if entry["id"] in ids:
                witnesses.append(sample)
        # A witnessed ID in a disjoint case invalidates the declared assumptions.
        if report["status"] == "disjoint" and witnesses:
            raise AssertionError(f"{name}: {len(witnesses)} witnesses contradict disjointness")
        outputs.append({
            "name": name, "source_sha256": report["source_sha256"],
            "compiled_version": toks.__version__,
            "control": marker, "id": entry["id"],
            "static_status": report["status"], "compiled_id_matches": True,
            "probes": len(samples), "witnesses": witnesses[:10],
            "witness_count": len(witnesses),
            "limitation": "Finite probes only; zero witnesses is not a security proof",
        })
        print(name, report["status"], "compiled ID verified", len(samples),
              "plain-text probes", len(witnesses), "witnesses", flush=True)
        del tok
        gc.collect()
    out = Path("build/security/compiled-audit.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(outputs, sort_keys=True, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
