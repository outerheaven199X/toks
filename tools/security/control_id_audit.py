#!/usr/bin/env python3
"""Conservative structural-token ID audit for tokenizer.json inputs.

This is a *model-vocabulary disjointness* check, not a proof of prompt
injection resistance. It applies only to encode(text, added_tokens="none",
add_special_tokens=False), and only when the model's possible IDs are
described by a conventional BPE, WordPiece, or Unigram vocabulary.

Callers MUST choose the structural control token names to audit. A token's
"special" flag does not by itself mean the token is a structural delimiter.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


class AuditError(ValueError):
    """Malformed or unsupported input: never report this as disjoint."""


def _id(value: object, context: str) -> int:
    if type(value) is not int or value < 0 or value > 0xFFFFFFFF:
        raise AuditError(f"{context}: expected a nonnegative u32 ID")
    return value


def model_ids(model: object) -> tuple[str, set[int]]:
    """Over-approximate IDs the tokenizer MODEL can emit, not added/template IDs.

    A disjoint result is useful only when this set is complete. On unknown
    schemas we refuse to certify rather than guessing or dropping entries.
    """
    if not isinstance(model, dict):
        raise AuditError("model must be an object")
    kind = model.get("type")
    vocab = model.get("vocab")
    if kind in ("BPE", "WordPiece"):
        if not isinstance(vocab, dict) or not vocab:
            raise AuditError(f"{kind}: expected a nonempty object vocabulary")
        ids = set()
        for token, idx in vocab.items():
            if not isinstance(token, str):
                raise AuditError(f"{kind}: non-string vocabulary token")
            ids.add(_id(idx, f"{kind} vocabulary {token!r}"))
        unk = model.get("unk_token")
        if unk is not None and (not isinstance(unk, str) or unk not in vocab):
            raise AuditError(f"{kind}: unknown token is not in the model vocabulary")
        return kind, ids
    if kind == "Unigram":
        if not isinstance(vocab, list) or not vocab:
            raise AuditError("Unigram: expected a nonempty list vocabulary")
        for i, row in enumerate(vocab):
            if not isinstance(row, list) or len(row) != 2 or not isinstance(row[0], str):
                raise AuditError(f"Unigram: malformed vocabulary row {i}")
        unk = model.get("unk_id")
        if unk is not None and _id(unk, "Unigram unk_id") >= len(vocab):
            raise AuditError("Unigram: unk_id is out of vocabulary")
        return kind, set(range(len(vocab)))
    raise AuditError(f"unsupported model kind {kind!r}; cannot certify")


def audit(document: object, controls: list[str], source_sha256: str) -> dict:
    """Classify *only* absence/presence of explicitly named control IDs in the model vocab."""
    if not isinstance(document, dict):
        raise AuditError("tokenizer.json root must be an object")
    if not controls or any(not isinstance(n, str) or not n for n in controls):
        raise AuditError("supply at least one nonempty --control name")
    if len(controls) != len(set(controls)):
        raise AuditError("duplicate --control name")
    kind, emitted_ids = model_ids(document.get("model"))
    added = document.get("added_tokens")
    if not isinstance(added, list):
        raise AuditError("added_tokens must be a list")
    special = {}
    for i, entry in enumerate(added):
        if not isinstance(entry, dict):
            raise AuditError(f"added_tokens[{i}] is not an object")
        name = entry.get("content")
        if not isinstance(name, str):
            raise AuditError(f"added_tokens[{i}] lacks a string content")
        idx = _id(entry.get("id"), f"added_tokens[{i}]")
        is_special = entry.get("special")
        if type(is_special) is not bool:
            raise AuditError(f"added_tokens[{i}] has no boolean special flag")
        if is_special:
            if name in special and special[name] != idx:
                raise AuditError(f"special token {name!r} has conflicting IDs")
            special[name] = idx
    findings = []
    for name in controls:
        if name not in special:
            raise AuditError(f"control {name!r} not found as a flagged special token")
        idx = special[name]
        verdict = "vocab_overlap" if idx in emitted_ids else "vocab_disjoint"
        findings.append({"content": name, "id": idx, "verdict": verdict})
    return {
        "schema": 1,
        "source_sha256": source_sha256,
        "algorithm": kind,
        "model_vocab_ids": len(emitted_ids),
        "encoding_mode": {"added_tokens": "none", "add_special_tokens": False},
        "status": "inconclusive" if any(f["verdict"] == "vocab_overlap" for f in findings) else "disjoint",
        "controls": findings,
        "scope": (
            "Set-membership audit of tokenizer.json model IDs only; assumes the C model "
            "emits only IDs described by this vocabulary. Added-token recognition, "
            "post-processing, application prompt assembly, and any nonstandard model "
            "behavior are NOT covered. Vocab overlap does not prove exploitability; "
            "vocab disjointness does not certify an application."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tokenizer", type=Path, help="Hugging Face tokenizer.json")
    parser.add_argument("--control", action="append", required=True,
                        help="exact content of a structural control token; repeatable")
    parser.add_argument("--require-disjoint", action="store_true",
                        help="exit 1 on any overlapping control ID (otherwise report inconclusive)")
    args = parser.parse_args()
    try:
        raw = args.tokenizer.read_bytes()
        report = audit(json.loads(raw), args.control, hashlib.sha256(raw).hexdigest())
    except (OSError, UnicodeError, json.JSONDecodeError, AuditError) as exc:
        print(f"control_id_audit: UNVERIFIED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 1 if args.require_disjoint and report["status"] != "disjoint" else 0


if __name__ == "__main__":
    sys.exit(main())
