#!/usr/bin/env python3
"""Research-only occupancy survey for K6's unmerged 1024x1024 u32 pair grid.

This measures unique low-ID merge pairs in the model file. It DOES NOT
implement a lookup, estimate CPU cache misses, or establish a speedup.
Any source shape it cannot reproduce exactly is rejected, not guessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

LOW_BITS = 10
LOW = 1 << LOW_BITS
DENSE_BYTES = 4 * LOW * LOW


class ModelError(ValueError):
    pass


def vocab_id(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > 0xFFFFFFFF:
        raise ModelError(f"{label}: not a u32 ID")
    return value


def pair_tokens(record: object, i: int) -> tuple[str, str]:
    if isinstance(record, list) and len(record) == 2 and all(isinstance(x, str) for x in record):
        return record[0], record[1]
    if isinstance(record, str):
        # The string-format BPE merge serialization separates the two spellings
        # by exactly one space. Fail closed on embedded/ambiguous spaces.
        parts = record.split(" ")
        if len(parts) == 2 and all(parts):
            return parts[0], parts[1]
    raise ModelError(f"merges[{i}]: cannot parse the pair without ambiguity")


def analyze(source: object, sha256: str) -> dict:
    if not isinstance(source, dict) or not isinstance(source.get("model"), dict):
        raise ModelError("tokenizer.json has no model object")
    model = source["model"]
    if model.get("type") not in (None, "BPE"):
        raise ModelError("not a BPE model")
    vocab, merges = model.get("vocab"), model.get("merges")
    if not isinstance(vocab, dict) or not vocab or not isinstance(merges, list):
        raise ModelError("model must contain a BPE vocabulary object and merges list")
    ids = {tok: vocab_id(v, f"vocab[{tok!r}]") for tok, v in vocab.items()}
    occupied: set[tuple[int, int]] = set()
    seen_all: set[tuple[int, int]] = set()
    rows: set[int] = set()
    dup = 0
    for i, item in enumerate(merges):
        left, right = pair_tokens(item, i)
        if left not in ids or right not in ids:
            raise ModelError(f"merges[{i}]: spelling not found in model vocabulary")
        pair = (ids[left], ids[right])
        if pair in seen_all:
            dup += 1
        seen_all.add(pair)
        if pair[0] < LOW and pair[1] < LOW:
            occupied.add(pair)
            rows.add(pair[0])
    count = len(occupied)
    bitmap = (LOW * LOW + 7) // 8
    row_offsets = (LOW + 1) * 4
    # Space-only estimates: bitset+prio needs rank/select, CSR needs search.
    # Neither is a measured runtime design or a shipped data structure.
    estimates = {
        "dense_u32_grid": DENSE_BYTES,
        "bitmap_plus_u32_prios_and_row_offsets": bitmap + 4 * count + row_offsets,
        "csr_u16_columns_u32_prios_unpadded": 6 * count + row_offsets,
        "only_nonempty_dense_rows_plus_index": 4 * LOW * len(rows) + 4 * LOW,
    }
    return {
        "schema": 1,
        "sha256": sha256,
        "low_id_limit_exclusive": LOW,
        "model_vocab_size": len(ids),
        "merge_records": len(merges),
        "distinct_merge_pairs": len(seen_all),
        "duplicate_pair_records": dup,
        "low_id_distinct_pairs": count,
        "low_id_density": round(count / (LOW * LOW), 8),
        "nonempty_left_rows": len(rows),
        "bytes_theoretical": estimates,
        "limits": (
            "Structural table occupancy only. The estimates exclude runtime/cache "
            "latency, hash table fallback, alignments/padding, population cost, "
            "and extra model tables. No performance or memory saving is claimed "
            "until code and pinned-machine ABBA benchmarks validate the trade."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("tokenizers", nargs="+", type=Path)
    args = p.parse_args()
    for path in args.tokenizers:
        try:
            raw = path.read_bytes()
            data = analyze(json.loads(raw), hashlib.sha256(raw).hexdigest())
        except (OSError, UnicodeError, json.JSONDecodeError, ModelError) as exc:
            print(f"k6_grid_density: {path}: UNVERIFIED: {exc}", file=sys.stderr)
            return 2
        data["source_name"] = path.name
        print(json.dumps(data, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
