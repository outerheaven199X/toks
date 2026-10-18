#!/usr/bin/env python3
"""Export pinned BPE merge keys and their last-wins raw ranks for C lookup experiments.

Output is a versioned little-endian fixture, not a toks serialized image.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from k6_grid_density import ModelError, pair_tokens, vocab_id

MAGIC = b'K6CMP1\x00\x00'
MAX_ID = 1 << 21


def generate(src: Path, dest: Path) -> dict:
    raw = src.read_bytes()
    obj = json.loads(raw)
    if not isinstance(obj, dict) or not isinstance(obj.get('model'), dict):
        raise ModelError('missing model object')
    m = obj['model']
    if m.get('type') not in ('BPE', None) or not isinstance(m.get('vocab'), dict) or not isinstance(m.get('merges'), list):
        raise ModelError('needs a BPE vocabulary + merge array')
    ids = {t: vocab_id(v, f'vocab {t!r}') for t, v in m['vocab'].items()}
    pairs = {}
    for rank, record in enumerate(m['merges']):
        left, right = pair_tokens(record, rank)
        if left not in ids or right not in ids:
            raise ModelError(f'merge {rank} refers to a missing vocabulary token')
        l, r = ids[left], ids[right]
        if max(l, r) >= MAX_ID or rank >= MAX_ID:
            raise ModelError('ID or merge rank exceeds the K6 21-bit range')
        pairs[(l, r)] = rank  # last rank wins, as toks_merge_slots does
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('wb') as out:
        out.write(struct.pack('<8sIII', MAGIC, len(pairs), len(ids), len(m['merges'])))
        for (l, r), rank in sorted(pairs.items()):
            out.write(struct.pack('<III', l, r, rank))
    meta = {'source': src.name, 'source_sha256': hashlib.sha256(raw).hexdigest(),
            'fixture_sha256': hashlib.sha256(dest.read_bytes()).hexdigest(),
            'distinct_pairs': len(pairs), 'model_ids': len(ids), 'raw_merges': len(m['merges']),
            'format': 'K6CMP1 little-endian, 8-byte magic + 3 u32 counts + (left,right,last_raw_rank) triples'}
    dest.with_suffix(dest.suffix + '.json').write_text(json.dumps(meta, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return meta


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('tokenizer', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(generate(args.tokenizer, args.output), sort_keys=True))
    except (OSError, json.JSONDecodeError, UnicodeError, ModelError) as e:
        print('K6 fixture rejected:', e, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
