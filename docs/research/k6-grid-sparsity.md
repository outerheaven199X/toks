# Research: K6 low-ID pair grid occupancy

This is not a kernel optimization and is not a speed claim.

The unmerged experiment described in docs/kernels.md section 5.3 had a
1024 x 1024 dense u32 merge-priority grid (4 MiB per loaded tokenizer).
It sped up some English/code cells, but missed the maintainer's
no-cell-regression bar on CJK. Its measurements and layout controls remain
the authoritative baseline. The grid is not shipped.

This survey examines an alternative question: how many *distinct* BPE
merge-pair keys actually fit the low-ID grid? It treats duplicate pairs as
one occupied cell, matching the hash merge table's last-rank-wins
presence rule. It rejects unknown/ambiguous merge spellings rather than
ignoring records. All source tokenizer files are SHA-256-pinned.

The output compares only *theoretical storage*:

- 4,194,304 bytes: full dense grid of u32 prios.
- 131,072 bytes bitmap + 4 bytes per occupied key + 4,100 bytes
  row offsets. Random lookup would require rank/select and rank data.
- A more realistic direct-index candidate adds 32,768 bytes of u16
  within-row prefixes, one per 64-bit bitmap word. Lookup still needs
  bit selection, popcount, and a priority-array load.
- 4,100 bytes row offsets + 2 bytes for each right ID and 4 bytes per
  occupied key. This unpadded CSR layout would require a search.
- 4 bytes per row index + a full 4096-byte row for each nonempty left ID.

No method's actual cache behavior, alignment/padding, construction
overhead, branch cost, power, or throughput is included.

To reproduce:

    python3 -m unittest discover -s tests/perf -p 'test_k6_grid_density.py' -v
    python3 tools/ci/fetch_tokenizers.py
    python3 tools/bench/k6_grid_density.py ~/.cache/toks/tokenizers/gpt2

The research CI uploads JSONL records with model digests and counts.
Before claiming an improvement, implement one candidate lookup that
remains exactly equivalent to the hash table (including last-rank
priority, sparse misses, and >1023-ID fallback), run tier and HF parity,
then compare frozen binaries under pinned-load ABBA benchmarking using
the maintainer's no-regression gates. Shared CI runners cannot
establish the speed claim.
