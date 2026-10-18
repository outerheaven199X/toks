# K6 compact bitmap/rank lookup — experimental negative result

**Disposition: do not integrate.** A standalone compact lookup now exists and has exhaustive merge-rank verification, but is slower than the old 4 MiB dense-grid experiment in a synthetic shared-runner microbenchmark. No tokenizer kernel was changed.

## Evidence

Branch: https://github.com/outerheaven199X/toks/tree/research/k6-compact-lookup-prototype
CI: https://github.com/outerheaven199X/toks/actions/runs/39118453161

The fixture generator reads SHA-256-pinned tokenizer.json files, preserves the final raw rank for repeated left/right ID merge pairs, and writes a versioned little-endian file. The standalone C tool constructs both a dense grid and a compact bitmap + row-rank lookup. For IDs >= 1024 it uses a *sorted-array reference fallback*, not the real toks hash-table fallback.

Both optimized and ASan/UBSan builds verified every one of 1,048,576 low-ID pairs, every distinct present merge pair, and 100,000 high-ID/missing samples per model. These are **reconstructed merge-rank comparisons, not Hugging Face end-to-end encode parity tests**.

## Actual table storage

| Pinned model | Dense grid bytes | Compact bytes | Dense/compact | Rank comparisons |
|---|---:|---:|---:|---:|
| GPT-2 | 4,194,304 | 229,452 | 18.280x | 1,198,576 |
| Llama 3 | 4,194,304 | 281,436 | 14.903x | 1,428,723 |
| gpt-oss/o200k | 4,194,304 | 311,452 | 13.467x | 1,594,765 |
| Qwen 3.8 | 4,194,304 | 280,092 | 14.975x | 1,396,163 |
| GLM 5.3 | 4,194,304 | 288,912 | 14.518x | 1,470,225 |

Total: 7,088,452 rank comparisons, zero mismatches. The compact size counts its C struct and priority allocation, excluding allocator bookkeeping and the original full merge table, which a real integrated path would still need.

## Negative timing result (exploratory only)

On a shared Ubuntu CI runner with compiler -O3, 200,000 synthetic low-ID queries and ABBA order across four samples, **mean compact lookup time divided by dense-grid time**:

| Model | 0% hit mix | 50% hit mix | 100% hit mix |
|---|---:|---:|---:|
| GPT-2 | 2.02x | 12.70x | 7.05x |
| Llama 3 | 1.67x | 9.67x | 6.45x |
| o200k | 1.56x | 9.89x | 5.63x |
| Qwen 3.8 | 1.47x | 10.36x | 6.32x |
| GLM 5.3 | 1.61x | 9.70x | 6.16x |

Every ratio over 1 means slower. The hit mixes come from synthetic queries drawn from the merge table, **not** observed real tokenizer traffic. Dense lookups may auto-vectorize; the compact path has popcount, branches and dependent loads. Absolute nanoseconds include possible shared-runner noise. This is neither a comparison against the shipped hash-table probe nor a measurement of total toks speed.

## Reproduce

1. Run python3 tools/ci/fetch_tokenizers.py.
2. Run python3 tools/bench/k6_compact_fixture.py ~/.cache/toks/tokenizers/gpt2 build/k6/gpt2.bin.
3. Compile tools/bench/k6_compact_probe.c with cc -std=c11 -O3 -Wall -Wextra -Werror -o build/k6/probe.
4. Run build/k6/probe build/k6/gpt2.bin --bench. Use -fsanitize=address,undefined for a second pass.

The CI artifact holds original generated fixtures, input hashes, sanitizer evidence, machine fingerprint, and raw benchmark logs.

**Review result:** memory saving is real for this standalone data structure; a performance improvement is not demonstrated. Do not ship this lookup without comparing against the real hash path on pinned machines and passing end-to-end HF parity and the maintainer's no-regression benchmark gate.
