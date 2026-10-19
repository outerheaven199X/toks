# Windows Python tokenization: first-pass comparison with Hugging Face

Community experiment by ANTIMEME SYSTEMWORKS, 2026-10-18. This measures CPU text-to-token IDs, not model inference.
The historical run reports Windows 11, Ryzen 7 9800X3D, CPython 3.12.14 and the AVX2 path. Hardware and execution
are self-reported; the archive cannot independently attest them. No GPU participates.

The single-worker result is **17–22x on 512-byte inputs; 41–56x on long and batched inputs, where 58–78% of bytes
repeat within the pass**. Both implementations produced identical IDs for 6,240 distinct tokenizer/text pairs.

Median million input tokens/s over six rounds, with each API/trial in a new process. HF is the faster of the two
measured HF APIs (`hf_fast` in every cell); the ratio uses unrounded rates. Min/max values and all supplementary
rows are in the linked report and machine-readable data.

| Tokenizer | Input | toks | HF | Ratio | Repeated bytes in pass |
|---|---|---:|---:|---:|---:|
| zai-org/GLM-5.3-Flash | 512 B | 24.75 | 1.43 | 17.35x | ~14% |
| zai-org/GLM-5.3-Flash | 64 KiB | 53.53 | 1.31 | 40.93x | ~58% |
| zai-org/GLM-5.3-Flash | 32 × 4 KiB | 73.05 | 1.58 | 46.23x | ~78% |
| Qwen/Qwen3.8-27B | 512 B | 25.24 | 1.17 | 21.56x | ~14% |
| Qwen/Qwen3.8-27B | 64 KiB | 53.53 | 1.18 | 45.22x | ~58% |
| Qwen/Qwen3.8-27B | 32 × 4 KiB | 73.71 | 1.37 | 53.77x | ~78% |
| deepseek-ai/DeepSeek-V4.1-Flash-1017 | 512 B | 25.98 | 1.18 | 22.04x | ~14% |
| deepseek-ai/DeepSeek-V4.1-Flash-1017 | 64 KiB | 56.10 | 1.16 | 48.36x | ~58% |
| deepseek-ai/DeepSeek-V4.1-Flash-1017 | 32 × 4 KiB | 73.70 | 1.31 | 56.06x | ~78% |

## Protocol and limits

Six balanced API orders, separate parity processes, 216 accepted timing receipts across 12 cells. Nine rejected
attempts are retained; seven failed only during the warm-repeat phase. Including them changes the affected
headline ratios by at most 1.4%, according to the independent review. Warm replay and eight-worker Python calls
are supplementary, not headline speed or native scaling claims.

Loading/tokenizer construction is outside timing. Python strings are prepared outside timing; their first UTF-8
conversion occurs during the timed call in both libraries. A new tokenizer starts with an empty object cache,
but overlapping corpus windows reuse bytes during that first pass. Approximate reuse is 14% short, 58% long and
78% batch; the batch code half reaches 91%.

Run-start CPU samples were 2.25–6.45%; accepted pre-trial samples were 0.39–9.96%, below the 10% gate. Every toks
first pass lasts only 5–13 ms, below reliable Windows CPU accounting resolution. Background load during those
passes is therefore unresolved. This is a single reported Windows CPU, not a general hardware comparison.

The independent reviewer recomputed all 576 summary values without kit code, with no mismatches. The extended
auditor passes 741 checks. Reviewer-built Linux toks produced matching IDs in all nine unique input cells, with
13.4–44.2x ratios on different hardware. The reviewer did not independently rebuild the Windows binary.

## Artifacts and reproduction

- [Interactive results and full evidence download](https://huggingface.co/spaces/b4ph/toks-windows-benchmark)
- [Report, harness, commands and full-precision data](https://github.com/outerheaven199X/toks-windows-benchmark)
- [Independent review](https://github.com/outerheaven199X/toks-windows-benchmark/blob/main/evidence/INDEPENDENT_REVIEW.md)

Public ZIP SHA-256: `716833fe83e11ed15d831c3f4d11bfed971be50c1553bae479cb55687fd956f1`.
It contains the exact wheel, source Git bundle, pinned tokenizer/corpus assets, original timing/parity records,
four unchanged hashed measurement sources, auditor and an explicit metadata-redaction ledger. Private desktop
identifiers were removed; numerical measurements were preserved. The publication does not rerun the timings.

Historical wheel: `toks-0.3.2-cp312-cp312-win_amd64.whl`, SHA-256
`c15cc2b01b861d26c00d1366e44db0b900df1e9eb65574a4a8330dd4ff7c0c76`.
Historical source pin: `ca80a3ed4a45fdabd934f5b5ff818ac3efc0f3e9` in the fork bundle; tokenizer code matches upstream
v0.3.2. These are the measured artifacts, not a claim that a newly built wheel reproduces identical timings.

```powershell
git clone https://github.com/outerheaven199X/toks-windows-benchmark.git
Set-Location toks-windows-benchmark
python tools/download_evidence.py
$kit = 'evidence/run/toks-vs-hf-windows-v2-public'
python "$kit/audit_results.py" "$kit/runs/20261018-183431" audit-recheck.json
```

The report explains the correct fresh-run launcher and software setup. The historical local preparation launcher
is not in the archive. The worker receipts record the measurement-source hashes; they do not prove how the
desktop was prepared. The public report carries this limitation rather than implying that the included launcher
started the historical run.
