# Windows wheel audit — independent-review remediation

**This is research on a fork, not an upstream release gate.** The Windows wheel source commit ca80a3ed4a45fdabd934f5b5ff818ac3efc0f3e9 belongs to outerheaven199X/toks, and upstream Actual Computer does not yet distribute these Windows wheels.

An independent reviewer found five bypasses in the first auditor (b48e237530184f142e8aae8ea80435d57a28a28a): arbitrary Python code, injected Requires-Dist, and three malformed WHEEL headers. All now have direct regression cases which regenerate RECORD. Extended tests check native PE executable tampering, metadata bodies, source Git blobs, and PE alignment.

The revised auditor pins eight Python/type/license files to Git blob SHA-1 and SHA-256; separately pins METADATA, WHEEL and top_level.txt bytes. The complete native extension is hashed against five ABI-specific archived Windows builds after normalizing only two validated PE linker timestamps. It checks imported DLLs and PE section alignment. Reference builds: GitHub Actions run 39089648806.

## Reproduction

Prerequisites: Git, Python, authenticated gh and unexpired GitHub artifacts, or the offline evidence bundle.

    gh run download 39089648806 --repo outerheaven199X/toks --dir build/previous
    python3 tools/ci/audit_windows_wheel.py --verify-source-root . build/previous/windows-wheel-3.12/*.whl

See the branch CI for exact five-wheel enumeration and the original reviewer's attacks. The Windows test profile uses TOKS_PY_N=100 (default 1500) and TOKS_PY_CASES=0 (six forced case-set skips). That is reduced smoke parity; no full case-set parity is claimed. Upstream-required original Linux commands are replayed separately in windows-review-upstream-command-replay.yml.

## Boundaries

This checks identity against a chosen fork build, not publisher authentication or absence of malicious source code in the reference. Runtime dynamic DLL loads and arbitrary code behavior are not proven safe by static PE inspection. The research workflow does not gate upstream release. The stacked fork commits lack the actual contributor's required DCO and additional license/patent grant; no PR or release was created.

Independent reviewers should independently verify the Git source pins, actual wheels and hashes, rerun the five attacks, invent native/code/metadata counterexamples with regenerated RECORD, and report test/environment deviations honestly. Self-run CI is author evidence, not independent endorsement.
