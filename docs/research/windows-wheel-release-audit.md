# Windows wheel release audit — verified research, not an upstream release

Branch: https://github.com/outerheaven199X/toks/tree/research/windows-release-audit
CI: https://github.com/outerheaven199X/toks/actions/runs/39117969708

This branch builds on research/windows-wheels-reviewed. No tokenizer core or ABI changes were made; the new code is a stdlib-only wheel inspector, twelve mutation-based tests, and an independent CI gate.

## What the audit validates

- Wheel name and CPython 3.10–3.14 ABI tag must match exactly the single packaged AMD64 CPython extension.
- Wheel file table is bounded, contains no duplicate paths, case-fold collisions, traversal paths, symlinks, unexpected extra Python/native executables, or missing licenses.
- Every member except RECORD itself is checked against the PEP 427/376 RECORD SHA-256 and declared byte size.
- WHEEL and METADATA fields are consistent with toks, version, architecture, and Apache-2.0 metadata.
- The PE32+ native extension must be AMD64, export precisely PyInit__toks, have no delay-import directory, and directly import the expected CPython DLL plus only approved Windows CRT/system DLLs.
- Mutation cases validate forged metadata, changed RECORD hash, renamed PE export, injected native import, hidden extra file, wrong ABI name, and invalid native binary.
- CI uploads an audited candidate wheel **only after** the full mutation and pinned HF parity steps pass.

## Completed evidence

- Five original Windows wheels from run 39089648806, whose source commit is SHA ca80a3ed4a45fdabd934f5b5ff818ac3efc0f3e9, independently re-audited on Linux; all accepted. Names, PE import lists, SHA-256 hashes, and member counts appear in CI's JSONL artifact.
- Fresh Windows CPython 3.12 wheel compiled on the branch and accepted by the same auditor. All twelve negative/positive audit tests passed.
- Installed fresh cp312 wheel ran existing Python API/thread/HF parity tests: 140 passed, nine skipped, zero failed. Those skips include missing larger case sets and reference fixtures and are not claimed as passes.
- This is in addition to the parent Windows branch's five-version build/install/parity matrix, full C/asm native/scalar regression, and Linux wheel regression.

## Honest boundary

RECORD checks establish consistency with the package's own manifest, **not cryptographic publisher authentication**. Native import inspection is a static view of the PE tables; it cannot prove absence of dynamic LoadLibrary calls or malicious execution. This audit cannot replace an independent wheel install, SBOM/supply-chain review, maintainer-owned release CI, Python/Windows support policy, or the project's required contribution license sign-off.

The strict filename/member allowlist is deliberately version-specific: a legitimate packaging change may require updating the auditor after review. The audit does not automatically publish to PyPI or create a GitHub release. It remains a user-owned fork research branch and **no PR has been opened**.
