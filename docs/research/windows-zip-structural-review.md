# ZIP layout hardening / independent review round 3

This branch is a narrow research continuation on top of the independently checked Windows-wheel remediation. It does not open a PR or gate upstream releases.

## Finding and fix

The supplied zipsmuggle.py inserted an unindexed ZIP local-file record containing a .pth payload, then moved the central directory. The original auditor trusted Python zipfile's central directory, so it accepted that archive even though a different ZIP reader could interpret the extra record. No tested pip or uv version was observed extracting that hidden file; this is an **archive layout audit gap**, not demonstrated code execution.

The new verify_zip_layout function walks the ZIP32 central directory and **every referenced local header**, validates matching names, flags, timestamps, sizes and CRCs, and rejects gaps, overlaps, comments, prepended/trailing data, data-descriptor and ZIP64 variants. This research build intentionally accepts only the simple wheel layout it itself produces; different legitimate ZIP profiles need review before approval.

The reviewer script's outcomes after the change:
- Hidden .pth local record: rejected (previously accepted).
- Nonempty ZIP comment: rejected by strict policy (not evidence of an executable vulnerability).
- Reordered members and ZIP_STORED encoding: accepted, because all bytes are accounted for and member hashes match.
- RECORD re-quoted with CRLF: accepted, because the parsed entries and SHA-256s are the same.
- PE linker timestamps changed together: still accepted intentionally; the two timestamps are documented exceptions in the normalized .pyd fingerprint.

The local mutation suite adds five new tests. The existing source files, metadata and PE data remain pinned to reference fork build 39089648806. All claims are specific to this one release candidate family, not generic supply-chain safety.

## CI reproducibility

The fork workflow pins the setup-uv action to its immutable GitHub SHA **and uv itself to 0.13.1**. Fresh wheel verification explicitly installs CPython 3.12.15 and pytest 9.1.1, with tokenizers==0.23.2. The Python smoke settings still reduce generated cases (TOKS_PY_N=100 vs 1500) and force six case-set skips (TOKS_PY_CASES=0). Dependencies below the top-level packages and shared Windows image/toolchain are not fully locked.

## Independent acceptance

Independently clone this branch, verify the SHA and raw source, reproduce zipsmuggle.py on an audited cp312 artifact, attempt different unindexed or colliding local headers, and test actual installers on Windows. Confirm unchanged five original wheels and fresh branch build pass the stricter audit. Verify **current SHA**, not a green workflow on an earlier commit. Do not treat the author-run tests as an independent endorsement.

This remains an unsigned research branch. Actual Computer's required real-name DCO sign-offs, its additional licensing grant, and upstream release integration remain unresolved.
