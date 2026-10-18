# Research: model-vocabulary control ID audit

**This does not satisfy the structural isolation release requirement (SPEC §3.6).**
It is a conservative, inspectable prerequisite for deciding whether a specific
control ID could be produced by the raw tokenizer model. It does not change
toks's compiler, C ABI, or output, and does not protect an application's prompts.

The caller passes exact names of structural delimiters. The tokenizer's
"special" flag covers more than structural delimiters (e.g. unknown and padding
symbols); the script deliberately does not infer which are controls.

## Claim and modes

For a hypothetical call to encode(text, added_tokens="none",
add_special_tokens=False), the script reads the tokenizer JSON's BPE,
WordPiece, or Unigram vocabulary and the control ID declared by each named
special added token.

- **vocab_disjoint**: the selected control ID does not appear in the model
  vocabulary's ID set. Under the stated modeling assumption (the raw model
  emits IDs only from this set), raw model emission cannot create the ID.
- **vocab_overlap**: the ID does appear. The finding is "inconclusive", not
  "reachable" and not evidence of an exploit; a vocabulary entry need not be
  reachable by normal tokenization.
- Unknown model shape, malformed vocabulary, invalid IDs, missing/unflagged
  controls, and an unknown-token reference outside the vocabulary fail closed.

This is not a formal end-to-end certificate. It **excludes** added-token
recognition, post-processing (including automatic BOS/EOS), truncation/padding
effects, application-level prompt assembly, and any behavior inconsistent with
the model's declared vocabulary. It neither proves nor measures resistance to
prompt injection. The analyzer reads source JSON, not the C compiler's
post-load tables. It has no authority to declare an application safe.

## Reproduce

    python3 -m unittest discover -s tests/security -p 'test_*.py' -v
    python3 tools/ci/fetch_tokenizers.py
    python3 tools/security/control_id_audit.py ~/.cache/toks/tokenizers/llama3 --control '<|eot_id|>'

Use --require-disjoint for an automation that should fail on overlap.
Every JSON record includes the SHA-256 of the tokenizer bytes and the encoding
mode being assessed. The dedicated research GitHub Actions run audits five
pinned real tokenizer configurations and retains JSON evidence.

## Required before calling the release requirement met

Derive the selected control sets from an explicit contract, model every output
path (including templating and added tokens), prove or soundly approximate
reachability over the **compiled** tables for all four algorithms, and check
the C/Python surfaces and CI on each ISA. A finite corpus of adversarial
strings is useful for finding counterexamples, not proof of unreachability.
