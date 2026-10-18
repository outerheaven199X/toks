"""Finite-probe regression contract independent of the compiled toks import.

These checks deliberately make no global token-reachability or application-level
prompt-injection claim.
"""
from __future__ import annotations


def assert_probe_contract(tokenizer, samples: list[str], control_id: int, *,
                          expected_positive_count: int, model: str) -> dict:
    """Check both encoding modes and fail on every observed unexpected ID.

    A witnessed ID for a model with overlapping vocabulary is an empirical
    counterexample to this selected test corpus, not by itself an exploit.
    """
    if not samples or len(samples) != len(set(samples)):
        raise AssertionError(f"{model}: empty or duplicate finite-probe inputs")
    if not isinstance(control_id, int) or control_id < 0:
        raise AssertionError(f"{model}: invalid selected control ID")
    if expected_positive_count < 1 or expected_positive_count > len(samples):
        raise AssertionError(f"{model}: invalid positive control expectation")
    ordinary_witnesses, positive_witnesses = [], []
    for sample in samples:
        none_ids = tokenizer.encode(sample, added_tokens="none", add_special_tokens=False)
        all_ids = tokenizer.encode(sample, added_tokens="all", add_special_tokens=False)
        if control_id in none_ids:
            ordinary_witnesses.append(sample)
        if control_id in all_ids:
            positive_witnesses.append(sample)
    # This assertion has its own deliberate simulated-leak unit test.
    if ordinary_witnesses:
        raise AssertionError(
            f"{model}: {len(ordinary_witnesses)} added_tokens=none witnesses; "
            "investigate whether legitimate vocabulary overlap explains them"
        )
    if len(positive_witnesses) != expected_positive_count:
        raise AssertionError(
            f"{model}: positive recognition count {len(positive_witnesses)} "
            f"!= pinned expected {expected_positive_count}"
        )
    return {
        "input_count": len(samples),
        "none_mode_witness_count": 0,
        "positive_control_witness_count": len(positive_witnesses),
        "expected_positive_control_count": expected_positive_count,
    }
