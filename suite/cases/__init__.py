# SPDX-License-Identifier: GPL-2.0-only

from model import Batch


def build() -> tuple[Batch, ...]:
    """Collect every batch, reject duplicates and cases that assert nothing."""
    from . import (
        boot,
        control_ops,
        dmverity,
        fsverity,
        memfd_controls,
        policy,
        policy_signature,
        policy_text,
        securityfs,
    )

    batches = []
    for module in (
        securityfs, policy, policy_signature, policy_text, memfd_controls,
        dmverity, fsverity, boot, control_ops,
    ):
        batches.extend(module.build())
    terminal_seen = False
    for batch in batches:
        if terminal_seen and not batch.terminal:
            raise ValueError("ordinary batches must precede terminal batches")
        terminal_seen |= batch.terminal
        for case in batch.cases:
            if not case.checks:
                raise ValueError(f"case {case.id} asserts nothing")
    ids = [case.id for batch in batches for case in batch.cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id")
    return tuple(batches)
