# SPDX-License-Identifier: GPL-2.0-only
"""Exercise control authorization last, then leave the disposable guest sealed."""

import errno
from functools import partial

import checks
import ipe
import nodeio
import steps
import triggers
from assets import policy
from model import Batch, Case, CaseState, CaseStep, Check, Observation

PRIMARY_NAME = "ipe_test_control_primary"


def primary(version: int) -> ipe.Policy:
    """One policy name with signed, monotonically increasing updates."""
    return policy(asset=f"control/primary-{version}", name=PRIMARY_NAME)


ALTERNATE = policy(asset="control/alternate", name="ipe_test_control_alternate")
ACTIVATION_TARGET = policy(
    asset="control/activation-target", name="ipe_test_control_activation_target"
)
DELETE_TARGET = policy(asset="control/delete-target", name="ipe_test_control_delete")
LATE_POLICY = policy(asset="control/late", name="ipe_test_control_late")
BLOCKED_POLICY = policy(asset="control/blocked", name="ipe_test_control_blocked")
UPDATE_DENIED = policy(asset="control/update-denied", name="ipe_test_control_update")
UPDATE_CANDIDATE = policy(
    asset="control/update-candidate", name=UPDATE_DENIED.name
)


def prepare() -> None:
    """Start from trusted signed policies after the ordinary suite has cleaned up."""
    ipe.set_enforcement(True)
    ipe.set_success_audit(False)
    for fixture in (primary(1), ALTERNATE, ACTIVATION_TARGET, DELETE_TARGET):
        ipe.deploy_policy(fixture.signed)
    ipe.activate_policy(PRIMARY_NAME)


def update_primary(version: int, state: CaseState) -> None:
    """Install a signed update; updating the active policy keeps it active."""
    nodeio.write_path(
        ipe.node_path(ipe.node.UPDATE, primary(1)), primary(version).signed.read_bytes()
    )


def compatible_activation(state: CaseState) -> Observation:
    """Switch both ways while neither policy names a control operation."""
    ipe.activate_policy(ALTERNATE.name)
    ipe.activate_policy(PRIMARY_NAME)
    return Observation(errno=0)


def compatible_audit(state: CaseState) -> Observation:
    """Both audit transitions remain allowed under a global DENY."""
    ipe.set_success_audit(True)
    ipe.set_success_audit(False)
    return Observation(errno=0)


def compatible_enforcement(state: CaseState) -> Observation:
    """Both enforcement transitions remain allowed under a global DENY."""
    ipe.set_enforcement(False)
    ipe.set_enforcement(True)
    return Observation(errno=0)


def sealed_changes(state: CaseState) -> Observation:
    """Observe each mutation and no-op without trying to undo the final policy."""
    writes = (
        ("load", ipe.node.NEW_POLICY, None, BLOCKED_POLICY.signed.read_bytes()),
        ("update", ipe.node.UPDATE, primary(1), primary(12).signed.read_bytes()),
        ("activation", ipe.node.ACTIVE, ACTIVATION_TARGET, b"1"),
        ("delete", ipe.node.DELETE, LATE_POLICY, b"1"),
        ("enforcement_off", ipe.node.ENFORCE, None, b"0"),
        ("audit_off", ipe.node.SUCCESS_AUDIT, None, b"0"),
        ("enforcement_noop", ipe.node.ENFORCE, None, b"1"),
        ("audit_noop", ipe.node.SUCCESS_AUDIT, None, b"1"),
    )
    for name, entry, fixture, data in writes:
        result = triggers.write_node(
            entry=entry, policy=fixture, data=data, state=state
        )
        state.observed.append(f"{name}={result.errno}")
    return Observation()


def sealed_errnos(observation: Observation) -> str | None:
    """Every effective change is denied and the two no-op writes succeed."""
    expected = tuple(
        f"{name}={errno.EACCES}"
        for name in (
            "load", "update", "activation", "delete", "enforcement_off", "audit_off"
        )
    ) + ("enforcement_noop=0", "audit_noop=0")
    if observation.observed != expected:
        return f"expected {expected!r}, got {observation.observed!r}"
    return None


def write_case(
    *,
    id: str,
    entry: str,
    data: bytes,
    fixture: ipe.Policy | None = None,
    expected_errno: int = 0,
    setup: tuple[CaseStep, ...] = (),
    result_checks: tuple[Check, ...] = (),
) -> Case:
    """Use the standard securityfs trigger and checks for one control write."""
    return Case(
        id=id,
        setup=setup,
        trigger=partial(triggers.write_node, entry=entry, policy=fixture, data=data),
        checks=(partial(checks.errno_is, expected=expected_errno), *result_checks),
    )


def build() -> tuple[Batch, ...]:
    """One ordered sequence, ending with irreversible policy self-protection."""
    active = partial(checks.policy_active_is, policy=primary(1), expected=True)
    enforced = partial(checks.node_value_is, entry=ipe.node.ENFORCE, expected="1")
    audit_on = partial(checks.node_value_is, entry=ipe.node.SUCCESS_AUDIT, expected="1")
    audit_off = partial(
        checks.node_value_is, entry=ipe.node.SUCCESS_AUDIT, expected="0"
    )
    return (
        Batch(
            id="control_operations",
            terminal=True,
            setup=(prepare,),
            cases=(
                # UPDATE denial must work independently of ACTIVATION denial.
                write_case(
                    id="policy_control_update_eacces",
                    setup=(
                        partial(steps.deploy_policy, policy=UPDATE_DENIED),
                        partial(steps.activate_policy, name=UPDATE_DENIED.name),
                    ),
                    entry=ipe.node.UPDATE,
                    fixture=UPDATE_DENIED,
                    data=UPDATE_CANDIDATE.signed.read_bytes(),
                    expected_errno=errno.EACCES,
                    result_checks=(
                        partial(
                            checks.policy_version_is,
                            policy=UPDATE_DENIED,
                            expected="0.0.1",
                        ),
                        partial(
                            checks.policy_active_is, policy=UPDATE_DENIED, expected=True
                        ),
                    ),
                ),
                write_case(
                    id="policy_control_omitted_load_ok",
                    setup=(partial(steps.activate_policy, name=PRIMARY_NAME),),
                    entry=ipe.node.NEW_POLICY,
                    data=LATE_POLICY.signed.read_bytes(),
                    result_checks=(
                        partial(
                            checks.policy_present_is, policy=LATE_POLICY, expected=True
                        ),
                    ),
                ),
                write_case(
                    id="policy_control_omitted_delete_ok",
                    entry=ipe.node.DELETE,
                    fixture=DELETE_TARGET,
                    data=b"1",
                    result_checks=(
                        partial(
                            checks.policy_present_is,
                            policy=DELETE_TARGET,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="policy_control_omitted_activation_ok",
                    trigger=compatible_activation,
                    checks=(partial(checks.errno_is, expected=0), active),
                ),
                write_case(
                    id="policy_control_omitted_update_ok",
                    entry=ipe.node.UPDATE,
                    fixture=primary(1),
                    data=primary(2).signed.read_bytes(),
                    result_checks=(
                        partial(
                            checks.policy_version_is,
                            policy=primary(1),
                            expected="0.0.2",
                        ),
                        active,
                    ),
                ),
                Case(
                    id="policy_control_omitted_audit_ok",
                    trigger=compatible_audit,
                    checks=(partial(checks.errno_is, expected=0), audit_off),
                ),
                Case(
                    id="policy_control_omitted_enforcement_ok",
                    trigger=compatible_enforcement,
                    checks=(partial(checks.errno_is, expected=0), enforced),
                ),
                write_case(
                    id="policy_control_load_eacces",
                    setup=(partial(update_primary, version=3),),
                    entry=ipe.node.NEW_POLICY,
                    data=BLOCKED_POLICY.signed.read_bytes(),
                    expected_errno=errno.EACCES,
                    result_checks=(
                        partial(
                            checks.policy_present_is,
                            policy=BLOCKED_POLICY,
                            expected=False,
                        ),
                    ),
                ),
                write_case(
                    id="policy_control_delete_eacces",
                    setup=(partial(update_primary, version=4),),
                    entry=ipe.node.DELETE,
                    fixture=LATE_POLICY,
                    data=b"1",
                    expected_errno=errno.EACCES,
                    result_checks=(
                        partial(
                            checks.policy_present_is, policy=LATE_POLICY, expected=True
                        ),
                    ),
                ),
                write_case(
                    id="policy_control_activation_eacces",
                    setup=(partial(update_primary, version=5),),
                    entry=ipe.node.ACTIVE,
                    fixture=ACTIVATION_TARGET,
                    data=b"1",
                    expected_errno=errno.EACCES,
                    result_checks=(active,),
                ),
                write_case(
                    id="policy_control_enforcement_off_eacces",
                    setup=(partial(update_primary, version=6),),
                    entry=ipe.node.ENFORCE,
                    data=b"0",
                    expected_errno=errno.EACCES,
                    result_checks=(enforced,),
                ),
                write_case(
                    id="policy_control_audit_on_eacces",
                    setup=(partial(update_primary, version=7),),
                    entry=ipe.node.SUCCESS_AUDIT,
                    data=b"1",
                    expected_errno=errno.EACCES,
                    result_checks=(audit_off,),
                ),
                write_case(
                    id="policy_control_audit_off_eacces",
                    setup=(
                        partial(update_primary, version=8),
                        partial(steps.set_success_audit, enabled=True),
                    ),
                    entry=ipe.node.SUCCESS_AUDIT,
                    data=b"0",
                    expected_errno=errno.EACCES,
                    result_checks=(audit_on,),
                ),
                write_case(
                    id="policy_control_enforcement_on_permissive_ok",
                    setup=(
                        partial(update_primary, version=9),
                        partial(steps.set_enforcement, enabled=False),
                        partial(update_primary, version=10),
                    ),
                    entry=ipe.node.ENFORCE,
                    data=b"1",
                    result_checks=(enforced,),
                ),
                Case(
                    id="policy_control_sealed",
                    setup=(partial(update_primary, version=11),),
                    trigger=sealed_changes,
                    checks=(
                        sealed_errnos,
                        partial(
                            checks.policy_version_is,
                            policy=primary(1),
                            expected="0.0.11",
                        ),
                        active,
                        partial(
                            checks.policy_present_is,
                            policy=BLOCKED_POLICY,
                            expected=False,
                        ),
                        partial(
                            checks.policy_present_is, policy=LATE_POLICY, expected=True
                        ),
                        enforced,
                        audit_on,
                    ),
                ),
            ),
        ),
    )
