# SPDX-License-Identifier: GPL-2.0-only

import os

import ipe
from model import CaseState


def deploy_policy(policy: ipe.Policy, state: CaseState) -> None:
    """Write the signed policy into securityfs so the kernel loads it."""
    ipe.deploy_policy(policy.signed)


def activate_policy(name: str, state: CaseState) -> None:
    """Activate a policy as one case setup step."""
    ipe.activate_policy(name)


def set_enforcement(enabled: bool, state: CaseState) -> None:
    """Set enforcement as one case setup step."""
    ipe.set_enforcement(enabled)


def set_success_audit(enabled: bool, state: CaseState) -> None:
    """Set successful-decision auditing as one case setup step."""
    ipe.set_success_audit(enabled)


def open_node(
    entry: str,
    policy: ipe.Policy | None,
    state: CaseState,
) -> None:
    """Open a securityfs node for a later trigger."""
    if state.opened_file is not None:
        raise RuntimeError("case state already holds an open file")
    descriptor = os.open(ipe.node_path(entry, policy), os.O_WRONLY)
    state.resources.callback(os.close, descriptor)
    state.opened_file = descriptor


def read_node(
    entry: str,
    policy: ipe.Policy | None,
    state: CaseState,
) -> None:
    """Append one securityfs value to this case's observations."""
    state.observed.append(ipe.node_path(entry, policy).read_text().strip())


def read_binary_node(
    entry: str,
    policy: ipe.Policy | None,
    state: CaseState,
) -> None:
    """Append one binary securityfs value as hex."""
    state.observed.append(ipe.node_path(entry, policy).read_bytes().hex())


def unshare_user_namespace(state: CaseState) -> None:
    """Enter a child user namespace where init_user_ns capabilities do not apply."""
    # IPE asks for CAP_MAC_ADMIN in init_user_ns.  A capability held in a
    # child user namespace does not apply to its parent; ID maps do not alter it.
    os.unshare(os.CLONE_NEWUSER)


def clear_mac_admin(state: CaseState) -> None:
    """Remove CAP_MAC_ADMIN from the effective set, keeping it permitted."""
    from resources import capabilities

    capabilities.set_mac_admin_effective(False)


def raise_mac_admin(state: CaseState) -> None:
    """Restore CAP_MAC_ADMIN to the effective set from the permitted set."""
    from resources import capabilities

    capabilities.set_mac_admin_effective(True)


def drop_mac_admin(state: CaseState) -> None:
    """Remove CAP_MAC_ADMIN from both effective and permitted, irrecoverably."""
    from resources import capabilities

    capabilities.drop_mac_admin()
