# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Generator
from contextlib import ExitStack, contextmanager

import ipe
from scope import ContextFactory, collection, setting


@contextmanager
def run_scope() -> Generator[None, None, None]:
    """Restore the original active policy and remove new ipe_test_ policies."""
    with ExitStack() as stack:
        stack.enter_context(
            collection(members=ipe.test_policy_names, discard=ipe.delete_policy)
        )
        stack.enter_context(
            setting(read=ipe.active_policy, write=ipe.activate_policy)
        )
        yield


@contextmanager
def batch_scope(
    *extra: ContextFactory, restore_state: bool = True
) -> Generator[None, None, None]:
    """Optionally restore common IPE state; always restore explicit scopes."""
    with ExitStack() as stack:
        if restore_state:
            stack.enter_context(
                setting(read=ipe.enforcement, write=ipe.set_enforcement)
            )
        for make_context in extra:
            stack.enter_context(make_context())
        yield


@contextmanager
def case_scope(
    *extra: ContextFactory, restore_state: bool = True
) -> Generator[None, None, None]:
    """Optionally restore common IPE state; always restore explicit scopes."""
    with ExitStack() as stack:
        if restore_state:
            stack.enter_context(
                collection(members=ipe.test_policy_names, discard=ipe.delete_policy)
            )
            stack.enter_context(
                setting(read=ipe.active_policy, write=ipe.activate_policy)
            )
            stack.enter_context(
                setting(read=ipe.enforcement, write=ipe.set_enforcement)
            )
            stack.enter_context(
                setting(read=ipe.success_audit, write=ipe.set_success_audit)
            )
        for make_context in extra:
            stack.enter_context(make_context())
        yield
