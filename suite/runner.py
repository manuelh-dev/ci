# SPDX-License-Identifier: GPL-2.0-only

import json
import os
import signal
import traceback
from contextlib import ExitStack
from dataclasses import replace
from typing import TextIO

import cases
import ipe
import runtime
from assets import BASELINE_POLICY
from model import Case, CaseState, Observation

CASE_TIMEOUT_SECONDS = 180


def error_report(message: str) -> dict:
    """A complete report for a child that could not produce an observation."""
    return {
        "error": message,
        "errno": None,
        "returncode": None,
        "message": "",
        "observed": [],
    }


def run_in_child(case: Case) -> dict:
    """Fork and run all case phases with one fresh state."""
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            # Give this case its own process group so the parent can kill leftover descendants.
            os.setsid()
            os.close(read_fd)
            signal.alarm(CASE_TIMEOUT_SECONDS)
            try:
                with ExitStack() as resources:
                    case_state = CaseState(resources=resources)
                    for step in case.collect:
                        step(state=case_state)
                    for step in case.setup:
                        step(state=case_state)
                    observation = (
                        case.trigger(state=case_state) if case.trigger else Observation()
                    )
                    observation = replace(
                        observation,
                        observed=tuple(case_state.observed),
                    )
                report = {
                    "error": None,
                    "errno": observation.errno,
                    "returncode": observation.returncode,
                    "message": observation.message,
                    "observed": list(observation.observed),
                }
            except BaseException as failure:
                report = error_report(f"{type(failure).__name__}: {failure}")
            with os.fdopen(write_fd, "w", encoding="utf-8") as pipe:
                json.dump(report, pipe)
        except BaseException:
            os._exit(1)
        os._exit(0)

    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as pipe:
        payload = pipe.read()
    _, status = os.waitpid(child, 0)
    try:
        os.killpg(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGALRM:
        return error_report(f"case exceeded {CASE_TIMEOUT_SECONDS}s")
    if not os.WIFEXITED(status):
        return error_report(f"child terminated abnormally: {status}")
    if os.WEXITSTATUS(status) != 0:
        return error_report(f"child exited with status {os.WEXITSTATUS(status)}")
    if not payload:
        return error_report("child produced no result")
    return json.loads(payload)


def test(case: Case, *, restore_state: bool = True) -> tuple[str, str] | None:
    """Run and check one case, restoring common IPE state unless terminal."""
    try:
        with runtime.case_scope(*case.extra_scopes, restore_state=restore_state):
            result = run_in_child(case)
            if result["error"]:
                return "error", result["error"]
            observation = Observation(
                errno=result["errno"],
                returncode=result["returncode"],
                message=result["message"],
                observed=tuple(result["observed"]),
            )
            for check in case.checks:
                if problem := check(observation=observation):
                    return "failure", problem
            return None
    except Exception as failure:
        traceback.print_exc()
        return "error", f"{type(failure).__name__}: {failure}"


def run(output: TextIO) -> int:
    """Run every batch, emitting TAP to the output stream."""
    def emit(line: str) -> None:
        output.write(line.replace("\n", " ").replace("\r", " ") + "\n")
        output.flush()

    batches = cases.build()
    planned = [case for batch in batches for case in batch.cases]
    emit("TAP version 13")

    number = 0
    with ExitStack() as run_resources:
        run_resources.enter_context(runtime.run_scope())
        ipe.deploy_policy(BASELINE_POLICY.signed)
        ipe.activate_policy(BASELINE_POLICY.name)
        for batch in batches:
            if batch.terminal:
                # Irreversible cases must not prevent ordinary suite cleanup.
                run_resources.close()
            try:
                with runtime.batch_scope(
                    *batch.extra_scopes, restore_state=not batch.terminal
                ):
                    for step in batch.setup:
                        step()
                    for case in batch.cases:
                        number += 1
                        outcome = test(case, restore_state=not batch.terminal)

                        if outcome is None:
                            emit(f"ok {number} {case.id}")
                        else:
                            kind, message = outcome
                            prefix = "error " if kind == "error" else ""
                            emit(f"not ok {number} {case.id} # {prefix}{message}")
            except Exception as failure:
                traceback.print_exc()
                emit(f"Bail out! batch {batch.id} failed: {failure}")
                return 0

    emit(f"1..{len(planned)}")
    return 0
