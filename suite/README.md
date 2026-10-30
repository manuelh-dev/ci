# Guest suite layout

| Location | Responsibility |
|---|---|
| `cases/` | Concrete test inputs, policies and expected results. Each group supplies batches; the `dmverity/` and `fsverity/` packages keep their shared setup, cleanup scopes and explicit case order in `__init__.py`, with one module per operation. |
| `operations/` | One module per tested operation: its trigger, result checks, operation-specific resource scopes and case factory. |
| `resources/` | Shared guest resources: files, mounts, module loading, keyrings and capabilities. These helpers do not define test cases. |
| `model.py`, `runner.py`, `runtime.py`, `scope.py` | Common case model, child-process execution, TAP reporting and state restoration. |
| `ipe.py`, `steps.py`, `triggers.py`, `checks.py` | IPE securityfs access, case setup/read-write steps and common assertions. |
| `assets.py` | Named policy assets. Build/guest paths and hash lists come from the staged `layout` and `hashes` modules. |
| `command.py`, `nodeio.py` | Command execution and raw node I/O. |

For example, `cases/dmverity/kexec_image.py` declares which kernel file and policy
to use and what result is expected. `operations/kexec.py` constructs that Case,
invokes the syscall, checks the staged state and owns kexec-slot cleanup. The
runner does not dispatch on an operation name or know those details.

Shared resource scopes stay in `resources/`; operation-owned scopes stay beside
the operation, such as kexec's image slot and memfd's temporary hugepage pool.
`cases/memfd_controls.py` contains the concrete baseline controls, not another
copy of the memfd implementation.

Imports and case order are explicit. There is no plugin discovery or generated
runtime registry. Keep errno, program exit status and resulting state separate;
process exit releases process-local memory, not global kernel resources.

Terminal batches run last, after the runner restores ordinary suite state.
They retain the same child execution, checks and TAP reporting, but do not
restore common IPE state between cases or at batch exit. Explicit resource
scopes still run. Use this only for irreversible changes, such as a final
policy that denies further control-plane changes; the disposable guest is
powered off afterwards. Ordinary batches cannot follow a terminal batch.

The `control_operations` terminal batch signs its fixtures with the existing
builtin test identity at build time. It first exercises compatibility and
selective denials, then installs a policy denying all eight control operations.
The final case checks rejected mutations and successful no-op writes. This
sequence requires a fresh guest boot. It does not cover initial loading with
no active policy: this image starts with a built-in boot policy.
