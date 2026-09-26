# x64 kernel exception-handler entry

The kernel exception dispatcher now supplies the sign-extended exception code
in RAX when transferring to a selected `__except` handler. MSVC's compiled
`GetExceptionCode()` reads EAX at that entry point. Previously the generic guest
callback restored the pre-fault registers after calling the personality routine,
and the dispatcher changed only RIP and RSP. The handler consequently consumed
the old EAX value rather than the exception code.

This matches the examined guest kernel's `__C_specific_handler` path: it passes
the sign-extended exception code as `RtlUnwindEx`'s return value, which is restored
through `CONTEXT.Rax`. The guest kernel used for that investigation was Windows
10.0.26100.9444, SHA-256
`75665496A75FC020A0573523F3F77D7C719479ACEB5806A98D82FF2D1B5314A1`.

The change belongs at the final handler transfer, after callback register
restoration. Ordinary callbacks retain their existing register preservation.
The user-mode exception dispatcher and `EXCEPTION_CONTINUE_EXECUTION` path are
unchanged. The adjustment is guarded for x64; ARM64 handler-entry semantics have
not been validated by this pass.

This is a bounded handler-entry correction, not a complete implementation of
Windows exception unwinding. In particular, it does not establish correctness
of cross-frame register restoration, termination-handler sequencing, or context
changes made by filters. DEBUGCTL emulation and debugger API behavior remain
separate work.

## Regression coverage

Build and run the emulator-only fixture:

```powershell
tests/scripts/build-drivers.ps1 -Driver exception_conformance
tests/scripts/run-conformance.ps1 -Driver exception_conformance
```

Its leaf helpers put `0x13579bdf` in EAX immediately before invalid RDMSR and
UD2 instructions. Compiler-generated `__except` handlers must observe
`0xc0000005` and `0xc000001d`, respectively. A same-frame assembly scope also
returns the entire handler-entry RAX, which must be `0xffffffffc0000005`.

The identical fixture failed all three value checks on the frozen pre-fix
executable (`8D5DFA0FAC28916584B261B5A54A28E0F8FB470EDA9F2C33775F5DD49FE51FD4`),
despite entering both C handlers. The corrected executable
(`099DBF49B82D6A4F8871D6C725913E08A043B4AB6FDDE7DD6CE4B460FC5F63A9`)
passed all five checks. Local manifests are
`build-conformance/exception_conformance-20260927-002422-198.json` (before) and
`build-conformance/exception_conformance-20260927-002438-885.json` (after).
`callback_conformance` and the `image_noexecute_enforcement` negative check
also passed: ordinary callbacks work and an unhandled execute fault remains
fatal. The original investigative RDMSR probe now reports `c0000005` instead
of zero.
