# Code Integrity boundary: earlier ABI repair

This page records the earlier failure-only adapter and its ABI corrections.
The current cryptographic backend, policy, and validation are described in
[CI verification](ci-verification.md).

The modern 64-bit CI adapters use explicit guest layouts and initialize failure
outputs consistently. They do not implement Authenticode signature verification,
certificate-chain trust, revocation, or a catalog database. A failed verification
request therefore does not establish that the input image has a bad signature.
The diagnostic identifies the absent backend; `STATUS_INVALID_IMAGE_HASH` is the
emulator's compatibility failure result, not the outcome of a cryptographic check.

## ABI correction

The previous `CiCheckSignedFile` adapter decoded nine arguments. The modern API
has eight: hash, hash size, algorithm, signature, signature size, signer policy,
signing time, and timestamp policy. The adapter misidentified timestamp policy as
a digest and wrote through an invented ninth size pointer. On x64 this reads
caller storage at entry RSP+0x48. An unmapped value faults; a mapped value can cause
silent corruption. The four faults in the 2026-09-26 capture affected the kernel
image's four digest attempts. The later filter-manager attempts used a different
stack position; their lack of faults did not prove correct output handling.

The policy structure is 48 bytes: size at 0, verification status at 4, policy bits
at 8, chain pointer at 16, revocation time at 24, and validity times at 32 and 40.
Its size field describes the returned structure; it is not treated as a buffer
capacity. Callers supplying a policy output must provide the complete structure.
The former local definition was 40 bytes and did not describe these fields.

The catalog adapter's seventh argument is signer policy, not a catalog handle.
Both catalog and signed-file verification return signer and timestamp policy.
`CiValidateFileObject` uses a one-byte signing-level argument and has distinct
digest-buffer, size, and algorithm outputs. A raw SHA-256 of the entire file is
not an Authenticode digest, so this unavailable backend does not return one.

## Failure and ownership model

For unavailable verification, present policy outputs contain size 48, a failure
status, and zero policy bits, chain pointer, and times. Signing time is zero.
Catalog name is empty. File validation returns no digest: its size and algorithm
are zero, and the caller's digest buffer is untouched. Invalid file objects report
`STATUS_INVALID_PARAMETER` rather than claiming an image was verified.

No CI chain or catalog-name allocation is created by this backend. Cleanup clears
the complete policy and is safe to repeat; it does not follow or free arbitrary
guest chain pointers. Adding a real verifier will require explicit allocation
ownership and matching release behavior.

Output ranges are checked before the first write, including overflow checks.
An inaccessible output produces an explicit boundary diagnostic and
`STATUS_ACCESS_VIOLATION`, rather than escaping into the generic hook and leaving
a stale return register. This is an emulator failure contract. The current memory
access abstraction checks backing, not guest write permissions; it does not
provide concurrent-unmap atomicity or validate a caller's allocation capacity.

## Sources and limits

Modern signatures and layouts follow the authored
[System Informer declarations](https://github.com/winsiderss/systeminformer/blob/0a12d2a1d6ed24daf9a8d619b3596e03fc2c5b70/KSystemInformer/include/ntfill.h)
and the original
[CiDllDemo research code](https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h).
These are reverse-engineered interfaces, not a stable documented Windows DDI.
Older six-argument signed-file and eight-argument catalog variants are not
implemented. Runtime verification here targets x64 WHP; other architectures need
their own execution checks.

The guest CI fixture imports the actual CI exports and checks poisoned unused
stack storage, both policy outputs, output guards, optional outputs, repeated
cleanup, catalog output positions, and controlled invalid-pointer failures.
Use `tests/scripts/build-ci.ps1`, then run `ci_conformance` through
`tests/scripts/run-conformance.ps1`; never load the fixture as a host driver.

## Verification on 2026-09-26

The same CI fixture produces 44 failing assertions on the preceding executable,
including all four mapped ninth-slot canaries being overwritten and two CI hook
faults. On the corrected executable, all 52 CI assertions pass, as do the 15
thread-ownership checks. Independent source review found no material issues.

The kernel-only WHP capture in `build-conformance/kernel-20260926-130632-839`
lasts 210.039 seconds and is stopped at its requested limit. Initialization
returns zero. All eight signed-file requests return without hook or output-memory
faults, compared with four CI hook faults in the preceding capture. The
three-minute timer expires and subsequent reads return true 19 times. There are
no missing-export, callback-failure, or unhandled-exception diagnostics; 144
handled exceptions and other subsystem warnings remain.

The guest kernel is 10.0.26100.9444 and the guest CI DLL is 10.0.19041.6456; this
is a mixed guest image set, not a stock Windows installation. The manifest pins
both hashes. The capture uses the existing user-provided in-memory compatibility
patch on a separate local lab branch. No user-mode service is launched and the
driver file is unchanged. This validates the CI boundary, not certificate trust
or the correctness of every monitoring path.
