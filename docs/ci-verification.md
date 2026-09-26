# Cryptographic Code Integrity backend

This pass replaces the unconditional unavailable-verifier result with a separate
cryptographic verifier and a guest ABI adapter. Firmware, storage, and user-mode
environment work are outside this pass.

## Evidence boundaries

`CiCheckSignedFile` receives an algorithm, digest, and complete attribute
certificate table. It verifies the signature over the signed indirect-data
content, compares that content's algorithm and digest with the request, and
evaluates signer trust. It does not receive a file: success authenticates the
supplied digest, not an independently identified file on disk.

`CiValidateFileObject` has the stronger input: a snapshot of the actual guest
file bytes. Its digest must use PE Authenticode/SIP semantics; an ordinary hash of
the whole file is not interchangeable. A successful digest output is tied to
those bytes and verification evidence.

`CiVerifyHashInCatalog` requires both exact member digest/algorithm membership
and a valid signature and trusted signer on the catalog. The catalog inputs are
snapshots from the guest filesystem. The host's catalog database, a catalog
filename, and an unsigned member record are not trust evidence.

## Trust policy

The Windows backend uses CryptoAPI and the host's certificate trust anchors.
It disables network retrieval. Default offline verification does not assert
revocation freshness; its result explicitly records that revocation was not
checked. A cache-required revocation mode must fail if definite cached evidence
is unavailable. Tests can use an application-owned exclusive root store without
installing roots into Windows.

Trust evaluation uses the host's verification clock and certificate stores, or a
verified timestamp when applicable. The emulator's synthetic guest clock is not
used as a substitute for certificate validity. Consequently, results depend on
the selected trust anchors, verification time, and available cached evidence;
captures record the input identities and policy rather than claiming a timeless
or installation-independent trust result.

Only authenticated timestamps bound to the signer's signature may select a
historical verification time. A signing-time attribute alone cannot rescue an
expired certificate. Timestamp evidence has its own TSA signature, chain, and
usage checks.

Authenticode trust does not reproduce all kernel-CI policy. WDAC, accepted-root
masks, secure-process policy, and signing-level decisions require additional
evidence and are not silently treated as satisfied. Unknown policy bits remain
unset. Other host platforms report that this backend is unavailable.

## Guest ownership

The adapter keeps the eight-argument signed-file ABI and the 48-byte policy
layout. Host certificate pointers never enter guest memory. Verified certificate
DER, digests, names, and validity dates populate bounded, owned guest buffers.
Cleanup follows host ownership records and is safe to repeat; it does not free
arbitrary addresses supplied by the guest. Catalog names use guest pool storage.
The caller releases catalog names with `ExFreePool`. Chain allocations use a
private pool and are released by `CiFreePolicyInfo` on the original policy object;
freeing a copied policy clears the copy without destroying the original graph.

The modern chain layout is reverse-engineered and version-specific. Reserved
bytes remain zero. Unproven representations of public-key, EKU, or authenticated
attribute arrays are not invented to fill optional fields.

Catalog discovery scans the file map once, with caps on inspected entries,
matching files, individual catalog size, and total snapshot bytes. Empty guest
directories cannot amplify the scan. Snapshots are refreshed on each request.
The guest filesystem still lacks general synchronization for concurrent mutation
by multiple virtual CPUs. Output preflight checks mapped backing, not full PTE
write permissions or a transactional multi-range copy.

## Verification plan

Host tests exercise the actual verifier with private test roots, signed and
unsigned PE files, catalog members, tampered bytes, changed digests, malformed
tables, wrong usage, expiry, and untrusted chains. Guest tests exercise the real
CI entry points, chain inspection and cleanup, output capacities, two signed
system images, and guest-catalog lookup. A bounded Hyper-V target capture then
checks whether the observed CI requests now produce evidence-based outcomes.

Guest `.sys` and native `.exe` fixtures are only inputs to the emulator. They are
never installed or run on the host. Standalone host verifier tests execute only
the verification implementation.

Reproduce from the repository root with PowerShell 7, the configured Windows SDK,
and the mapped guest system images/catalogs:

```powershell
pwsh -NoProfile -File tests/scripts/build-ci.ps1
pwsh -NoProfile -File tests/scripts/prepare-ci-verifier-fixtures.ps1
pwsh -NoProfile -File tests/scripts/build-ci-verifier-tests.ps1 -Run
pwsh -NoProfile -File tests/scripts/build-drivers.ps1 -Driver ci_verification
pwsh -NoProfile -File tests/scripts/prepare-ci-guest.ps1
pwsh -NoProfile -File tests/scripts/run-conformance.ps1 -Driver ci_conformance
pwsh -NoProfile -File tests/scripts/run-conformance.ps1 -Driver ci_verification
pwsh -NoProfile -File tests/scripts/run-model-tests.ps1
```

The guest positive fixture requires host trust for its particular signed system
images and catalog. The isolated private-root suite does not. See
[`tests/ci/README.md`](../tests/ci/README.md) for optional real-image integration.

## Sources

- [Microsoft Code Integrity security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3644.pdf)
- [PE attribute certificate table](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [CryptMsgControl signature verification](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol)
- [Authenticode indirect data](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-spc_indirect_data_content)
- [Certificate chain building](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain)
- [Certificate chain policies](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy)
- [RFC 3161 verification](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptverifytimestampsignature)
- [Catalog membership](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatenumeratemember)
- [PE signing and SIP hashing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures)
- [Original CI layout research](https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h)
