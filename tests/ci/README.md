# Isolated host code-integrity tests

These are ordinary x64 Windows console executables, not guest drivers. They only
read PE/catalog bytes. They never load or execute a guest image, install a
certificate, access a network TSA, or modify a host root store.

From the repository root, with PowerShell 7 and SDK 10.0.28000.0:

```powershell
# Requires an already-built, unsigned build-conformance/ci_conformance.sys.
pwsh -NoProfile -File tests/scripts/prepare-ci-verifier-fixtures.ps1

# Independent fixture check, usable before the backend is ready:
pwsh -NoProfile -File tests/scripts/build-ci-verifier-tests.ps1 -FixturesOnly -Run

# Compile only the host tests and code_integrity.cpp, then test the backend:
pwsh -NoProfile -File tests/scripts/build-ci-verifier-tests.ps1 -Run
```

The backend uses the Windows SDK cryptography libraries. This script does not
install dependencies or perform a repository-wide build.

Fixtures and executables go under ignored `build-conformance/ci-fixtures` and
`build-conformance/ci-host-tests`. Fixture regeneration replaces the fixture
root, leaf keys, signed copies, and catalog. The input driver remains unchanged.
The PFX password is intentionally public: `ci-fixtures-only-not-a-secret`.
These keys and certificates are disposable test material.

The generator creates a memory-only .NET root and code-signing leaf, then signs
a copy of the unsigned driver with signtool. It creates wrong-EKU and expired
leaf variants by re-signing the same SPC content with SignedCms, bypassing
signtool's certificate eligibility checks. A valid re-signed control must also
pass backend verification. SignedCms and the independent CryptoAPI probe check
the actual cryptographic signatures without applying chain trust policy.

Offline RFC3161 fixtures append the Microsoft unsigned timestamp attribute
`1.3.6.1.4.1.311.3.3.1` to the expired signer's unchanged signature. TSTInfo uses
SHA-256 over `SignerInfo.GetSignature()`, and a genTime seven days before fixture
generation, inside the expired signer's validity window. The TSA has a critical,
timestamp-only EKU and is issued by the same private root. Tokens include the
SigningCertificateV2 attribute. WIN_CERTIFICATE length, eight-byte padding, and
the PE security directory size are updated without altering hashed PE content.

The generator checks token signatures and binding with .NET, and TSA trust with
an offline custom-root chain. The standalone probe independently checks the
embedded attribute and token binding with `CryptVerifyTimeStampSignature`, and
confirms the original code signature and SPC digest remain unchanged. A token
with a deliberately wrong imprint still has a valid TSA signature; an untrusted
self-signed TSA token has a valid imprint. These distinguish binding and trust
failures from broken cryptographic fixtures. A future token is also bound and
cryptographically valid, but its time falls after code-signer expiry.

The full suite requires the valid bound timestamp to rescue both signed-digest
and PE verification, with the exact verified genTime and a nonempty TSA chain.
Wrong-imprint, untrusted-TSA, future-time, and empty-root cases must not rescue
the expired signer. The existing no-timestamp expired cases remain controls.

The host suite decodes the signed SPC digest with CryptoAPI. Cases cover matching
and changed digests, bad sizes, algorithm mismatch, malformed WIN_CERTIFICATE and
PKCS7, tampered signature bytes, forged signed content with a matching caller
digest, missing trust anchors, wrong EKU, expired signer, modified PE payload,
unsigned and truncated PE, and catalog fallback. Tampered inputs are constructed
in memory from known fixture structures; the generated files stay intact.
SHA-1-only embedded signatures and corrupt catalogs before/after a valid SHA-1
catalog exercise algorithm fallback independently of catalog iteration order.

Catalog tests enumerate `CRYPTCATMEMBER::pIndirectData` and use its actual digest
and algorithm, including SHA-1 catalogs produced by makecat. Cases include a
trusted member, absent member, empty snapshots, untrusted catalog, and altered
catalog member content with the matching altered caller digest. Private-root
tests set `exclusive_roots=true`; an independent empty exclusive-root verifier
checks rejection. Optional integration cases use default system trust.

```powershell
& build-conformance/ci-host-tests/ci-verifier-tests.exe `
    build-conformance/ci-fixtures `
    --system-pe PATH_TO_GUEST_NTOSKRNL_EXE `
    --system-pe PATH_TO_GUEST_FLTMGR_SYS `
    --system-cat PATH_TO_EXISTING_CATALOG
```

System PE arguments and catalogs are optional and repeatable. Supplied catalogs
are available to every supplied PE; each catalog's actual members are also
checked. Host system trust must validate those real artifacts for these opt-in
checks to pass. The runner never searches or enrolls catalogs in the host catalog
database. With no optional arguments it explicitly reports integration skipped.

Exit status is 0 for passing executed checks, 1 for backend assertion failures,
and 2 for fixture/input errors. `unsupported` or `unavailable` never count as a
successful rejection of a supported negative fixture. The unknown-algorithm
test explicitly expects `unsupported`.

Coverage gaps are printed on every full run: legacy countersignatures, multiple
timestamp tokens, and revocation-cache policy. The future-token test establishes
failure to rescue an expired signer; it does not isolate a future-clock policy
from signer validity-window enforcement. No backend test success is implied by
the separate fixture-only probe.
