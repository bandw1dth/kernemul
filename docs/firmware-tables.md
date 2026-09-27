# Bounded firmware-table queries

This pass implements `Nt/ZwQuerySystemInformation` class 76 for the RSMB raw
SMBIOS provider. It is separate from the existing UEFI/NVRAM variable store.
The model, kernel/native conformance fixtures, regressions, and bounded VGK
capture passed. VGK's previously unsupported RSMB request now succeeds.

## Investigation

The fifteen-minute snapshot capture showed VGK calling class 76 during kernel
initialization and receiving `STATUS_INVALID_INFO_CLASS`. A 30-second diagnostic
capture, `build-conformance/kernel-20260927-135636-163/`, preserved that failure
while logging the input header. At stdout line 9231 the actual request is:

```text
ProviderSignature = 0x52534D42 (RSMB)
Action            = 1 (Get)
TableID           = 0
TableBufferLength = 4080
outer length      = 4096
```

DriverEntry still returned success. This establishes a missing query used by
VGK, not proof that the failure prevented initialization. The investigation ran
only `vgk.sys`, using the existing local-only compatibility stub; `vgc.exe` was
not started and the driver file was not modified.

## Contract and native observations

The [phnt native header](https://github.com/winsiderss/phnt/blob/master/ntexapi.h)
defines a 16-byte fixed header: four 32-bit fields for provider, action, table ID,
and payload length, followed by the variable payload. Microsoft documents the
related [GetSystemFirmwareTable](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable)
and [EnumSystemFirmwareTables](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-enumsystemfirmwaretables)
interfaces. RSMB enumeration returns one DWORD table ID, zero. Get returns an
8-byte `RawSMBIOSData` header and the SMBIOS structure-table bytes; it is not an
SMBIOS entry-point structure.

A read-only native probe on host kernel 10.0.26100.9457 established the behavior
below. The pinned guest kernel is 10.0.26100.9444, so this is nearby-build evidence,
not proof of every fault-ordering detail on the guest version. The probe records
only statuses, sizes, and write-boundary observations; no host SMBIOS identities
or raw payload are saved or used by the emulator. Local evidence is
`build-conformance/native-firmware-table-boundaries.json` and
`native-firmware-table-additional.json`, and
`native-firmware-table-alignment.json`. A separate in-memory comparison of
table IDs 0, 1, and 0xFFFFFFFF returned byte-identical payloads; only the equality
result and lengths are saved in `native-firmware-table-aliases.json`.

| Request | Native observation |
| --- | --- |
| Outer length below 16 | INFO_LENGTH_MISMATCH, ReturnLength 16 |
| RSMB with insufficient payload space | BUFFER_TOO_SMALL, payload unchanged, required payload length in header, total required length in ReturnLength |
| Sufficient outer buffer | Success, exact payload and total lengths |
| Input TableBufferLength zero or very large | Ignored for capacity; outer length controls the accessible payload space |
| Nonzero RSMB table ID | Accepted as an alias, including enumeration |
| Unknown provider | NOT_IMPLEMENTED, ReturnLength zero, request header unchanged |
| Invalid RSMB action | INVALID_PARAMETER_1, ReturnLength equals outer length, request header unchanged |
| Nonempty misaligned user output | DATATYPE_MISALIGNMENT, ReturnLength untouched |
| Zero-length output with misaligned pointer | Pointer alignment ignored; INFO_LENGTH_MISMATCH |
| Null output, nonzero length | ACCESS_VIOLATION |

The host's raw SMBIOS payload size was 4,256 bytes. That size belongs only to the
native boundary experiment and is not copied into the synthetic guest fixture.

## Architecture and scope

One immutable synthetic RSMB payload backs enumeration, size negotiation, and
full reads. The bounded inventory uses SMBIOS 2.8-format type 0 (BIOS), type 1
(system), and type 127 (end-of-table) records, with synthetic identity strings,
stable UUID, unique handles, valid string indexes, double-NUL termination, and
exact record/payload lengths. It makes no claims about host hardware.
The type-0 UEFI-support bit is derived from the same machine firmware mode used
by the UEFI variable store. Model tests cover both UEFI and legacy settings.

This is a structurally parseable partial inventory, **not a complete
DMTF-conforming platform inventory**. Chassis, processor, memory, cache, slot,
and boot records are not supplied. Consumers requiring those records may need
a later extension tied to the emulator's actual hardware model. The
[SMBIOS specification](https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.9.0.pdf)
defines those additional platform requirements.

Only RSMB is implemented. ACPI and FIRM queries remain explicitly unsupported;
this pass does not change `HalAcpiGetTableEx`, UEFI variables, or unrelated
system-information classes. Nonzero RSMB IDs follow the observed native alias
behavior, rather than inventing additional tables.

Static invalid buffers must be rejected before output writes. Nt/Zw caller-mode
rules and actual native-user access checks remain in force. Overlapping
ReturnLength and output ranges are rejected as a bounded emulator policy;
Windows does not promise a useful contract for that aliasing. Concurrency with
arbitrary direct guest page-table edits is not made globally atomic by this pass.

## Validation

All 16 host model tests passed, including the new firmware-table model. It
independently walks the SMBIOS wire format and validates string indexes, handles,
termination, every short payload length, table-ID aliases, and immutable storage.
Evidence: `build-conformance/firmware-tables-model-tests.log`.

An initial paired run (`firmware-tables-20260927-140615-065.json`) passed all
17 kernel assertion labels but timed out before native completion. Disassembly
and trace inspection showed a bounded, advancing buffer fill: image-backed
native scratch arrays caused 158,781 per-byte monitor records. The native test
uses allocated guest scratch memory to avoid that logging overhead while keeping
the same full-buffer canaries and 30-second deadline. Native loader warnings are
separately classified; unmatched warnings and fault diagnostics still fail.

The final WHP Release build succeeded. Generic executable SHA-256:
`224495C8BEC93C1F9699FC944706C47C277F90F146BA6D4A947FA9DCCDC2D01F`.
All three sequential integration runs passed without timeout, stderr output, or
remaining forbidden diagnostics; executable and fixture hashes stayed stable.

| Run | Result | Manifest under `build-conformance/` |
| --- | --- | --- |
| Firmware tables | 17 kernel labels, 44 successful assertion occurrences; 36 native source checks certified by exact success `0x7640` | `firmware-tables-20260927-141352-923.json` |
| Process snapshots regression | 27 kernel labels, 66 successful assertion occurrences; native success `0x5150` | `process-snapshots-20260927-141403-952.json` |
| UEFI variable regression | Expected query counts 31/56/31 and native status checks; native exit zero | `firmware-user-20260927-141411-873.json` |

The RSMB get result is 212 bytes, including its 8-byte raw header; the complete
class-76 result is 228 bytes. Eleven known native loader warnings were matched
against exact, count-bounded patterns before the first native firmware query.
They remain environment limitations, not successful subsystem implementations.

Independent production/model and final fixture reviews found no material issues.
Mixed-permission page-crossing buffers, arbitrary concurrent mapping changes,
and ARM64 runtime behavior remain outside the focused guest validation.

## Target capture

The kernel-only WHP validation capture is
`build-conformance/kernel-20260927-141600-534/`, using generic commit `0b34a00`
plus the existing local-only compatibility stub at lab commit
`067370aeec46a3dec0d4180feb5b092c67f3e469`. Frozen lab executable SHA-256:
`CC1BDE0F03837380585B9A117F87C3152252370666EB48D641DF231727C07957`.
The generic checkout and executable were restored after launch.

At stdout line 9553, VGK's observed RSMB Get/table-0 request succeeds with total
required length 228. DriverEntry returns STATUS_SUCCESS at line 9585,
14:16:10.925. The earlier unsupported-class-76 warning and subsequent `E000017F`
diagnostic are absent. This establishes that the exercised API path now succeeds;
it does not establish full inventory conformance or unobserved consumer behavior.

The capture completed 210.0361049 seconds and was deliberately stopped at the
configured limit; exit -1 reflects that supervisor stop. Timer expiration occurs
at 14:19:02.406 and the first true read at 14:19:03.363. There are 115 false reads
followed by 19 true reads, confirming continued execution beyond expiration.

Nine successful process snapshots retain the expected startup transitions and
settle at 41 processes, five modeled threads, and four handles. Seven audit
sweeps produce 287 process lookups, 245 attachments, 245 detaches, and 245 rundown
releases. Every release reports zero remaining references and all parsed
attachments balance.

Independent full-log inspection found 141 dispatched and 141 handled exceptions,
zero unhandled exceptions, zero API faults/callback failures/executed missing
APIs, and no new normalized warning messages relative to the prior capture.
The three known optional IRQL hook-symbol setup errors remain. These results
validate this bounded workload, not complete hardware/debugger fidelity.

The logged pool footprint at capture end is 1,823 allocations / 24,801,152 bytes,
matching the prior capture's final footprint. All surviving allocations originate
before DriverEntry returns. This reconstruction covers only logged pool APIs,
not all allocation sources or shutdown cleanup; no host-resource sampling was
performed in this short run.

`verification.json` records matching post-run driver, lab executable, kernel,
and CI hashes, empty stderr, restored generic executable, and no remaining
emulator process. Stdout SHA-256:
`2302B618DF75A67AC77BE14C18814FAAA2D28A287BB433C003F42485B6B361E1`.
Detailed observations are in the capture's `worker-analysis.json`,
`resource-analysis.json`, and `snapshot-analysis.json` sidecars. The kernel-only
scope deliberately excludes `vgc.exe` and user-service fidelity.

Reproduction commands (guest images run only through the emulator):

```powershell
tests/scripts/run-model-tests.ps1
tests/scripts/build-drivers.ps1 -Driver firmware_table_conformance
tests/scripts/build-firmware-table-user.ps1
tests/scripts/run-firmware-tables.ps1
tests/scripts/run-process-snapshots.ps1
tests/scripts/run-firmware-user.ps1
```
