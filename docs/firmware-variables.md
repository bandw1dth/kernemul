# Guest UEFI variable queries

The guest firmware model supplies a bounded, read-only UEFI variable snapshot.
Each emulated Windows instance owns its own store; variables are selected by
the exact UTF-16 name and vendor GUID. Both executive and native query APIs use
the same store. This replaces the unconditional firmware-unavailable response.

## Boot profile

The default profile is explicitly synthetic. Under the EFI global-variable
namespace `8BE4DF61-93CA-11D2-AA0D-00E098032B8C`, it contains:

| Variable | Attributes | Data |
| --- | --- | --- |
| `BootCurrent` | Boot-service and runtime access (`0x06`) | Boot option 0, as a little-endian `UINT16` |
| `BootOrder` | Nonvolatile, boot-service and runtime access (`0x07`) | One little-endian `UINT16`: 0 |
| `Boot0000` | `0x07` | Active `EFI_LOAD_OPTION`, a GPT partition device path, a Windows boot-manager file path, and an end node |

The load option has a null-terminated UTF-16 description and the file path
`\EFI\Microsoft\Boot\bootmgfw.efi`. Its device-path length includes the final
end node and excludes the description and load-option header. Storage-variable
attributes and load-option attributes are distinct fields.

Only those three variables exist. Queries for `Boot0001` through `Boot0009`
return `STATUS_VARIABLE_NOT_FOUND`. The synthetic disk and partition identities
are available for a future storage-device model to reuse. This profile does not
claim that a disk device or a boot-manager executable is currently emulated.

No host firmware is read or written. Nonvolatile attributes describe the guest
snapshot; guest writes, persistence across runs, authenticated variable updates,
Secure Boot keys and firmware execution remain outside this pass. A separate
legacy-BIOS store is representable and reports firmware services unavailable.
Snapshot construction provides a boundary for later import support; this pass
does not add a snapshot-file loader or host-firmware exporter.

## Query contract

`ExGetFirmwareEnvironmentVariable` and `Nt/ZwQuerySystemEnvironmentValueEx`
share one implementation. Success writes the exact data, byte count, and optional
attributes. A short buffer, including a null buffer with zero capacity, receives
`STATUS_BUFFER_TOO_SMALL` and the required byte count, without a partial value.
Unknown names and namespaces are distinct from unavailable firmware.

Inputs are captured before outputs. Names, snapshot sizes and variable sizes
are bounded: 128 variables, 1024 UTF-16 code units per name, 64 KiB per value,
and 1 MiB of aggregate value bytes. Duplicate keys are rejected. Unknown
attribute bits are preserved, and variables without runtime access are hidden
from the query APIs. The adapter uses the current effective address space and validates
guest ranges before writes. User buffers use process memory protection metadata;
kernel buffers can only be checked for backing because the current model lacks
kernel buffer protection metadata.

Some failure behavior is an explicit emulator policy rather than a measured
Windows implementation detail: attributes are preserved on a short-buffer
failure, malformed counted names and overlapping outputs are rejected, and
calls above PASSIVE_LEVEL return `STATUS_INVALID_DEVICE_STATE`. Native calls
respect the thread's PreviousMode; a distinct kernel Zw entry uses KernelMode.
User-mode execution does not acquire kernel privileges by reaching a Zw entry.
Until token privileges are modeled, user-mode queries conservatively fail with
`STATUS_PRIVILEGE_NOT_HELD`; the executive API is for kernel callers.

## Sources and validation

The public [Microsoft executive API contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetfirmwareenvironmentvariable)
specifies byte-count behavior, optional attributes and PASSIVE_LEVEL. The
[Nt/Zw rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines)
and [user-mode firmware API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexa)
establish the mode distinction and user privilege requirement. They do not
document every native failure ordering or failure-side output.

The profile follows the [UEFI 2.11 boot-manager definitions](https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html)
and [device-path layouts](https://uefi.org/specs/UEFI/2.11/10_Protocols_Device_Path_Protocol.html).
The [UEFI runtime variable service](https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html)
has its own attributes-on-failure contract; that should not be mistaken for a
documented guarantee from the Windows wrapper.

Host model tests validate snapshot isolation, limits and independently decoded
boot bytes. Kernel guest conformance tests exercise Ex and Zw. In the pinned
kernel, `NtQuerySystemEnvironmentValueEx` is a private PDB symbol, not a PE export;
`MmGetSystemRoutineAddress` correctly refuses to resolve it. A native guest
fixture exercises Nt and Zw through ntdll's syscall path, including valid user
buffers denied by the current privilege policy. The kernel fixture uses the
pinned x64 KTHREAD layout to verify that kernel Ex and Zw do not inherit a
UserMode PreviousMode probe policy. These are emulator tests, not portable
drivers intended to run on arbitrary Windows kernels.
Guest drivers are inert emulator inputs and must never be loaded as host drivers.
The target capture uses the existing local-only DEBUGCTL compatibility patch;
the driver file on disk remains unchanged.

```powershell
pwsh -NoProfile -File tests/scripts/run-model-tests.ps1
pwsh -NoProfile -File tests/scripts/build-drivers.ps1 -Driver firmware_conformance
pwsh -NoProfile -File tests/scripts/run-conformance.ps1 -Driver firmware_conformance
pwsh -NoProfile -File tests/scripts/build-firmware-user.ps1
pwsh -NoProfile -File tests/scripts/run-firmware-user.ps1
```

The pre-change executable (`21b3d83`, SHA-256
`79EC91369EBBB811169AD8E8CE1E66C18491C3962F1D2BD0D98B07E4006A608E`)
fails the first query assertion for Ex and Zw. Its kernel image does not export
the Nt spelling, so the initial fixture also fails its Nt-resolution assertion.
The fixture stops negative-pointer checks after an initial query failure,
because the old stub cannot safely handle them. This baseline is recorded in
`build-conformance/firmware_conformance-20260926-222317-923.json`.

Runtime coverage is x64/WHP with one vCPU and the existing mixed guest image
set. Legacy-BIOS snapshot construction is covered by the host model tests; the
default guest runtime always selects the synthetic UEFI profile. No ARM64 run,
host firmware comparison, authenticated-write implementation or imported
firmware snapshot is claimed. System-information class 90 remains unsupported.

## Validation on 2026-09-26

The generic x64/WHP build has SHA-256
`4D03D2546C36F0785221C98E190053695AE0D92FFB74A45B67CDE72D64BE06B9`.
Its executable and runtime DLLs are frozen in
`build-conformance/uefi-nvram-validated-20260926`.

All 13 MSVC host model executables passed. The firmware model also passed Clang
C++23 with `-Wall -Wextra -Werror`. Independent guest verification completed
seven runs, with 383 passing kernel assertions across those runs and 56 native
firmware queries. The paired firmware run contained all 33 kernel assertion
names exactly twice, once for Ex and once for Zw. Its query counts were exactly
31 Ex, 56 native Nt/Zw and 31 kernel Zw. Native return statuses, output canaries,
and CPL/TEB/PID/TID restoration all matched the fixture's expectations.

Evidence:

- `build-conformance/firmware-user-20260926-223222-480.json`: paired firmware run.
- `build-conformance/firmware_conformance-20260926-223233-524.json`: 66 standalone firmware assertions.
- `build-conformance/irql_conformance-20260926-223234-551.json`: 49 IRQL assertions.
- `build-conformance/timer_conformance-20260926-223238-071.json`: 32 timer assertions.
- `build-conformance/ci_conformance-20260926-223239-901.json`: 52 CI adapter assertions.
- `build-conformance/ci_verification-20260926-223241-041.json`: 49 CI verification assertions.
- `build-conformance/attach-20260926-223242-568.json`: 69 attach assertions with both native guest images.

All runs exited successfully without timeout, stderr output, failed assertions,
or embedded NUL characters in the trace. Known optional IRQL export diagnostics
and native-loader probes for unsupported information classes 192/197 remain
explicitly recorded. Paired firmware and attach artifact hashes stayed stable.

Independent review found no material actionable issue. Remaining untested paths
include firmware queries while attached to another process, physical aliases
between otherwise distinct output ranges, backend write failures and multi-vCPU
concurrency. Staging preflights writes; it does not provide atomic visibility
to concurrent readers.
