# Physical-memory resource map

The boot registry publishes `HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory`
with a `.Translated` value of type `REG_RESOURCE_LIST` (8). Its bytes are derived
from the MMU's declared physical range, the same source used by
`MmGetPhysicalMemoryRanges`. Pool allocations and lazy host backing do not change
installed RAM, and host-machine memory is not used to populate this value.

The current machine profile has 4 GiB of RAM in the half-open physical interval
`[0x100000000, 0x200000000)`. The lower 4 GiB remains a hole. This pass reports
that existing profile; it does not change physical allocation or page tables.

## Representation

The serializer writes little-endian, pack-4 Windows resource-list bytes for the
supported 64-bit guest profiles. The list contains one full descriptor, using
`Internal`, bus zero, version/revision 1, and ordinary memory descriptors with
device-exclusive sharing and read/write flags. Those metadata choices are the
synthetic profile's policy, not a claim that every Windows build emits them.

An ordinary descriptor has a 32-bit byte length. A 4 GiB run cannot fit in one,
so the encoder splits it into page-aligned chunks no larger than `0xfffff000`:

| Physical start | Byte length |
| --- | --- |
| `0x100000000` | `0xfffff000` |
| `0x1fffff000` | `0x1000` |

The resulting blob is 60 bytes: a 20-byte list/full/partial header followed by
two 20-byte partial descriptors. Adjacent descriptors cover the same continuous
range reported by the memory API; no byte is truncated or counted twice. The
serializer also preserves holes between input ranges and rejects malformed or
unbounded input instead of publishing a plausible-looking partial map.

Only `.Translated` is seeded. There is no invented raw bus map, memory hotplug,
or `CmResourceTypeMemoryLarge` encoding in this bounded pass. Values use the
existing registry store and query/enumeration paths, rather than a special-case
success in `ZwOpenKey` or `ZwQueryValueKey`.

## References

- [CM_RESOURCE_LIST](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_resource_list)
- [CM_FULL_RESOURCE_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_full_resource_descriptor)
- [CM_PARTIAL_RESOURCE_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor)
- [CM_PARTIAL_RESOURCE_LIST](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_list)
- [RtlCmEncodeMemIoResource](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmencodememioresource)

The registry location/value selection is a bounded compatibility profile. The
documented structures establish the binary representation; they do not specify
the complete contents of this Windows boot registry key on every machine.

The fixture parses full-information data at the returned `DataOffset` using
bounded copies. It does not assume that the existing registry adapter pads the
payload to an additional alignment boundary. This pass does not change general
registry query behavior, value-name casing, permissions or notification delivery.

## Verification

Host model tests independently decode the bytes, including the 4 GiB split,
disjoint ranges, high physical addresses, invalid input and descriptor limits.
A kernel fixture queries and enumerates the actual registry value through guest
APIs, checks sizing and output bounds, and compares normalized coverage against
`MmGetPhysicalMemoryRanges`, including after allocating pool memory.

Guest fixtures run only inside the emulator, never as host drivers.

```powershell
pwsh -NoProfile -File tests/scripts/run-model-tests.ps1
pwsh -NoProfile -File tests/scripts/build-drivers.ps1 -Driver physical_memory_resources
pwsh -NoProfile -File tests/scripts/run-conformance.ps1 -Driver physical_memory_resources
```

The preceding storage build (SHA-256
`92656A395F1110B5347DF44F8BABA623A0E88558F1BB46617864B6CA80D2A93D`)
fails exactly the initial missing-parent-key assertion, then exits cleanly with
`STATUS_UNSUCCESSFUL`. Baseline evidence is
`build-conformance/physical_memory_resources-20260926-234128-217.json`.
All 15 host model executables pass, including the new resource serializer;
the model run is recorded in `build-conformance/physical-memory-model-tests.log`.

The WHP Release build has SHA-256
`8D5DFA0FAC28916584B261B5A54A28E0F8FB470EDA9F2C33775F5DD49FE51FD4`.
Independent verification passed all 381 guest assertions:

| Fixture | Passing assertions | Manifest under `build-conformance` |
| --- | ---: | --- |
| Physical-memory resources | 17 | `physical_memory_resources-20260926-234229-737.json` |
| Registry notifications | 65 | `registry_notify_conformance-20260926-234235-304.json` |
| Registry boundaries | 17 | `registry_notify_boundaries-20260926-234240-422.json` |
| Storage | 282 | `storage_conformance-20260926-234244-544.json` |

All four runs exited zero without timeout, with empty stderr and no unhandled
exceptions, executed unimplemented functions or DPC failures. The only three
startup error diagnostics were the existing optional IRQL hook names. The
resource fixture has SHA-256
`E7544B2398D9E9B7B43E183101B2FD6E5D81F56DA26AA76B314210890D45A5AB`.
The guest runtime checks cover x64/WHP; ARM64 is guarded by the corresponding
in-tree ABI layout assertions but was not separately built or executed here.
Independent review found no material issue in the encoder, integration or
fixtures. Matching real-Windows byte-for-byte output is not claimed; the tested
contract is coherent, bounded resource reporting for this emulator profile.

## Bounded VGK capture

Implementation commit: `a88407c`. The frozen WHP run is
`build-conformance/kernel-20260926-234423-577`, with local-only lab commit
`072c0a20cb03592414be6f3cac170dc79a098ce7` and executable SHA-256
`FA43E594C760D94982A1FC554947951D403AE7F4E842224ECB7F2A730FEE0BFF`.
The author-provided in-memory compatibility patch remains local. The generic
branch and its validated executable were restored once the run was frozen.
The only native companion is the process-notification fixture, not the service.

Compared with `kernel-20260926-232326-759`, the missing-key warning is replaced
by an actual key open and two value queries:

| Time | Observation |
| --- | --- |
| 23:44:32.867 | Physical Memory key opens successfully, handle `0x38` |
| 23:44:32.869 | Value query reports 102 bytes required |
| 23:44:32.870 | VGK allocates a 102-byte result buffer |
| 23:44:32.871 | Value query writes 102 bytes |
| 23:44:32.872 | VGK frees the buffer and closes the key |
| 23:44:33.635 | Driver initialization returns `STATUS_SUCCESS` |

The size matches `KEY_VALUE_FULL_INFORMATION` with its 20-byte fixed header,
22-byte `.Translated` name, and 60-byte resource-list payload. The trace does
not expose every subsequent instruction interpreting that payload. The existing
`B000001A` diagnostic still follows this sequence, and `E00000EF` involving
`fltmgr.sys` also remains; both occurred in the preceding storage capture.
Successful resource delivery is not evidence that those diagnostics are solved.

The run completed **210.035 seconds** and was deliberately stopped at its limit
(host exit code `-1`). The three-minute timer first read signaled at
23:47:26.538, with 19 signaled reads before the deadline. There were 145 handled
exceptions, zero unhandled exceptions, zero API/callback faults and no executed
unimplemented functions. Stderr was empty; the only startup errors were the
three known optional IRQL hook names.

The preceding storage behavior is preserved: one rejected malformed ATA request,
successful 8-byte and 94-byte storage-property responses, and eight absent-disk
open failures. Firmware reports three successful reads and nine absent variables.
CI reports two trusted SHA-256 checks and six digest/algorithm mismatches.
Four process callbacks and four balanced attach/detach pairs were observed.

The target file remains unchanged at SHA-256
`3CB2F36CF9F3B66BF63561D24649422D852229F2C788A7AAA783752DCE4AB39F`.
The manifest, stdout/stderr and `physical-memory-summary.json` preserve the local
capture evidence. Generated executables and traces are not committed; the lab
patch is not part of the generic branch.
