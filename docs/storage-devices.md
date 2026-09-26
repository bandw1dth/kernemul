# Synthetic storage device queries

This pass replaces the boot seed's ordinary `physicaldrive0` through
`physicaldrive5` files with one named guest disk device. `PhysicalDrive0` reaches
the device through the existing object-manager namespace and device-request
dispatch. Unconfigured raw disks fail to open; they are not empty files.

The disk is a synthetic, read-only identification model. Its identity and
capacity are consistent across the storage descriptor and ATA IDENTIFY data,
and its profile reuses the synthetic UEFI boot disk and partition identities.
This is not a sector image, GPT partition manager, filesystem volume, PnP bus,
or host-disk passthrough implementation. Raw sector reads and writes remain
unsupported, as do unmodeled control requests and ATA commands.

## Observed requests

A 15-second local diagnostic capture,
`build-conformance/kernel-20260926-225140-504`, recorded the input headers while
preserving the preceding unsupported responses. It used local probe commit
`71a71a1`; the diagnostic instrumentation is not part of the generic branch.

VGK queried both controls for each of `PhysicalDrive0` through `PhysicalDrive4`:

| Control | Captured input | Captured output capacity |
| --- | --- | --- |
| `0x2D1400` (`IOCTL_STORAGE_QUERY_PROPERTY`) | 12 bytes: `StorageDeviceProperty`, `PropertyStandardQuery` | 8 bytes, a descriptor size probe |
| `0x4D02C` (`IOCTL_ATA_PASS_THROUGH`) | 48-byte x64 `ATA_PASS_THROUGH_EX` | 512 bytes |

The ATA wrapper declares `Length=48`, flags `0x03` (DRDY required and data in),
`DataTransferLength=512`, `TimeOutValue=5`, and `DataBufferOffset=48`. Its
`CurrentTaskFile[0]` is `0xEC`, while `CurrentTaskFile[6]` is zero. According to
the documented ABI, index 0 is the features register and index 6 is the command
register. IDENTIFY DEVICE requires command `0xEC`. Independently, the declared
payload ends at offset 560, beyond the supplied 512-byte output capacity.

The captured ATA request must not receive a fabricated success. Tests cover
both its rejection and a correctly formed 560-byte IDENTIFY request. This
describes the captured API boundary; it does not establish why the driver
constructed that request.

## Model contract

The property query returns a `STORAGE_DEVICE_DESCRIPTOR` with bounded,
null-terminated ASCII identity strings, offsets relative to the descriptor,
`BusTypeAta`, and a complete `Size`. A successful 8-byte probe reports the
descriptor version and required size. Full queries return exactly the populated
descriptor. Property-existence queries return no payload. Unsupported properties
and query types receive explicit failures.

ATA IDENTIFY returns one 512-byte block through the buffered wrapper. Serial,
firmware revision and model strings use ATA word ordering and space padding;
they agree with the storage descriptor. Transfer offsets and lengths are checked
before writes. Unsupported directions, flags and commands cannot reach host
hardware. Request sizes are bounded at 64 KiB.

The guest adapter captures input before output so METHOD_BUFFERED in-place
requests work. Guest ranges and status-block outputs are validated before
committing results. Synchronous completion returns an accurate byte count;
asynchronous event/APC requests are explicitly outside this bounded backend.
Existing guest-driver device dispatch remains a separate backend.

The native control boundary preserves Nt/Zw caller-mode distinctions and checks
the IOCTL's requested access for user callers. The existing global file-handle
namespace is not migrated in this pass. Kernel caller-mode access rules do not
give an ntdll Zw call elevated access. Raised-IRQL calls receive a deterministic
failure rather than performing device work outside the native API's contract.

Failure precedence and intermediate short-descriptor behavior are deterministic
emulator policies where Microsoft does not specify an exact status for every
combination. They are not claims of bit-for-bit behavior for every Windows build.
The IDENTIFY-only model requires a two-byte-aligned data offset. It does not
implement every controller's DMA or alignment contract.

## References

- [IOCTL_STORAGE_QUERY_PROPERTY](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_query_property)
- [STORAGE_PROPERTY_QUERY](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_property_query)
- [STORAGE_DEVICE_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_device_descriptor)
- [IOCTL_ATA_PASS_THROUGH](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ni-ntddscsi-ioctl_ata_pass_through)
- [ATA_PASS_THROUGH_EX task-file layout](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_ata_pass_through_ex)
- [IDENTIFY_DEVICE_DATA](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ata/ns-ata-_identify_device_data)
- [ZwDeviceIoControlFile caller and completion requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwdeviceiocontrolfile)

## Verification

Host model tests decode descriptors and ATA words independently. Kernel guest
fixtures exercise named-device opens, aliases, missing disks, buffered controls,
size probes, malformed requests, output canaries and close/reopen behavior.
Guest `.sys` and native `.exe` fixtures are emulator inputs only; never load or
execute them on the host.

```powershell
pwsh -NoProfile -File tests/scripts/run-model-tests.ps1
pwsh -NoProfile -File tests/scripts/build-drivers.ps1 -Driver storage_conformance
pwsh -NoProfile -File tests/scripts/run-conformance.ps1 -Driver storage_conformance
pwsh -NoProfile -File tests/scripts/build-storage-user.ps1
pwsh -NoProfile -File tests/scripts/run-storage-user.ps1
```

The frozen preceding UEFI executable (SHA-256
`4D03D2546C36F0785221C98E190053695AE0D92FFB74A45B67CDE72D64BE06B9`)
failed the initial device-open/header checks in
`build-conformance/storage_conformance-20260926-225926-437.json`. The fixture
then stopped before issuing negative-pointer tests against the old stubs.

The storage build passed all 14 host model executables and the initial WHP
guest checks. Each run completed with zero failed assertions and empty stderr.

| Fixture | Passing assertions | Manifest under `build-conformance` |
| --- | ---: | --- |
| Storage kernel | 273 | `storage_conformance-20260926-231149-172.json` |
| Firmware paired | 66 kernel assertions, native termination zero | `firmware-user-20260926-231159-242.json` |
| IRQL | 49 | `irql_conformance-20260926-231207-115.json` |
| Timer | 32 | `timer_conformance-20260926-231215-608.json` |
| CI verification | 49 | `ci_verification-20260926-231223-013.json` |
| Process attach, two guest images | 69 | `attach-20260926-231228-258.json` |

These runs used executable SHA-256
`959506911E279CF5FE39C79014DB239207F16AE86B34B7E3A809A18781894A1D`.
Known optional IRQL hook diagnostics and native-loader queries for unsupported
information classes 192/197 remain explicitly recorded by the runners.

The native fixture uses allocated guest pages for its guarded 65,537-byte buffer.
The initial image-global buffer incurred a monitored access for every byte:
the first fill and tail check each took about 11 seconds, exhausting the runner's
25-second limit before the second query. The existing image-section monitoring
policy is unchanged; moving the fixture buffer preserves the complete bounds
and canary checks. That initial timeout was forward progress, not a storage
dispatch deadlock.

Independent review identified a caller-mode gap in the unsupported raw-I/O
path. Nt read/write calls now validate the status block using PreviousMode as
well as actual CPU mode; kernel Zw calls retain their documented kernel-mode
boundary. The added fixture checks rejection without modifying a kernel status
block for UserMode Nt callers, successful status delivery for kernel Zw callers,
and rejection of storage controls passed through FsControlFile.

The final reviewed build has SHA-256
`92656A395F1110B5347DF44F8BABA623A0E88558F1BB46617864B6CA80D2A93D`.
The focused reruns all passed:

- `storage_conformance-20260926-232034-115.json`: 282 kernel assertions.
- `firmware-user-20260926-232038-887.json`: firmware kernel/native pair.
- `attach-20260926-232045-998.json`: both process-attach guest images.
- `storage-user-20260926-232138-757.json`: 282 kernel assertions and native
  termination zero; all 14 expected backend records match. The fifteenth native
  control call rejects a null IOSB before backend dispatch and is checked by the
  guest fixture. Access rejection, Nt/Zw distinctions, bad pointers, kernel
  addresses, alias rejection, bounds, ATA checksum and context restoration pass.

The final paired run exited without timeout, stderr or forbidden diagnostics,
and executable/fixture hashes stayed stable. Kernel fixture SHA-256 is
`307995659E8FC357083F9B1D95A9EFA07C6998FE2D3DF7A74157CBADEA1682E8`;
native fixture SHA-256 is
`386D628A77B31D099167FBE4E77A6D73073580D3ACC3C2650BAA5FC2532E3ED5`.
Independent re-review confirmed the finding resolved with no further material
finding. Physical-alias and backend-write-failure paths and multi-vCPU races
remain untested; staged writes do not promise atomic visibility to concurrent
readers. This is bounded emulator conformance, not a matching Windows VM run.

## Bounded VGK capture

Implementation commit: `32db993`. The frozen WHP capture is
`build-conformance/kernel-20260926-232326-759`. It uses local-only lab commit
`111dbeb9ebb068ef26b081277db5955990e98c2b` and executable SHA-256
`CB6BBE98132E859B1419FD8FE1055362A91208086C089B7A7DB7B2E38AF8E9AD`.
The author-provided in-memory DEBUGCTL compatibility patch remains on that local
branch. The generic branch and validated executable were restored after freezing
the run. The only native companion is the process-notification fixture; the
user-mode service is not run.

VGK initialization returned `STATUS_SUCCESS` at 23:23:37.272. Its storage
observations changed as follows from the preceding UEFI capture
(`kernel-20260926-223635-224`):

| Observation | Before | Storage pass |
| --- | --- | --- |
| PhysicalDrive0 | Ordinary file with no device handler | Named synthetic disk, opened twice |
| ATA request `0x4D02C` | No device handler | `STATUS_BUFFER_TOO_SMALL`, zero bytes; captured malformed request preserved |
| Property request `0x2D1400` | No device handler | Successful 8-byte size probe, then successful 94-byte descriptor read |
| PhysicalDrive1–4 | Fake files, eight unsupported IOCTLs | Eight opens return `STATUS_OBJECT_NAME_NOT_FOUND` |

The extra full-descriptor request is new target behavior enabled by the successful
size probe. The driver now receives coherent identity metadata for the configured
disk while absent disks remain absent. Valid ATA IDENTIFY requests are covered by
the model, kernel and native fixtures; this VGK capture does not issue a valid one.

The run completed **210.044 seconds** and was deliberately stopped at the limit
(host exit code `-1`). The shared three-minute timer first read signaled at
23:26:29.016, with 19 signaled reads before the deadline. There were 142 handled
exceptions, zero unhandled exceptions, zero API/callback faults and no executed
unimplemented functions. The three startup errors were only the known optional
IRQL export hooks; stderr was empty.

The trace contains exactly three storage controls: the rejected ATA request and
the two successful property queries. No old "not a device" storage warnings
remain. Firmware still reports three successful reads and nine absent variables;
CI reports two trusted SHA-256 checks and six digest/algorithm mismatches. Four
process callbacks were delivered, with four balanced attach/detach pairs.

The physical-memory resource-map registry key remains absent, and the
`E00000EF` diagnostic involving `fltmgr.sys` remains. Those are not resolved by
this identification-only disk model. The target file stayed unchanged at SHA-256
`3CB2F36CF9F3B66BF63561D24649422D852229F2C788A7AAA783752DCE4AB39F`.
The frozen manifest, stdout/stderr and `storage-summary.json` preserve the local
capture evidence; generated binaries and traces are not committed.
