# Image mapping notifications

This increment connects image notifications to guest section mappings. The emulator
already handles `Nt/ZwMapViewOfSection`; its old image registrations retained only
addresses. Process creation remains a separate project: current user-process
creation is initiated during host setup before guest callbacks can register.

## Acceptance contract

- Deliver synchronous callbacks after successful executable-image mapping and
  before the mapping API returns. Expose valid mapped bytes, base, virtual size,
  optional name, and the subject process ID. The model delivers once per successful
  view; precise multiplicity on all Windows mapping paths needs differential tests.
- Do not replay boot images or notify for section creation, failed mappings,
  data views, no-execute image views, or unmapping.
- Process image views use `SystemModeImage=false` and their process ID. They are
  distinct from kernel driver loading, whose notification uses PID zero.
- Run callbacks at PASSIVE_LEVEL in a critical region with normal kernel APCs
  disabled; restore prior APC state on return and failure. Do not invent image
  signature trust or an extended `IMAGE_INFO_EX` payload.
- Retain registrations through callback execution and synchronize removal with
  in-flight calls. Execute no guest code under registration or view-table locks.
- Make mapping state belong to its process. Validate required outputs before
  allocating, clean up failed mappings, and never notify a failed map.
- Keep no-execute views non-executable. Preserve their section attributes.
- Explicitly reject unsupported callback blocking, self-removal, or termination.

Host boot mappings, kernel driver loads, process lifecycle events, and cross-process
mapping APIs remain outside this increment. Existing view mappings copy file bytes;
this does not implement Windows section sharing, copy-on-write, or the full memory
manager. Modern Windows callback capacity is the version assumption.

## Implementation boundaries

The image registry has 64 slots and shares lifecycle admission/rundown machinery
with thread registrations. Ex registration with flags zero is supported; unknown
flags are invalid, and the conflicting-architecture subscription flag is explicitly
unsupported. Guest executable-image views are limited to the configured native
architecture. The callback payload is basic `IMAGE_INFO`, with no extended file
object or signature-verification claims.

Section attributes survive creation and query. No-execute image views use
non-executable translations and metadata even when an executable page protection
is requested. Ordinary image views still use the existing coarse protection model;
this is not full per-PE-section protection emulation.

No-execute policy survives later protection changes: executable protection requests
overlapping these views return `STATUS_SECTION_PROTECTION`, without updating the
view or caller outputs. Non-executable protection changes remain supported.

Nt/Zw views are tracked by owning process and base address; Mm system-space views
use a separate table. User view teardown releases allocator reservations. Kernel
teardown removes translations, while the existing monotonic allocator retains
backing memory. Data views are classified as `MEM_MAPPED`; ordinary virtual-memory
release/decommit cannot remove a tracked section view. This keeps stale view records
from deleting a later allocation at the same address. Requested input base placement
is still limited to the existing preferred-base/fallback behavior. Host memory
access checks establish output mapping
accessibility, not complete guest write-permission probing.

Pre-commit failures clean up mapping state and restore output values where possible.
Callback failure after commit stops the emulator with the committed view retained;
the callback is an observation, not a veto. PE validation added here covers the
Nt/Zw section path; legacy Mm section creation and other uses of the generic PE
materializer still need their own validation work.

## Native protection reference

`tests/scripts/compare-image-protection.ps1 -Image <fixture.sys>` performs a native
user-mode data-mapping comparison without loading a driver or executing mapped
instructions. On Windows 10.0.26200.0, ordinary `SEC_IMAGE` views accepted read-only,
read/write, execute/read, and execute/read/write changes on both the header and the
first executable section. `SEC_IMAGE_NO_EXECUTE` views accepted the first two and
rejected both executable protections with `0xC000004E` (`STATUS_SECTION_PROTECTION`).
Each request used a fresh view. This is a build-specific observation supporting the
retained no-execute policy, not evidence for the entire Windows memory manager.

## Focused verification

- `image_notify_conformance` checks synchronous delivery, callback payload and
  execution context, removal, and the absence of notifications for data/no-execute
  views, section creation, and unmapping.
- `image_notify_boundaries` checks invalid output pointers, malformed images,
  missing backing files, process ownership, and recovery after rejected mappings.
- Four image callback failure fixtures check blocking, removal deadlocks, nested
  API failure, and termination. They require a controlled stop with restored
  IRQL/APC state and reject continuation after the failure.
- `image_noexecute_enforcement` executes a relocated function in an ordinary image
  view as a control, checks protection changes on a no-execute view, then requires
  an instruction-fetch fault at the same function in that view.
- Host models check registration capacity and rundown, PE bounds, and view
  ownership and teardown. `win_user_mem_model` compiles the production allocator
  against a deterministic MMU to check reservation reuse, hidden backing, partial
  allocation failure, failed teardown, and no-execute protection/recommit policy.
  Existing timer, executive callback, and thread lifecycle fixtures cover
  regressions in the shared callback machinery.

These fixtures exercise the emulator through WHP; they do not establish full
Windows compatibility or exercise a third-party driver's entire monitoring logic.

### Recorded validation (2026-09-26)

WHP Release build passed. Independent verification passed all eight positive
fixtures (151 assertions), all thirteen expected-failure fixtures, and all seven
host models. Every guest run exited within its limit with empty stderr, matching
fixture hashes, and the same executable SHA-256 at the beginning and end:
`F26CB933C796CA066146008CFB0ECC75679B1974CEDB4A0708F38D0D1F6D9103`.

Local evidence is indexed by
`build-conformance/independent-status-20260926-111203-manifest-audit.json`.
The no-execute test passed both the reprotection rejection and instruction-fetch
fault checks. Its executable control succeeded. Native reference outcomes are in
`build-conformance/native-image-protection.json`; the reference script is tracked
so that comparison can be reproduced without the local artifact.

Review exposed a stale data-view/free/reuse problem. The new guest regression
failed before the ownership fix, then passed after classification and free-path
guards were added. This also exposed an existing incorrect numeric value for
`STATUS_UNABLE_TO_FREE_VM`; it now matches the WDK value `0xC000001A`, with an
independent numeric assertion in the allocator model.

## Sources

- [Load-image callback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine)
- [IMAGE_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_image_info)
- [Registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine)
- [Extended registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutineex)
- [Removal rundown](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremoveloadimagenotifyroutine)
- [Section mapping](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection)
- [APC-state query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keareapcsdisabled)
