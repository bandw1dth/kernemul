# WHP DEBUGCTL investigation

## Decision

The zero DEBUGCTL read-back is reproducible in a standalone WHP partition,
without kernemul, Hypermulator hooks, or RFLAGS.TF. On the investigated host,
WHP reports neither PMU nor LBR support. This is a native virtualization
limitation, not solely corruption by the emulator's internal single stepping.
No production DEBUGCTL shadow or forced read-back is introduced by this pass.

The result is host-specific: Windows 11 Pro 10.0.26200, Intel Core i9-14900HX,
Windows SDK 10.0.28000.0, WinHvPlatform.dll 10.0.26100.9278. Initial probes ran
without elevation; the subsequent administrator run reproduced the results.
No permission-policy or host configuration changes were made. A different host
or hypervisor configuration must still be measured independently.

## Native probe results

The standalone probe creates disposable WHP partitions and executes short guest
instruction sequences. It never executes host RDMSR/WRMSR instructions. The
default suite has no MSR interception, no software hooks, and TF clear. Adjacent
`WRMSR; RDMSR` executes in a single run, followed by HLT. Debug and general
protection exception exits are observable instead of silently handled by a guest
kernel. Every run has a cancellation deadline.

This isolated probe uses real mode at CPL0. The earlier kernemul driver probe
observed the same zero read-back in the long-mode environment. This experiment
does not establish equivalence across all modes or explain Hyper-V's internal
reason for rejecting the configuration. In particular, unavailable LBR and
zero read-back are both observed; their internal causal relationship is not
proven. The target's full startup rejection is not diagnosed by this test alone.

| Experiment | Observed result |
| --- | --- |
| WHP perfmon capability | Query succeeds; PMU=0, LBR=0 |
| DEBUGCTL writes `1`, `2`, `3`, `4` | Complete without a debug exception; immediate read returns zero |
| DEBUGCTL write of bit 63 | Also completes and reads zero; no architectural reserved-bit fault is reproduced |
| SYSENTER_CS control write/read/restore | Retains the written value and restores the original |
| Invalid MSR read/write, default partition | Both generate vector 13 (#GP) |
| Unhandled-MSR exits enabled | Invalid MSR read/write exits are delivered; DEBUGCTL still runs internally and reads zero |
| Exact DEBUGCTL read/write exit action | Property setter succeeds, but partition setup rejects it with `0xc0350006`, both with and without coarse MSR exits |
| Exact invalid-MSR action control | Partition setup succeeds and MSR exits are delivered (coarse exits are also enabled) |
| Request LBR on a fresh partition | Property setter succeeds, but partition setup rejects it with `0xc0350005` |

The action-list control distinguishes the DEBUGCTL rejection from an entirely
unavailable action-list API. It does not establish every possible configuration
or future WHP version's behavior. The probe establishes the observable native
policy; it cannot identify undocumented Hyper-V implementation details.

Initial raw evidence is in ignored local files
`build-conformance/debugctl-investigation-final.log` and
`build-conformance/debugctl-investigation-native.cpp`. The source and raw output
also record guest CPUID, partition properties, exit reasons, and TF state.

## Reproduction

The maintained probe is `tests/whp/debugctl_probe.cpp`. Build and run it with:

```powershell
pwsh -NoProfile -File tests/scripts/run-whp-debugctl-probe.ps1
```

It requires WHP and the configured Windows SDK/Visual C++ tools, but no driver
installation or guest Windows image. The runner writes timestamped build logs,
stdout/stderr, and a JSON manifest under `build-conformance`, with source and
executable hashes, OS/DLL versions, elevation state, and raw capabilities.
Execution is bounded by per-run cancellation and a process timeout.

A completed diagnostic means its control checks succeeded. It does not mean
DEBUGCTL is supported. Expected optional configuration rejections are findings;
runtime errors, failed controls, and timeouts fail the diagnostic. Failed
capability queries remain explicitly unknown rather than becoming zero support.

Independent verification rebuilt and ran the maintained probe successfully;
manifest `build-conformance/whp-debugctl-20260927-004229-616-13992.json` records
exit zero, stable hashes, empty stderr, and `SUMMARY failures=0`. Its observations
match the matrix above. Unknown-capability handling was inspected in source but
was not triggered on this host. This verification is one run in the recorded
configuration, not evidence of deterministic behavior across platforms.

## Elevated comparison

The user-authorized elevated rerun completed successfully, with
`ProcessIsAdministrator=true` in
`build-conformance/whp-debugctl-20260927-004512-887-27508.json`.
The source hash matches the non-elevated verification run exactly:
`574AEFAA408D97BEC198B21FA5FC9D3FCCF42413E4D24287CEA5BBA300275AE8`.
Both capability and finding records are identical across the two manifests.

In the elevated run, DEBUGCTL writes `1`, `2`, `3`, and `4` still read zero with
TF clear, both in the default partition and with unhandled-MSR exits enabled.
The PMU/LBR capability remains zero. Exact DEBUGCTL action-list configurations
still fail setup with `0xc0350006`; requesting LBR still fails with `0xc0350005`.
The SYSENTER and invalid-MSR controls pass, as does the invalid action-list
configuration control. The diagnostic exits zero with `SUMMARY failures=0`,
empty stderr, stable hashes, and no timeout. This confirms the unchanged
behavior under ordinary administrator elevation on this machine; it does not
identify the internal hypervisor permission or feature policy responsible.

Elevation is therefore not the missing native-enablement step in the tested
configuration. Faithful LBR/BTF support here would require a software execution
and debug model, or a backend/configuration that exposes the necessary native
facilities. Before undertaking a full software model, a bounded feasibility pass
should prove reliable instruction interception and separate guest-requested
TF/#DB behavior from the hook engine's stepping. A writable MSR shadow alone
does not meet that requirement. The evidence does not establish that the target
requires every LBR/BTF feature, nor that implementing them guarantees startup.

## Architectural boundary

Intel defines `IA32_DEBUGCTL` (`0x1d9`) bit 0 as LBR and bit 1 as BTF. Recording
branches, changing trap behavior, and clearing these bits on debug exceptions
are observable consequences of enabling those facilities. Retaining a write in
a map would implement register storage without those effects.

WHP exposes `WHV_PROCESSOR_PERFMON_FEATURES.LbrSupport` as a capability and
partition feature. Processor features must be configured before partition setup.
The published register interface has no `WHvX64RegisterDebugCtl`; the coarse MSR
exit bitmap has no dedicated DEBUGCTL selector. The newer MSR action-list API
must also be tested through partition setup: accepting a property alone does
not establish that the configuration can run.

Hypermulator currently sets up its partition in
`vendor/hypermulator/src/guest/guest_partition.cpp`. Its hook engine uses TF and
consumes internal debug exits; `src/emu/x86/whp.cpp` hides that TF from host-side
guest context reads. Native LBR/BTF support on another host would still need
tests distinguishing guest-requested debug events from internal stepping.

## Consequence for implementation

There is no evidence-supported small native-enablement fix on this host.
Ordinary MSR exits cannot intercept the tested access, and the tested explicit
DEBUGCTL exit configuration is rejected. A register-only shadow would also
misrepresent instruction execution semantics. Production behavior is therefore
unchanged.

A future native implementation must first demonstrate LBR availability and
successful partition setup on its test host, then verify branch records, BTF
behavior, reserved-bit policy for its CPU profile, and isolation from internal
TF/#DB stepping. A software implementation would need a coherent CPU debug
model and a way to intercept/emulate these instructions, with those same
observable effects. Merely removing the target's startup rejection is not an
acceptance criterion.

## Target baseline

The unpatched target was run with the corrected exception-delivery executable
SHA-256 `099DBF49B82D6A4F8871D6C725913E08A043B4AB6FDDE7DD6CE4B460FC5F63A9`.
Capture `build-conformance/kernel-20260927-003418-174` exited after 2.172 seconds;
DriverEntry returned `STATUS_ACCESS_DENIED` (`0xc0000022`). No service was run.
The target remained SHA-256
`3CB2F36CF9F3B66BF63561D24649422D852229F2C788A7AAA783752DCE4AB39F`.
It did not reach the three-minute timer, so no post-timer validation is claimed.

## References

- [Microsoft: partition property contracts](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvpartitionpropertydatatypes)
- [Microsoft: WHP capabilities](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability)
- [Microsoft: virtual processor register types](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvvirtualprocessordatatypes)
- [Microsoft: current WHP header definitions](https://github.com/MicrosoftDocs/Virtualization-Documentation/blob/main/virtualization/api/hypervisor-platform/headers/WinHvPlatformDefs.h)
- [Intel SDM volume 3B, debug facilities](https://cdrdv2-public.intel.com/874250/253669-090-sdm-vol-3b.pdf)
