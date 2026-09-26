#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinHvPlatform.h>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <mutex>
#include <stdexcept>
#include <thread>

// All RDMSR/WRMSR instructions below execute only in WHP guest memory.
struct ApiError : std::runtime_error {
  HRESULT hr;
  ApiError(HRESULT value, const char *name) : std::runtime_error(name), hr(value) {}
};
static void require(bool condition, const char *name) {
  if (!condition) throw std::runtime_error(name);
}
static void check(HRESULT hr, const char *name) {
  if (FAILED(hr)) {
    printf("API %s hr=0x%08lx\n", name, (unsigned long)hr);
    throw ApiError(hr, name);
  }
}
struct Capability {
  bool known;
  uint64_t raw;
};
static Capability capability(WHV_CAPABILITY_CODE code, const char *name) {
  WHV_CAPABILITY cap{};
  UINT32 written = 0;
  HRESULT hr = WHvGetCapability(code, &cap, sizeof(cap), &written);
  uint64_t raw = 0;
  memcpy(&raw, &cap, sizeof(raw));
  UINT32 expected = (code == WHvCapabilityCodeHypervisorPresent || code == WHvCapabilityCodeProcessorVendor) ? 4 : 8;
  bool known = SUCCEEDED(hr) && written == expected;
  printf("CAP %s code=0x%x hr=0x%08lx bytes=%u status=%s raw=0x%016llx\n", name, code, (unsigned long)hr, written,
         known ? "known" : "unknown", raw);
  return {known, raw};
}
struct Probe {
  WHV_PARTITION_HANDLE p = nullptr;
  unsigned char *memory = nullptr;
  bool vp = false;
  unsigned sequence = 0;
  bool invalidMsrExits = false;
  ~Probe() {
    if (vp) WHvDeleteVirtualProcessor(p, 0);
    if (p) WHvDeletePartition(p);
    if (memory) VirtualFree(memory, 0, MEM_RELEASE);
  }
  void reg(WHV_REGISTER_NAME name, uint64_t value) {
    WHV_REGISTER_VALUE r{};
    r.Reg64 = value;
    check(WHvSetVirtualProcessorRegisters(p, 0, &name, 1, &r), "set register");
  }
  void setup(bool lbr, uint64_t exceptions, bool unhandled = false, bool exactAction = false, uint32_t actionIndex = 0x1d9) {
    invalidMsrExits = unhandled || (exactAction && actionIndex == 0xffffffff);
    check(WHvCreatePartition(&p), "create partition");
    UINT32 count = 1;
    check(WHvSetPartitionProperty(p, WHvPartitionPropertyCodeProcessorCount, &count, sizeof(count)), "processor count");
    WHV_EXTENDED_VM_EXITS exits{};
    exits.ExceptionExit = 1;
    exits.X64MsrExit = unhandled; // No CPUID exits or MSR emulation.
    check(WHvSetPartitionProperty(p, WHvPartitionPropertyCodeExtendedVmExits, &exits, sizeof(exits)), "exception exits");
    uint64_t bitmap = exceptions & ((1ull << 1) | (1ull << 6) | (1ull << 13));
    printf("CONFIG LbrRequested=%d ExtendedVmExits=0x%llx "
           "ExceptionBitmap=0x%llx TF=0 MSR_EXIT=%d\n",
           lbr, exits.AsUINT64, bitmap, unhandled);
    check(WHvSetPartitionProperty(p, WHvPartitionPropertyCodeExceptionExitBitmap, &bitmap, sizeof(bitmap)), "exception bitmap");
    if (unhandled) {
      WHV_X64_MSR_EXIT_BITMAP msrs{};
      msrs.UnhandledMsrs = 1;
      HRESULT msrHr = WHvSetPartitionProperty(p, WHvPartitionPropertyCodeX64MsrExitBitmap, &msrs, sizeof(msrs));
      printf("SET MsrExitBitmap UnhandledMsrs=1 hr=0x%08lx\n", (unsigned long)msrHr);
      check(msrHr, "MSR exit bitmap");
    }
    if (lbr) {
      WHV_PROCESSOR_PERFMON_FEATURES perf{};
      perf.LbrSupport = 1;
      HRESULT hr = WHvSetPartitionProperty(p, WHvPartitionPropertyCodeProcessorPerfmonFeatures, &perf, sizeof(perf));
      printf("SET Perfmon Lbr raw=0x%llx hr=0x%08lx\n", perf.AsUINT64, (unsigned long)hr);
      check(hr, "request Lbr");
    }
    if (exactAction) {
      WHV_MSR_ACTION_ENTRY entry{};
      entry.Index = actionIndex;
      entry.ReadAction = WHvMsrActionExit;
      entry.WriteAction = WHvMsrActionExit;
      HRESULT actionHr = WHvSetPartitionProperty(p, WHvPartitionPropertyCodeMsrActionList, &entry, sizeof(entry));
      printf("SET MsrActionList Index=0x%x ReadAction=%u WriteAction=%u "
             "hr=0x%08lx\n",
             entry.Index, entry.ReadAction, entry.WriteAction, (unsigned long)actionHr);
      check(actionHr, "MSR action list");
    }
    check(WHvSetupPartition(p), "setup partition");
    WHV_PROCESSOR_PERFMON_FEATURES perf{};
    UINT32 written = 0;
    HRESULT hr = WHvGetPartitionProperty(p, WHvPartitionPropertyCodeProcessorPerfmonFeatures, &perf, sizeof(perf), &written);
    printf("PARTITION Perfmon hr=0x%08lx raw=0x%llx Pmu=%u Lbr=%u\n", (unsigned long)hr, perf.AsUINT64, (unsigned)perf.PmuSupport,
           (unsigned)perf.LbrSupport);
    check(hr, "get partition Perfmon");
    require(written == sizeof(perf), "partition Perfmon size");
    check(WHvCreateVirtualProcessor(p, 0, 0), "create vp");
    vp = true;
    memory = (unsigned char *)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) throw std::runtime_error("VirtualAlloc");
    // Each immutable slot starts with one instruction or WRMSR;RDMSR, then HLT.
    for (unsigned n = 0; n < 64; n++) {
      unsigned char *b = memory + 0x1000 + n * 16;
      b[0] = 0x0f;
      b[1] = 0x32;
      b[2] = 0xf4;
    }
    for (unsigned n = 64; n < 128; n++) {
      unsigned char *b = memory + 0x1000 + n * 16;
      b[0] = 0x0f;
      b[1] = 0x30;
      b[2] = 0x0f;
      b[3] = 0x32;
      b[4] = 0xf4;
    }
    memory[0x2000] = 0x0f;
    memory[0x2001] = 0xa2;
    memory[0x2002] = 0xf4;
    check(WHvMapGpaRange(p, memory, 0, 0x10000,
                         (WHV_MAP_GPA_RANGE_FLAGS)(WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute)),
          "map");
    WHV_REGISTER_NAME names[] = {WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs,
                                 WHvX64RegisterSs, WHvX64RegisterFs, WHvX64RegisterGs};
    WHV_REGISTER_VALUE vals[6]{};
    for (int i = 0; i < 6; i++) {
      vals[i].Segment.Limit = 0xffff;
      vals[i].Segment.Attributes = (i == 0) ? 0x9b : 0x93;
    }
    check(WHvSetVirtualProcessorRegisters(p, 0, names, 6, vals), "segments");
    reg(WHvX64RegisterCr0, 0x10);
    reg(WHvX64RegisterCr3, 0);
    reg(WHvX64RegisterCr4, 0);
    reg(WHvX64RegisterEfer, 0);
    reg(WHvX64RegisterRsp, 0xff00);
    reg(WHvX64RegisterDr7, 0x400);
    reg(WHvX64RegisterDr6, 0xffff0ff0);
    printf("REGISTER_API DebugCtl unavailable: no WHvX64RegisterDebugCtl in "
           "SDK 10.0.28000.0; no guessed ID used\n");
  }
  bool run(const char *label, bool write, uint32_t msr, uint64_t input, uint64_t &output, bool cpuid = false) {
    require(cpuid || sequence < 64, "instruction slot exhaustion");
    uint64_t rip = cpuid ? 0x2000 : 0x1000 + 16 * (sequence++ + (write ? 64 : 0));
    reg(WHvX64RegisterRip, rip);
    reg(WHvX64RegisterRflags, 2);
    reg(WHvX64RegisterRcx, msr);
    reg(WHvX64RegisterRax, (uint32_t)input);
    reg(WHvX64RegisterRdx, (uint32_t)(input >> 32));
    reg(WHvRegisterPendingInterruption, 0);
    reg(WHvRegisterPendingEvent, 0);
    std::mutex mutex;
    std::condition_variable cv;
    bool done = false;
    HRESULT cancelHr = S_OK;
    std::thread watchdog([&] {
      std::unique_lock<std::mutex> lock(mutex);
      if (!cv.wait_for(lock, std::chrono::seconds(5), [&] { return done; })) cancelHr = WHvCancelRunVirtualProcessor(p, 0, 0);
    });
    WHV_RUN_VP_EXIT_CONTEXT ctx{};
    HRESULT hr = WHvRunVirtualProcessor(p, 0, &ctx, sizeof(ctx));
    {
      std::lock_guard<std::mutex> lock(mutex);
      done = true;
    }
    cv.notify_one();
    watchdog.join();
    check(cancelHr, "cancel virtual processor");
    check(hr, "run virtual processor");
    WHV_REGISTER_NAME names[] = {WHvX64RegisterRax, WHvX64RegisterRdx,    WHvX64RegisterRcx,
                                 WHvX64RegisterRbx, WHvX64RegisterRflags, WHvX64RegisterRip};
    WHV_REGISTER_VALUE values[6]{};
    check(WHvGetVirtualProcessorRegisters(p, 0, names, 6, values), "readback");
    output = ((values[1].Reg64 & 0xffffffff) << 32) | (values[0].Reg64 & 0xffffffff);
    printf("RUN %s op=%s msr=0x%x input=0x%016llx hr=0x%08lx exit=0x%x "
           "start=0x%llx rip=0x%llx rflags=0x%llx TF=%u value=0x%016llx\n",
           label,
           cpuid   ? "CPUID"
           : write ? "WRMSR_RDMSR"
                   : "RDMSR",
           msr, input, (unsigned long)hr, ctx.ExitReason, rip, values[5].Reg64, values[4].Reg64, (unsigned)((values[4].Reg64 >> 8) & 1),
           output);
    if (cpuid)
      printf("GUEST_CPUID leaf=0x%x subleaf=0x%x EAX=%08x EBX=%08x ECX=%08x "
             "EDX=%08x\n",
             (uint32_t)input, msr, values[0].Reg32, values[3].Reg32, values[2].Reg32, values[1].Reg32);
    if (ctx.ExitReason == WHvRunVpExitReasonException)
      printf("EXCEPTION vector=%u GP=%u DB=%u errorValid=%u error=0x%x "
             "instructionLen=%u bytes=%02x %02x %02x %02x\n",
             ctx.VpException.ExceptionType, ctx.VpException.ExceptionType == 13, ctx.VpException.ExceptionType == 1,
             ctx.VpException.ExceptionInfo.ErrorCodeValid, ctx.VpException.ErrorCode, ctx.VpContext.InstructionLength,
             ctx.VpException.InstructionBytes[0], ctx.VpException.InstructionBytes[1], ctx.VpException.InstructionBytes[2],
             ctx.VpException.InstructionBytes[3]);
    if (ctx.ExitReason == WHvRunVpExitReasonX64MsrAccess)
      printf("MSR_EXIT number=0x%x write=%u\n", ctx.MsrAccess.MsrNumber, ctx.MsrAccess.AccessInfo.IsWrite);
    if (ctx.ExitReason == WHvRunVpExitReasonMemoryAccess)
      printf("MEMORY_EXIT gpa=0x%llx gva=0x%llx\n", ctx.MemoryAccess.Gpa, ctx.MemoryAccess.Gva);
    fflush(stdout);
    require((values[4].Reg64 & 0x100) == 0, "unexpected TF");
    bool halted = ctx.ExitReason == WHvRunVpExitReasonX64Halt;
    bool msrExit = ctx.ExitReason == WHvRunVpExitReasonX64MsrAccess;
    bool exception = ctx.ExitReason == WHvRunVpExitReasonException;
    require(halted || msrExit ||
                (exception &&
                 (ctx.VpException.ExceptionType == 1 || ctx.VpException.ExceptionType == 6 || ctx.VpException.ExceptionType == 13)),
            "unexpected exit or watchdog cancellation");
    if (msrExit) require(ctx.MsrAccess.MsrNumber == msr && bool(ctx.MsrAccess.AccessInfo.IsWrite) == write, "MSR exit identity");
    if (cpuid) require(halted, "CPUID control did not halt");
    if (!cpuid && msr == 0x174) require(halted && (!write || output == input), "SYSENTER control roundtrip");
    if (!cpuid && msr == 0xffffffff) {
      require(invalidMsrExits ? msrExit
                              : (exception && ctx.VpException.ExceptionType == 13 && ctx.VpException.ExceptionInfo.ErrorCodeValid &&
                                 ctx.VpException.ErrorCode == 0),
              "invalid MSR control");
      require(values[5].Reg64 == rip, "invalid MSR advanced RIP");
    }
    return halted;
  }
};
static void suite(bool lbr, uint64_t exceptions, bool unhandled = false) {
  printf("\nSUITE %s\n", lbr ? "LbrRequested" : unhandled ? "UnhandledMsrs" : "Default");
  Probe p;
  p.setup(lbr, exceptions, unhandled);
  uint64_t result = 0;
  for (uint32_t leaf : {0u, 1u, 7u, 0xau, 0x80000000u, 0x80000001u, 0x80000008u, 0x8000000au})
    p.run("guest-capability", false, 0, leaf, result, true);
  uint64_t controlOriginal = 0;
  if (p.run("control-sysenter-cs-original", false, 0x174, 0, controlOriginal)) {
    p.run("control-sysenter-cs-write-read", true, 0x174, 0x10, result);
    p.run("control-sysenter-cs-restore", true, 0x174, controlOriginal, result);
  }
  p.run("control-invalid-msr", false, 0xffffffff, 0, result);
  p.run("control-invalid-msr-write", true, 0xffffffff, 1, result);
  uint64_t original = 0;
  if (!p.run("original", false, 0x1d9, 0, original)) {
    printf("FINDING cannot read original\n");
    return;
  }
  for (unsigned bit = 1; bit <= 4; bit++) {
    char label[48];
    sprintf_s(label, "bit%u-write-read", bit);
    bool ok = p.run(label, true, 0x1d9, original | (1ull << bit), result);
    printf("RESULT bit=%u completed=%d requested=0x%llx observed=0x%llx "
           "retained=%d\n",
           bit, ok, original | (1ull << bit), result, ok && ((result & (1ull << bit)) != 0));
    sprintf_s(label, "bit%u-restore", bit);
    p.run(label, true, 0x1d9, original, result);
  }
  for (uint64_t value : {1ull, 2ull, 3ull, 4ull, 0x8000000000000000ull}) {
    char label[64];
    sprintf_s(label, "exact-0x%llx-write-read", value);
    p.run(label, true, 0x1d9, value, result);
    p.run("exact-restore", true, 0x1d9, original, result);
  }
  p.run("all-bits-write-read", true, 0x1d9, original | 0x1e, result);
  p.run("all-restore", true, 0x1d9, original, result);
  p.run("final-read", false, 0x1d9, 0, result);
}
int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  printf("Standalone WHP guest probe; no kernemul/hypermulator; no host "
         "RDMSR/WRMSR.\n");
  printf("LIMITATION real-mode guest only; no host configuration changes; access results depend on process privilege.\n");
  printf("LIMITATION invalid exact-action control also enables coarse exits; entry-specific attribution is unavailable.\n");
  int info[4]{};
  __cpuidex(info, 0, 0);
  char vendor[13]{};
  memcpy(vendor, info + 1, 4);
  memcpy(vendor + 4, info + 3, 4);
  memcpy(vendor + 8, info + 2, 4);
  printf("HOST_CPUID vendor=%s maxleaf=0x%x\n", vendor, info[0]);
  for (unsigned leaf : {1u, 7u, 0xau, 0x80000001u, 0x80000008u, 0x8000000au}) {
    __cpuidex(info, leaf, 0);
    printf("HOST_CPUID leaf=0x%x EAX=%08x EBX=%08x ECX=%08x EDX=%08x\n", leaf, info[0], info[1], info[2], info[3]);
  }
  capability(WHvCapabilityCodeX64MsrExitBitmap, "X64MsrExitBitmap");
  capability(WHvCapabilityCodeHypervisorPresent, "HypervisorPresent");
  capability(WHvCapabilityCodeFeatures, "Features");
  capability(WHvCapabilityCodeExtendedVmExits, "ExtendedVmExits");
  Capability exceptions = capability(WHvCapabilityCodeExceptionExitBitmap, "ExceptionExitBitmap");
  capability(WHvCapabilityCodeProcessorVendor, "ProcessorVendor");
  capability(WHvCapabilityCodeProcessorFeatures, "ProcessorFeatures");
  Capability perf = capability(WHvCapabilityCodeProcessorPerfmonFeatures, "ProcessorPerfmonFeatures");
  if (!exceptions.known || !(exceptions.raw & (1ull << 13))) {
    printf("FATAL required #GP exception capability unavailable or unknown\n");
    return 1;
  }
  int failures = 0;
  auto attempt = [&](const char *name, bool optional, auto body) {
    printf("\nPROBE %s\n", name);
    try {
      body();
    } catch (const ApiError &e) {
      // Only configuration rejection is a finding. Runtime/API failures still
      // fail.
      bool configuration = !strcmp(e.what(), "setup partition") || !strcmp(e.what(), "request Lbr") || !strcmp(e.what(), "MSR action list");
      bool unsupported = e.hr == static_cast<HRESULT>(0xC0350005u) || e.hr == static_cast<HRESULT>(0xC0350006u) || e.hr == E_NOTIMPL ||
                         e.hr == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
      if (optional && configuration && unsupported) printf("FINDING %s REJECTED %s hr=0x%08lx\n", name, e.what(), (unsigned long)e.hr);
      else {
        printf("FATAL %s %s hr=0x%08lx\n", name, e.what(), (unsigned long)e.hr);
        ++failures;
      }
    } catch (const std::exception &e) {
      printf("FATAL %s %s\n", name, e.what());
      ++failures;
    }
  };
  attempt("Default", false, [&] { suite(false, exceptions.raw); });
  attempt("UnhandledMsrs", false, [&] { suite(false, exceptions.raw, true); });
  attempt("ExactDebugCtlAction", true, [&] {
    Probe p;
    p.setup(false, exceptions.raw, true, true);
    uint64_t result = 0;
    p.run("exact-action-read", false, 0x1d9, 0, result);
    for (uint64_t value : {0ull, 1ull, 2ull, 3ull, 4ull, 8ull, 16ull, 30ull, 0x8000000000000000ull}) {
      char label[64];
      sprintf_s(label, "exact-action-write-0x%llx", value);
      p.run(label, true, 0x1d9, value, result);
    }
    p.run("exact-action-control-sysenter-cs", false, 0x174, 0, result);
  });
  attempt("ExactDebugCtlActionNoCoarseExit", true, [&] {
    Probe p;
    p.setup(false, exceptions.raw, false, true);
    uint64_t result = 0;
    p.run("exact-action-no-coarse-read", false, 0x1d9, 0, result);
  });
  attempt("ExactInvalidMsrActionControl", true, [&] {
    Probe p;
    p.setup(false, exceptions.raw, true, true, 0xffffffff);
    uint64_t result = 0;
    p.run("exact-invalid-action-read", false, 0xffffffff, 0, result);
    p.run("exact-invalid-action-write", true, 0xffffffff, 1, result);
  });
  printf("LBR availability=%s; fresh partition request once\n", perf.known ? ((perf.raw & 2) ? "present" : "absent") : "unknown");
  attempt("LbrRequested", true, [&] { suite(true, exceptions.raw); });
  printf("SUMMARY failures=%d\n", failures);
  return failures ? 1 : 0;
}
