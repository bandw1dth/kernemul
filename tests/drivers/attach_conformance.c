#include <ntifs.h>
#include <intrin.h>
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#endif

/* Guest only. No host execution, callback waits, or extended notify registration. */
NTKERNELAPI UCHAR *PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS,
    PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

#define VA ((PUCHAR)(ULONG_PTR)0x200000000ULL)
#define SELF ((HANDLE)(LONG_PTR)-1)
#define CANARY 0xCCCCCCCCu
static volatile LONG failures, creates, exits, ready[2];
static volatile LONG subject_exits[2];
static PEPROCESS targets[2], system_process;
static HANDLE pids[2];
static ULONG seed[1024];

static void check(BOOLEAN ok, const char *label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) InterlockedIncrement(&failures);
}

/* Keep AC windows free of calls, waits, and diagnostics. */
/* TF belongs to the emulator; do not replay it through guest PUSHFQ. */
static ULONG peek(ULONG offset)
{
    ULONG value;
    ULONG_PTR flags = __readeflags() & ~(1ULL << 8);
    __writeeflags(flags | (1ULL << 18));
    value = *(volatile ULONG *)(VA + offset);
    __writeeflags(flags);
    return value;
}
static void poke(ULONG offset, ULONG value)
{
    ULONG_PTR flags = __readeflags() & ~(1ULL << 8);
    __writeeflags(flags | (1ULL << 18));
    *(volatile ULONG *)(VA + offset) = value;
    __writeeflags(flags);
}
static void context(PEPROCESS effective)
{
    check(PsGetCurrentProcess() == effective && PsGetCurrentProcessId() == (HANDLE)4 &&
        PsGetThreadProcess(PsGetCurrentThread()) == system_process, "effective-process-owner-invariant");
}
static void notify(HANDLE parent, HANDLE pid, BOOLEAN create)
{
    PEPROCESS process = NULL, original;
    KAPC_STATE state;
    PVOID base = VA;
    SIZE_T size = 3 * PAGE_SIZE, copied = 0;
    NTSTATUS status;
    UCHAR *name;
    BOOLEAN valid_name;
    ULONG slot;
    if (!create) {
        check(pid == pids[0] || pid == pids[1], "exit-known-subject");
        if (pid == pids[0]) InterlockedIncrement(&subject_exits[0]);
        if (pid == pids[1]) InterlockedIncrement(&subject_exits[1]);
        InterlockedIncrement(&exits);
        return;
    }
    InterlockedIncrement(&creates);
    status = PsLookupProcessByProcessId(pid, &process);
    check(status == STATUS_SUCCESS && process, "create-lookup-retain");
    if (!NT_SUCCESS(status) || !process) return;
    name = PsGetProcessImageFileName(process);
    valid_name = name && RtlCompareMemory(name, "attach_user_", 12) == 12 &&
        (name[12] == 'a' || name[12] == 'b');
    check(valid_name, "create-image-name");
    if (!valid_name) { ObDereferenceObject(process); return; }
    slot = name[12] == 'a' ? 0 : 1;
    check(!targets[slot] && parent == (HANDLE)4, "create-exact-cli-subject");
    if (targets[slot]) { ObDereferenceObject(process); return; }
    targets[slot] = process; pids[slot] = pid;
    original = PsGetCurrentProcess();
    KeStackAttachProcess(process, &state);
    context(process);
    status = ZwAllocateVirtualMemory(SELF, &base, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    check(status == STATUS_SUCCESS && base == VA && size == 3 * PAGE_SIZE, "callback-fixed-allocation");
    if (status == STATUS_SUCCESS && base == VA) {
        /* Each callback owns its control seed; the common page seed is immutable. */
        ULONG control[4] = { 0, CANARY, CANARY, 0 };
        control[0] = slot ? 0xA11CB002u : 0xA11CA001u;
        status = MmCopyVirtualMemory(system_process, seed, process, VA, PAGE_SIZE, KernelMode, &copied);
        check(status == STATUS_SUCCESS && copied == PAGE_SIZE, "callback-seed-page-through-copy");
        if (status == STATUS_SUCCESS && copied == PAGE_SIZE) {
            status = MmCopyVirtualMemory(system_process, control, process, VA, sizeof(control), KernelMode, &copied);
            check(status == STATUS_SUCCESS && copied == sizeof(control), "callback-seed-control-through-copy");
        }
    }
    KeUnstackDetachProcess(&state);
    check(PsGetCurrentProcess() == original && PsGetCurrentProcessId() == (HANDLE)4,
        "callback-detach-restores-creator");
    InterlockedExchange(&ready[slot], status == STATUS_SUCCESS && copied == 16 ? 1 : -1);
}

static BOOLEAN removed(HANDLE pid)
{
    PEPROCESS found = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &found);
    if (NT_SUCCESS(status) && found) ObDereferenceObject(found);
    return pid && status == STATUS_INVALID_CID;
}
static void copy_tests(void)
{
    KAPC_STATE state;
    NTSTATUS status;
    SIZE_T copied, size;
    PVOID base;
    ULONG old, protection, i;
    copied = 99;
    status = MmCopyVirtualMemory(targets[0], VA, targets[1], VA + 8, 4, KernelMode, &copied);
    check(status == STATUS_SUCCESS && copied == 4, "explicit-process-prefix-copy");
    KeStackAttachProcess(targets[1], &state);
    check(peek(8) == 0xA11CA001u && peek(0) == 0xA11CB002u, "prefix-copy-canaries");
    poke(PAGE_SIZE, CANARY);
    for (i = 0; i < 3; ++i) {
        protection = i == 0 ? PAGE_READONLY : i == 1 ? PAGE_NOACCESS : PAGE_READWRITE | PAGE_GUARD;
        base = VA + PAGE_SIZE; size = PAGE_SIZE;
        status = ZwProtectVirtualMemory(SELF, &base, &size, protection, &old);
        check(status == STATUS_SUCCESS, "protect-negative-destination");
        if (!NT_SUCCESS(status)) continue;
        copied = 99;
        status = MmCopyVirtualMemory(targets[0], VA, targets[1], VA + PAGE_SIZE, 4, KernelMode, &copied);
        check(!NT_SUCCESS(status) && copied == 0, "protected-destination-rejected");
        base = VA + PAGE_SIZE; size = PAGE_SIZE;
        status = ZwProtectVirtualMemory(SELF, &base, &size, PAGE_READWRITE, &old);
        check(status == STATUS_SUCCESS, "restore-negative-destination");
        if (NT_SUCCESS(status)) check(peek(PAGE_SIZE) == CANARY, "protected-destination-canary");
    }
    base = VA + 2 * PAGE_SIZE; size = PAGE_SIZE;
    status = ZwFreeVirtualMemory(SELF, &base, &size, MEM_DECOMMIT);
    check(status == STATUS_SUCCESS, "decommit-third-page");
    if (NT_SUCCESS(status)) {
        copied = 99;
        status = MmCopyVirtualMemory(targets[0], VA, targets[1], VA + 2 * PAGE_SIZE, 4, KernelMode, &copied);
        check(!NT_SUCCESS(status) && copied == 0, "uncommitted-destination-rejected");
        copied = 99;
        status = MmCopyVirtualMemory(targets[0], VA + PAGE_SIZE - 16, targets[1],
            VA + 2 * PAGE_SIZE - 16, 32, KernelMode, &copied);
        check(status == STATUS_PARTIAL_COPY && copied == 16, "partial-copy-exact-valid-prefix");
        check(peek(2 * PAGE_SIZE - 16) == CANARY && peek(2 * PAGE_SIZE - 4) == CANARY,
            "partial-copy-prefix-data");
    }
    KeUnstackDetachProcess(&state);
    copied = 99;
    status = MmCopyVirtualMemory(targets[0], VA, targets[1], VA + 3 * PAGE_SIZE, 4, KernelMode, &copied);
    check(!NT_SUCCESS(status) && copied == 0, "unmapped-destination-rejected");
    copied = 99;
    status = MmCopyVirtualMemory(targets[0], VA, targets[1], VA + 8, 0, KernelMode, &copied);
    check(status == STATUS_SUCCESS && copied == 0, "zero-length-copy");
    copied = 99;
    status = MmCopyVirtualMemory(targets[0], (PVOID)(ULONG_PTR)-8, targets[1], VA + 8, 16, KernelMode, &copied);
    check(!NT_SUCCESS(status) && copied == 0, "overflow-range-rejected");
    KeStackAttachProcess(targets[0], &state);
    poke(32, 99); poke(36, 0);
    status = MmCopyVirtualMemory(targets[0], (PVOID)0xFFFF800000000000ULL, targets[1],
        VA + 8, 4, UserMode, (PSIZE_T)(VA + 32));
    check(!NT_SUCCESS(status) && peek(32) == 0 && peek(36) == 0, "user-limit-range-rejected");
    copied = 99;
    status = MmCopyVirtualMemory(targets[0], VA, targets[1], VA + 16, 4, UserMode, &copied);
    check(!NT_SUCCESS(status) && copied == 99, "kernel-bytecount-output-rejected-before-mutation");
    status = MmCopyVirtualMemory(targets[0], VA, targets[1], VA + 16, 4, UserMode, (PSIZE_T)1);
    check(!NT_SUCCESS(status), "invalid-bytecount-output-rejected");
    KeUnstackDetachProcess(&state);
    KeStackAttachProcess(targets[1], &state);
    check(peek(8) == 0xA11CA001u && peek(0) == 0xA11CB002u && peek(4) == 0xBEEF1234u && peek(16) == CANARY,
        "negative-api-canaries-unchanged");
    KeUnstackDetachProcess(&state);
}

static void monitor(PVOID unused)
{
    LARGE_INTEGER delay;
    KAPC_STATE a, b, same;
    ULONG attempt, slot, completed;
    HANDLE kernel_handles[2] = { NULL, NULL };
    UNREFERENCED_PARAMETER(unused);
    delay.QuadPart = -100000; /* 10 ms; each wait phase is bounded to ten seconds. */
    for (attempt = 0; attempt < 1000; ++attempt) {
        if (ready[0] && ready[1]) break;
        if (KeDelayExecutionThread(KernelMode, FALSE, &delay) != STATUS_SUCCESS) break;
    }
    check(ready[0] == 1 && ready[1] == 1, "both-targets-published-within-deadline");
    if (ready[0] == 1 && ready[1] == 1) {
        context(system_process);
        KeStackAttachProcess(targets[0], &a); context(targets[0]);
        check(peek(0) == 0xA11CA001u, "attached-a-real-memory");
        KeStackAttachProcess(targets[1], &b); context(targets[1]);
        check(peek(0) == 0xA11CB002u, "nested-b-distinct-same-va");
        KeStackAttachProcess(targets[1], &same); context(targets[1]);
        poke(4, 0xBEEF1234u);
        check(KeDelayExecutionThread(KernelMode, FALSE, &delay) == STATUS_SUCCESS, "yield-while-attached");
        context(targets[1]);
        check(peek(0) == 0xA11CB002u && peek(4) == 0xBEEF1234u, "scheduler-restores-attached-memory");
        KeUnstackDetachProcess(&same); context(targets[1]);
        check(peek(4) == 0xBEEF1234u, "same-process-detach-lifo");
        KeUnstackDetachProcess(&b); context(targets[0]);
        check(peek(0) == 0xA11CA001u && peek(4) == CANARY, "nested-detach-restores-a-isolation");
        KeUnstackDetachProcess(&a); context(system_process);
        copy_tests();
    }
    for (slot = 0; slot < 2; ++slot) if (ready[slot] == 1) {
        OBJECT_ATTRIBUTES attributes;
        CLIENT_ID cid;
        InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        cid.UniqueProcess = pids[slot]; cid.UniqueThread = NULL;
        check(ZwOpenProcess(&kernel_handles[slot], PROCESS_VM_READ | PROCESS_VM_WRITE,
            &attributes, &cid) == STATUS_SUCCESS && kernel_handles[slot], "create-kernel-process-handle");
        KeStackAttachProcess(targets[slot], &a);
        poke(48, (ULONG)(ULONG_PTR)kernel_handles[slot]);
        poke(52, (ULONG)((ULONG_PTR)kernel_handles[slot] >> 32));
        poke(24, (ULONG)(ULONG_PTR)pids[1 - slot]);
        poke(36, 0); poke(40, 0);
        poke(12, 1);
        KeUnstackDetachProcess(&a);
    }
    /* Keep both address spaces alive until native peer reads have finished. */
    for (attempt = 0; attempt < 1000; ++attempt) {
        if (exits || ready[0] != 1 || ready[1] != 1) break;
        completed = 0;
        for (slot = 0; slot < 2; ++slot) {
            KeStackAttachProcess(targets[slot], &a);
            if (peek(36) == 1) ++completed;
            KeUnstackDetachProcess(&a);
        }
        if (completed == 2) {
            for (slot = 0; slot < 2; ++slot) {
                KeStackAttachProcess(targets[slot], &a); poke(40, 1); KeUnstackDetachProcess(&a);
            }
            break;
        }
        if (KeDelayExecutionThread(KernelMode, FALSE, &delay) != STATUS_SUCCESS) break;
    }
    for (attempt = 0; attempt < 1000; ++attempt) {
        if (KeDelayExecutionThread(KernelMode, FALSE, &delay) != STATUS_SUCCESS) break;
        if (exits == 2 && removed(pids[0]) && removed(pids[1])) break;
    }
    check(creates == 2 && exits == 2 && subject_exits[0] == 1 && subject_exits[1] == 1 && attempt < 1000,
        "exact-two-create-exit-callbacks");
    check(pids[0] != pids[1] && removed(pids[0]) && removed(pids[1]), "both-pids-removed");
    check(PsSetCreateProcessNotifyRoutine(notify, TRUE) == STATUS_SUCCESS, "unregister-outside-callback");
    for (slot = 0; slot < 2; ++slot) if (kernel_handles[slot])
        check(ZwClose(kernel_handles[slot]) == STATUS_SUCCESS, "close-kernel-process-handle");
    for (slot = 0; slot < 2; ++slot) if (targets[slot]) ObDereferenceObject(targets[slot]);
    DbgPrint("ATTACH COMPLETE\n");
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    HANDLE thread = NULL;
    NTSTATUS status;
    ULONG i;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    system_process = PsGetCurrentProcess();
    for (i = 0; i < RTL_NUMBER_OF(seed); ++i) seed[i] = CANARY;
    context(system_process);
    status = PsSetCreateProcessNotifyRoutine(notify, FALSE);
    check(status == STATUS_SUCCESS, "register-classic-notify");
    if (!NT_SUCCESS(status)) return status;
    status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, monitor, NULL);
    check(status == STATUS_SUCCESS && thread, "create-monitor");
    if (!NT_SUCCESS(status) || !thread) {
        PsSetCreateProcessNotifyRoutine(notify, TRUE);
        return STATUS_UNSUCCESSFUL;
    }
    check(ZwClose(thread) == STATUS_SUCCESS, "close-monitor-handle");
    DbgPrint("ATTACH READY\n");
    return STATUS_SUCCESS;
}
