/* Guest input only. Run with one vCPU; never load on the host. */
#define KeGetCurrentIrql WdkInlineGetCurrentIrql
#include <ntifs.h>
#include <intrin.h>
#undef KeGetCurrentIrql
NTSYSAPI KIRQL NTAPI KeGetCurrentIrql(VOID);

static LONG failures;
static KEVENT ready, gate;
static volatile LONG entered, bad_child_irql;
static volatile LONG dpc_calls, bad_dpc_irql;
static LARGE_INTEGER frequency;

static void check(BOOLEAN ok, const char *name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

static void busy_ms(LONGLONG ms)
{
    LARGE_INTEGER start = KeQueryPerformanceCounter(NULL), now;
    do {
        YieldProcessor(); /* PAUSE is a hint, never a scheduling operation. */
        now = KeQueryPerformanceCounter(NULL);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart * ms / 1000);
}

static NTSTATUS wait_event(PVOID event)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -30000000;
    return KeWaitForSingleObject(event, Executive, KernelMode, FALSE, &timeout);
}

static void competitor(PVOID unused)
{
    UNREFERENCED_PARAMETER(unused);
    KeSetEvent(&ready, IO_NO_INCREMENT, FALSE);
    if (wait_event(&gate) != STATUS_SUCCESS) {
        InterlockedIncrement(&bad_child_irql);
    } else {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL || __readcr8() != PASSIVE_LEVEL)
            InterlockedIncrement(&bad_child_irql);
        InterlockedIncrement(&entered);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static HANDLE prepare_competitor(void)
{
    HANDLE handle = NULL;
    NTSTATUS status;
    entered = bad_child_irql = 0;
    KeInitializeEvent(&ready, NotificationEvent, FALSE);
    KeInitializeEvent(&gate, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        competitor, NULL);
    check(NT_SUCCESS(status) && handle != NULL, "competitor-created");
    if (!NT_SUCCESS(status) || !handle) return NULL;
    check(wait_event(&ready) == STATUS_SUCCESS, "competitor-ready");
    return handle;
}

static void join_competitor(HANDLE handle)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -30000000;
    check(ZwWaitForSingleObject(handle, FALSE, &timeout) == STATUS_SUCCESS, "competitor-joined");
    check(entered == 1 && !bad_child_irql, "competitor-runs-at-passive-after-release");
    check(ZwClose(handle) == STATUS_SUCCESS, "competitor-handle-closed");
}

/* Default host quantum is 50ms (kernel.hpp). 200ms crosses >=3 boundaries.
 * The gate is opened at DISPATCH, before any HIGH_LEVEL transition, so no
 * event operation is issued above its Windows IRQL contract. */
static void exclusion(ULONG mode)
{
    HANDLE handle = prepare_competitor();
    KSPIN_LOCK lock;
    KIRQL old;
    LONG observed;
    BOOLEAN consistent;
    if (!handle) return;
    KeInitializeSpinLock(&lock);
    if (mode == 0) KeAcquireSpinLock(&lock, &old);
    else if (mode == 2) { old = (KIRQL)__readcr8(); __writecr8(DISPATCH_LEVEL); }
    else old = KfRaiseIrql(DISPATCH_LEVEL);
    KeSetEvent(&gate, IO_NO_INCREMENT, FALSE);
    if (mode == 1) (void)KfRaiseIrql(HIGH_LEVEL);
    consistent = KeGetCurrentIrql() == (mode == 1 ? HIGH_LEVEL : DISPATCH_LEVEL) &&
        __readcr8() == (mode == 1 ? HIGH_LEVEL : DISPATCH_LEVEL);
    busy_ms(200);
    observed = entered;
    if (mode == 0) KeReleaseSpinLock(&lock, old);
    else if (mode == 2) __writecr8(old);
    else KeLowerIrql(old);
    check(consistent, "raised-api-and-cr8-agree");
    check(observed == 0, mode == 0 ? "dispatch-spinlock-no-preemption-200ms" :
        mode == 1 ? "high-level-no-preemption-200ms" : "direct-cr8-no-preemption-200ms");
    check(KeGetCurrentIrql() == PASSIVE_LEVEL && __readcr8() == PASSIVE_LEVEL,
        "lowered-api-and-cr8-agree");
    /* No blocking call: direct CR8 lowering must re-enable ordinary preemption. */
    busy_ms(200);
    check(entered == 1, "lowering-reenables-ordinary-preemption");
    join_competitor(handle);
}

static void apc_preemption(void)
{
    HANDLE handle = prepare_competitor();
    KIRQL old;
    LONG observed;
    BOOLEAN preserved;
    if (!handle) return;
    old = KfRaiseIrql(DISPATCH_LEVEL);
    KeSetEvent(&gate, IO_NO_INCREMENT, FALSE);
    KeLowerIrql(APC_LEVEL);
    busy_ms(200);
    observed = entered;
    preserved = KeGetCurrentIrql() == APC_LEVEL && __readcr8() == APC_LEVEL;
    KeLowerIrql(old);
    check(observed == 1, "apc-allows-passive-competitor-without-explicit-yield");
    check(preserved, "apc-preserved-on-resume");
    join_competitor(handle);
}

static void dpc_routine(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1); UNREFERENCED_PARAMETER(arg2);
    if (KeGetCurrentIrql() != DISPATCH_LEVEL || __readcr8() != DISPATCH_LEVEL)
        InterlockedIncrement(&bad_dpc_irql);
    InterlockedIncrement(&dpc_calls);
}

static void dpc_restore(KIRQL target)
{
    KDPC dpc;
    BOOLEAN queued, deferred, restored, delivered;
    dpc_calls = bad_dpc_irql = 0;
    KeInitializeDpc(&dpc, dpc_routine, NULL);
    (void)KfRaiseIrql(DISPATCH_LEVEL);
    queued = KeInsertQueueDpc(&dpc, NULL, NULL);
    busy_ms(200);
    deferred = dpc_calls == 0;
    KeLowerIrql(target);
    busy_ms(200);
    restored = KeGetCurrentIrql() == target && __readcr8() == target;
    delivered = dpc_calls == 1 && !bad_dpc_irql;
    KeLowerIrql(PASSIVE_LEVEL);
    KeFlushQueuedDpcs();
    check(queued && deferred, "queued-dpc-deferred-at-dispatch");
    check(delivered && dpc_calls == 1, "dpc-runs-once-at-dispatch-after-lower");
    check(restored, target == APC_LEVEL ? "dpc-restores-apc" : "dpc-restores-passive");
}

static void dispatch_poll(void)
{
    HANDLE handle = prepare_competitor();
    KEVENT signaled, empty;
    LARGE_INTEGER zero, start, now;
    KIRQL old;
    BOOLEAN statuses = TRUE;
    LONG observed;
    if (!handle) return;
    zero.QuadPart = 0;
    KeInitializeEvent(&signaled, NotificationEvent, TRUE);
    KeInitializeEvent(&empty, NotificationEvent, FALSE);
    old = KfRaiseIrql(DISPATCH_LEVEL);
    KeSetEvent(&gate, IO_NO_INCREMENT, FALSE);
    start = KeQueryPerformanceCounter(NULL);
    do {
        if (KeWaitForSingleObject(&signaled, Executive, KernelMode, FALSE, &zero) != STATUS_SUCCESS ||
            KeWaitForSingleObject(&empty, Executive, KernelMode, FALSE, &zero) != STATUS_TIMEOUT)
            statuses = FALSE;
        YieldProcessor();
        now = KeQueryPerformanceCounter(NULL);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart / 5);
    observed = entered;
    KeLowerIrql(old);
    check(statuses, "dispatch-zero-poll-success-and-timeout");
    check(observed == 0, "dispatch-zero-poll-and-pause-do-not-yield");
    join_competitor(handle);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(registry);
    check(KeQueryActiveProcessorCount(NULL) == 1, "requires-one-vcpu");
    KeQueryPerformanceCounter(&frequency);
    check(frequency.QuadPart > 0, "qpc-frequency-positive");
    if (!failures) {
        exclusion(0); exclusion(1); exclusion(2);
        apc_preemption(); dpc_restore(APC_LEVEL); dpc_restore(PASSIVE_LEVEL);
        dispatch_poll();
    }
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
