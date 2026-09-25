#include <ntddk.h>

/* Runs only when explicitly loaded as a guest image. No host installation. */
static LONG failures;
static volatile LONG dpc_calls;
static volatile LONG dpc_bad_irql;
static KEVENT dpc_event;
static KTIMER periodic;

static void check(BOOLEAN ok, const char* name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

static LARGE_INTEGER relative_ms(LONGLONG ms)
{
    LARGE_INTEGER result;
    result.QuadPart = -ms * 10000;
    return result;
}

static NTSTATUS wait_for(PVOID object, LONGLONG ms)
{
    LARGE_INTEGER timeout = relative_ms(ms);
    return KeWaitForSingleObject(object, Executive, KernelMode, FALSE, &timeout);
}

static void dpc_routine(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2)
{
    LONG calls;
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);
    if (KeGetCurrentIrql() != DISPATCH_LEVEL) InterlockedIncrement(&dpc_bad_irql);
    calls = InterlockedIncrement(&dpc_calls);
    if (calls >= (LONG)(LONG_PTR)context) KeSetEvent(&dpc_event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    KTIMER timer;
    KDPC dpc;
    LARGE_INTEGER due, before, after, frequency, counter_before, counter_after;
    KIRQL previous_irql;
    BOOLEAN queued, duplicate_queue, removed, removed_again;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);

    KeQuerySystemTime(&before); /* WDK inline reads KUSER_SHARED_DATA directly. */
    counter_before = KeQueryPerformanceCounter(&frequency);
    check(before.QuadPart > 116444736000000000LL, "shared-system-time-initialized");
    check(frequency.QuadPart > 0, "qpc-frequency");

    KeInitializeTimer(&timer);
    due = relative_ms(50);
    check(!KeSetTimer(&timer, due, NULL), "initial-arm-not-previously-queued");
    check(wait_for(&timer, 2000) == STATUS_SUCCESS, "notification-expiry-wakes-waiter");
    check(KeReadStateTimer(&timer), "notification-remains-signaled");
    check(wait_for(&timer, 0) == STATUS_SUCCESS, "notification-second-wait");
    check(!KeCancelTimer(&timer), "expired-one-shot-not-queued");

    due = relative_ms(500);
    check(!KeSetTimer(&timer, due, NULL), "rearm-expired-timer");
    check(!KeReadStateTimer(&timer), "rearm-clears-signal");
    check(KeCancelTimer(&timer), "cancel-armed");
    check(!KeCancelTimer(&timer), "cancel-idempotent");
    check(wait_for(&timer, 550) == STATUS_TIMEOUT, "cancelled-timer-does-not-signal-past-original-deadline");

    due = relative_ms(500);
    KeSetTimer(&timer, due, NULL);
    due = relative_ms(20);
    check(KeSetTimer(&timer, due, NULL), "replace-reports-queued");
    check(wait_for(&timer, 300) == STATUS_SUCCESS, "replacement-deadline");

    KeInitializeTimer(&timer);
    due = relative_ms(20);
    KeSetTimer(&timer, due, NULL);
    due = relative_ms(80);
    check(KeDelayExecutionThread(KernelMode, FALSE, &due) == STATUS_SUCCESS, "delay-success");
    check(KeReadStateTimer(&timer), "expiry-without-timer-wait-or-poll");
    KeQuerySystemTime(&due);
    due.QuadPart -= 10000;
    KeSetTimer(&timer, due, NULL);
    check(wait_for(&timer, 300) == STATUS_SUCCESS, "absolute-past-deadline");

    KeInitializeTimerEx(&timer, SynchronizationTimer);
    due = relative_ms(30);
    KeSetTimer(&timer, due, NULL);
    check(wait_for(&timer, 2000) == STATUS_SUCCESS, "synchronization-expiry");
    check(!KeReadStateTimer(&timer), "synchronization-consumed");
    check(wait_for(&timer, 0) == STATUS_TIMEOUT, "synchronization-second-wait-times-out");

    KeInitializeEvent(&dpc_event, NotificationEvent, FALSE);
    KeInitializeDpc(&dpc, dpc_routine, (PVOID)1);
    check(KeInsertQueueDpc(&dpc, NULL, NULL), "dpc-first-insert");
    check(wait_for(&dpc_event, 2000) == STATUS_SUCCESS, "dpc-delivered");
    KeFlushQueuedDpcs();
    KeClearEvent(&dpc_event);
    check(KeInsertQueueDpc(&dpc, NULL, NULL), "dpc-reusable-after-delivery");
    check(wait_for(&dpc_event, 2000) == STATUS_SUCCESS, "dpc-redelivered");
    KeFlushQueuedDpcs();
    check(dpc_calls == 2 && dpc_bad_irql == 0, "dpc-count-and-dispatch-irql");

    KeRaiseIrql(DISPATCH_LEVEL, &previous_irql);
    queued = KeInsertQueueDpc(&dpc, NULL, NULL);
    duplicate_queue = KeInsertQueueDpc(&dpc, NULL, NULL);
    removed = KeRemoveQueueDpc(&dpc);
    removed_again = KeRemoveQueueDpc(&dpc);
    KeLowerIrql(previous_irql);
    KeFlushQueuedDpcs();
    check(queued && !duplicate_queue, "dpc-single-queued-instance");
    check(removed && !removed_again && dpc_calls == 2, "removed-dpc-not-delivered");

    dpc_calls = 0;
    KeClearEvent(&dpc_event);
    KeInitializeDpc(&dpc, dpc_routine, (PVOID)3);
    KeInitializeTimer(&periodic);
    due = relative_ms(20);
    KeSetTimerEx(&periodic, due, 20, &dpc);
    check(wait_for(&dpc_event, 2000) == STATUS_SUCCESS, "periodic-three-deliveries");
    KeCancelTimer(&periodic);
    KeFlushQueuedDpcs();
    check(dpc_calls >= 3 && dpc_bad_irql == 0, "periodic-dpc-context");
    check(KeGetCurrentIrql() == PASSIVE_LEVEL, "caller-irql-restored");

    KeQuerySystemTime(&after);
    counter_after = KeQueryPerformanceCounter(NULL);
    check(after.QuadPart > before.QuadPart, "shared-system-time-advances");
    check(counter_after.QuadPart > counter_before.QuadPart, "qpc-advances");
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
