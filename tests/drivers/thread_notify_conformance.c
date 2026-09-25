#include <ntifs.h>

/* Guest-only checks. Returning from a system-thread routine is an emulator
 * extension; the other children use Windows' documented self-exit API. */
static LONG failures;
static HANDLE creator, process_id, observed_id;
static volatile LONG creates[2], exits[2], entered, bad_context;
static LONG active_callbacks;

static void check(BOOLEAN ok, const char* name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

static void observe(ULONG slot, HANDLE pid, HANDLE tid, BOOLEAN create)
{
    if (pid != process_id || KeGetCurrentIrql() > APC_LEVEL)
        InterlockedIncrement(&bad_context);
    if (create) {
        if (PsGetCurrentThreadId() != creator || tid == creator || entered)
            InterlockedIncrement(&bad_context);
        if (observed_id && observed_id != tid) InterlockedIncrement(&bad_context);
        observed_id = tid;
        InterlockedIncrement(&creates[slot]);
    } else {
        if (PsGetCurrentThreadId() != tid || tid != observed_id || !entered)
            InterlockedIncrement(&bad_context);
        InterlockedIncrement(&exits[slot]);
    }
}
static void notify_a(HANDLE pid, HANDLE tid, BOOLEAN create) { observe(0, pid, tid, create); }
static void notify_b(HANDLE pid, HANDLE tid, BOOLEAN create) { observe(1, pid, tid, create); }

static void child(PVOID mode)
{
    if (active_callbacks && (!creates[0] || (active_callbacks == 2 && !creates[1])))
        InterlockedIncrement(&bad_context);
    InterlockedIncrement(&entered);
    if (mode) {
        PsTerminateSystemThread(STATUS_SUCCESS);
        DbgPrint("CONFORMANCE FAIL termination-returned\n");
        InterlockedIncrement(&bad_context);
    }
}

static void run_child(BOOLEAN explicit_exit, LONG callbacks)
{
    HANDLE handle = NULL;
    CLIENT_ID cid = {0};
    LARGE_INTEGER timeout;
    NTSTATUS status;
    creates[0] = creates[1] = exits[0] = exits[1] = 0;
    entered = bad_context = 0;
    observed_id = NULL;
    active_callbacks = callbacks;
    status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, &cid,
        child, (PVOID)(ULONG_PTR)explicit_exit);
    check(NT_SUCCESS(status) && handle, "create-system-thread");
    if (!NT_SUCCESS(status) || !handle) return;
    check(cid.UniqueProcess == process_id && cid.UniqueThread != creator &&
        (!callbacks || cid.UniqueThread == observed_id), "notification-subject-client-id");
    timeout.QuadPart = -20000000;
    status = ZwWaitForSingleObject(handle, FALSE, &timeout);
    check(status == STATUS_SUCCESS, "thread-completion-wait");
    check(entered == 1 && !bad_context, "callback-context-and-before-entry");
    check(creates[0] == (callbacks >= 1) && exits[0] == (callbacks >= 1) &&
        creates[1] == (callbacks == 2) && exits[1] == (callbacks == 2),
        "exactly-once-exit-before-wakeup-and-removal");
    check(NT_SUCCESS(ZwClose(handle)), "close-thread-handle");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    NTSTATUS a, b;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);
    creator = PsGetCurrentThreadId();
    process_id = PsGetCurrentProcessId();
    a = PsSetCreateThreadNotifyRoutine(notify_a);
    b = PsSetCreateThreadNotifyRoutine(notify_b);
    check(NT_SUCCESS(a) && NT_SUCCESS(b), "register-two-callbacks");
    check(!creates[0] && !creates[1] && !exits[0] && !exits[1], "no-seed-replay");
    if (NT_SUCCESS(a) && NT_SUCCESS(b)) {
        run_child(FALSE, 2); /* Existing emulator natural-return extension. */
        run_child(TRUE, 2);
        check(PsRemoveCreateThreadNotifyRoutine(notify_b) == STATUS_SUCCESS, "remove-second-callback");
        b = STATUS_UNSUCCESSFUL;
        run_child(TRUE, 1);
        check(PsRemoveCreateThreadNotifyRoutine(notify_a) == STATUS_SUCCESS, "remove-first-callback");
        a = STATUS_UNSUCCESSFUL;
        check(PsRemoveCreateThreadNotifyRoutine(notify_a) == STATUS_PROCEDURE_NOT_FOUND,
            "remove-absent-callback");
        run_child(TRUE, 0);
    }
    if (NT_SUCCESS(a)) PsRemoveCreateThreadNotifyRoutine(notify_a);
    if (NT_SUCCESS(b)) PsRemoveCreateThreadNotifyRoutine(notify_b);
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
