#include <ntifs.h>

/* Guest-only: seeded process objects provide a distinct attachment target. */
static LONG failures, callbacks, entered;
static PEPROCESS owner, alternate;

static void check(BOOLEAN ok, const char* name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

static void notify(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    PETHREAD subject = NULL;
    KAPC_STATE state;
    if (!create) return;
    ++callbacks;
    check(tid != PsGetCurrentThreadId() && entered == 0,
        "query-child-before-entry");
    check(NT_SUCCESS(PsLookupThreadByThreadId(tid, &subject)) && subject,
        "lookup-notification-subject");
    if (!subject) return;
    check(PsGetThreadProcess(subject) == owner && PsGetProcessId(owner) == pid,
        "child-owner-matches-notification");
    KeStackAttachProcess(alternate, &state);
    check(PsGetThreadProcess(subject) == owner, "other-thread-owner-during-attach");
    check(PsGetThreadProcess(PsGetCurrentThread()) == owner,
        "current-thread-owner-during-attach");
    KeUnstackDetachProcess(&state);
    check(PsGetThreadProcess(subject) == owner, "child-owner-after-detach");
    ObDereferenceObject(subject);
}

static void child(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    ++entered;
    check(PsGetThreadProcess(PsGetCurrentThread()) == owner, "running-child-owner");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    ULONG_PTR id;
    NTSTATUS status;
    HANDLE handle = NULL;
    LARGE_INTEGER timeout;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);
    owner = PsGetCurrentProcess();
    check(PsGetThreadProcess(PsGetCurrentThread()) == owner, "initial-thread-owner");
    for (id = 4; id < 1024; id += 4) {
        PEPROCESS candidate = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)id, &candidate))) {
            if (candidate != owner) { alternate = candidate; break; }
            ObDereferenceObject(candidate);
        }
    }
    check(alternate != NULL, "distinct-attachment-target");
    if (alternate) {
        status = PsSetCreateThreadNotifyRoutine(notify);
        check(NT_SUCCESS(status), "register-owner-observer");
        if (NT_SUCCESS(status)) {
            status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL,
                NULL, NULL, child, NULL);
            check(NT_SUCCESS(status) && handle, "create-observed-child");
            if (NT_SUCCESS(status) && handle) {
                timeout.QuadPart = -20000000;
                check(ZwWaitForSingleObject(handle, FALSE, &timeout) == STATUS_SUCCESS,
                    "wait-child-completion");
                check(NT_SUCCESS(ZwClose(handle)), "close-child");
            }
            check(callbacks == 1 && entered == 1, "exactly-one-callback-and-child");
            check(NT_SUCCESS(PsRemoveCreateThreadNotifyRoutine(notify)), "remove-observer");
        }
        ObDereferenceObject(alternate);
    }
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
