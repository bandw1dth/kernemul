#include <ntifs.h>

/* Emulator-specific failed-creation fault injection.
 * Never install this fixture on a host Windows kernel. */
static LONG failures;
static volatile LONG creates, exits, entered, after_terminate;
static KEVENT release_child;

static void check(BOOLEAN ok, const char* name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}
static void notify(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    UNREFERENCED_PARAMETER(pid); UNREFERENCED_PARAMETER(tid);
    if (create) InterlockedIncrement(&creates); else InterlockedIncrement(&exits);
}
static void child(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    InterlockedIncrement(&entered);
    KeWaitForSingleObject(&release_child, Executive, KernelMode, FALSE, NULL);
    PsTerminateSystemThread(STATUS_SUCCESS);
    InterlockedIncrement(&after_terminate);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    HANDLE handle = (HANDLE)(ULONG_PTR)0x1234;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    KeInitializeEvent(&release_child, NotificationEvent, FALSE);
    status = PsSetCreateThreadNotifyRoutine(notify);
    check(NT_SUCCESS(status), "register-boundary-observer");
    if (!NT_SUCCESS(status)) goto done;
    status = PsCreateSystemThread(NULL, THREAD_ALL_ACCESS, NULL, NULL, NULL, child, NULL);
    check(!NT_SUCCESS(status) && !creates && !exits && !entered, "null-output-no-child-or-event");
    status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL,
        (PCLIENT_ID)(ULONG_PTR)0xFFFFFE00BAD00000ull, child, NULL);
    check(status == STATUS_ACCESS_VIOLATION && handle == (HANDLE)(ULONG_PTR)0x1234 &&
        !creates && !exits && !entered, "invalid-cid-no-child-or-event");
    handle = NULL;
    status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, child, NULL);
    check(NT_SUCCESS(status) && handle && creates == 1, "create-boundary-child");
    if (NT_SUCCESS(status) && handle) {
        KeSetEvent(&release_child, IO_NO_INCREMENT, FALSE);
        timeout.QuadPart = -20000000;
        status = ZwWaitForSingleObject(handle, FALSE, &timeout);
        check(status == STATUS_SUCCESS && entered == 1 && creates == 1 && exits == 1 &&
            !after_terminate, "valid-child-after-failed-creates-exits-once");
        ZwClose(handle);
    }
    check(PsRemoveCreateThreadNotifyRoutine(notify) == STATUS_SUCCESS, "remove-boundary-observer");
done:
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
