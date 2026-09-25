#include <ntddk.h>

/* Emulator-only negative fixture: thread callbacks must not block. */
static void child(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    DbgPrint("THREAD_NOTIFY_DELAY FORBIDDEN_CHILD\n");
}

static void notify(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    LARGE_INTEGER delay;
    UNREFERENCED_PARAMETER(pid);
    UNREFERENCED_PARAMETER(tid);
    if (!create) return;
    DbgPrint("THREAD_NOTIFY_DELAY PRE_WAIT\n");
    delay.QuadPart = -10000000;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    DbgPrint("THREAD_NOTIFY_DELAY FORBIDDEN_POST_WAIT\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    HANDLE handle;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);
    status = PsSetCreateThreadNotifyRoutine(notify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("THREAD_NOTIFY_DELAY SETUP_FAILED\n");
        return status;
    }
    DbgPrint("THREAD_NOTIFY_DELAY PRE_CREATE\n");
    PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, child, NULL);
    DbgPrint("THREAD_NOTIFY_DELAY FORBIDDEN_POST_CREATE\n");
    return STATUS_UNSUCCESSFUL;
}
