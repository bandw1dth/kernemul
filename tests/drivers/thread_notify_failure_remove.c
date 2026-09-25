#include <ntddk.h>

/* Emulator-only negative fixture: removal from the callback is forbidden. */
static void child(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    DbgPrint("THREAD_NOTIFY_REMOVE FORBIDDEN_CHILD\n");
}

static void notify(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    UNREFERENCED_PARAMETER(pid);
    UNREFERENCED_PARAMETER(tid);
    if (!create) return;
    DbgPrint("THREAD_NOTIFY_REMOVE PRE_REMOVE\n");
    PsRemoveCreateThreadNotifyRoutine(notify);
    DbgPrint("THREAD_NOTIFY_REMOVE FORBIDDEN_POST_REMOVE\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    HANDLE handle;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);
    status = PsSetCreateThreadNotifyRoutine(notify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("THREAD_NOTIFY_REMOVE SETUP_FAILED\n");
        return status;
    }
    DbgPrint("THREAD_NOTIFY_REMOVE PRE_CREATE\n");
    PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, child, NULL);
    DbgPrint("THREAD_NOTIFY_REMOVE FORBIDDEN_POST_CREATE\n");
    return STATUS_UNSUCCESSFUL;
}
