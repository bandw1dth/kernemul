#include <ntddk.h>

/* Emulator-only negative fixture: a nested callback cannot suspend its caller. */
typedef NTSTATUS (NTAPI *SUSPEND_THREAD)(HANDLE, PULONG);
static SUSPEND_THREAD suspend_thread;
static void child(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    DbgPrint("THREAD_NOTIFY_SUSPEND FORBIDDEN_CHILD\n");
}
static void notify(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    ULONG previous;
    UNREFERENCED_PARAMETER(pid); UNREFERENCED_PARAMETER(tid);
    if (!create) return;
    DbgPrint("THREAD_NOTIFY_SUSPEND PRE_SUSPEND\n");
    suspend_thread((HANDLE)(LONG_PTR)-2, &previous);
    DbgPrint("THREAD_NOTIFY_SUSPEND FORBIDDEN_POST_SUSPEND\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    HANDLE handle;
    NTSTATUS status;
    UNICODE_STRING name;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    RtlInitUnicodeString(&name, L"ZwSuspendThread");
    suspend_thread = (SUSPEND_THREAD)MmGetSystemRoutineAddress(&name);
    if (!suspend_thread) {
        DbgPrint("THREAD_NOTIFY_SUSPEND SETUP_FAILED\n");
        return STATUS_NOT_SUPPORTED;
    }
    status = PsSetCreateThreadNotifyRoutine(notify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("THREAD_NOTIFY_SUSPEND SETUP_FAILED\n");
        return status;
    }
    DbgPrint("THREAD_NOTIFY_SUSPEND PRE_CREATE\n");
    PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, child, NULL);
    DbgPrint("THREAD_NOTIFY_SUSPEND FORBIDDEN_POST_CREATE\n");
    return STATUS_UNSUCCESSFUL;
}
