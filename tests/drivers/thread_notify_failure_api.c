#include <ntddk.h>

/* Emulator-only invalid API input, to verify checked callback failure propagation. */
static KTIMER timer;
static void child(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    DbgPrint("THREAD_NOTIFY_API FORBIDDEN_CHILD\n");
}
static void notify(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    LARGE_INTEGER due;
    UNREFERENCED_PARAMETER(pid); UNREFERENCED_PARAMETER(tid);
    if (!create) return;
    DbgPrint("THREAD_NOTIFY_API PRE_FAULT\n");
    due.QuadPart = -10000;
    KeSetTimerEx(&timer, due, -1, NULL);
    DbgPrint("THREAD_NOTIFY_API FORBIDDEN_POST_FAULT\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    HANDLE handle;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    KeInitializeTimer(&timer);
    status = PsSetCreateThreadNotifyRoutine(notify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("THREAD_NOTIFY_API SETUP_FAILED\n");
        return status;
    }
    DbgPrint("THREAD_NOTIFY_API PRE_CREATE\n");
    PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, child, NULL);
    DbgPrint("THREAD_NOTIFY_API FORBIDDEN_POST_CREATE\n");
    return STATUS_UNSUCCESSFUL;
}
