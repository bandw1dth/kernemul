#include <ntddk.h>
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    LARGE_INTEGER interval;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    /* The queued user launcher must wait even when DriverEntry yields. */
    interval.QuadPart = -1000000;
    DbgPrint("PROCESS_LAUNCH DRIVER_WAIT\n");
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    DbgPrint("PROCESS_LAUNCH DRIVER_FAILED\n");
    return STATUS_ACCESS_DENIED;
}
