#include <ntddk.h>

/* A zero-timeout poll is legal through DISPATCH_LEVEL, not above it. Guest only. */
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    KEVENT event;
    LARGE_INTEGER timeout;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);
    KeInitializeEvent(&event, NotificationEvent, TRUE);
    timeout.QuadPart = 0;
    (void)KfRaiseIrql(HIGH_LEVEL);
    DbgPrint("IRQL_NEGATIVE PRE_POLL\n");
    (void)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &timeout);
    DbgPrint("IRQL_NEGATIVE FORBIDDEN_RETURN\n");
    KeLowerIrql(PASSIVE_LEVEL);
    return STATUS_UNSUCCESSFUL;
}
