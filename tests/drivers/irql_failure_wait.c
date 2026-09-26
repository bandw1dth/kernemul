#include <ntddk.h>

/* Guest-only negative fixture; host runner must enforce a deadline. */
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    KEVENT event;
    LARGE_INTEGER timeout;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    timeout.QuadPart = -50000000;
    (void)KfRaiseIrql(DISPATCH_LEVEL);
    DbgPrint("IRQL_NEGATIVE PRE_WAIT\n");
    (void)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &timeout);
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);
    DbgPrint("IRQL_NEGATIVE FORBIDDEN_RETURN\n");
    KeLowerIrql(PASSIVE_LEVEL);
    return STATUS_UNSUCCESSFUL;
}
