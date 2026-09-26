#include <ntddk.h>

/* Guest-only negative fixture; host runner must enforce a deadline. */
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -50000000;
    (void)KfRaiseIrql(DISPATCH_LEVEL);
    DbgPrint("IRQL_NEGATIVE PRE_DELAY\n");
    (void)KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);
    DbgPrint("IRQL_NEGATIVE FORBIDDEN_RETURN\n");
    KeLowerIrql(PASSIVE_LEVEL);
    return STATUS_UNSUCCESSFUL;
}
