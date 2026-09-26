#include <ntddk.h>
NTSYSAPI NTSTATUS NTAPI ZwYieldExecution(VOID);
/* Guest-only negative fixture; host runner must enforce a deadline. */
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    (void)KfRaiseIrql(DISPATCH_LEVEL);
    DbgPrint("IRQL_NEGATIVE PRE_YIELD\n");
    (void)ZwYieldExecution();
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);
    DbgPrint("IRQL_NEGATIVE FORBIDDEN_RETURN\n");
    KeLowerIrql(PASSIVE_LEVEL);
    return STATUS_UNSUCCESSFUL;
}
