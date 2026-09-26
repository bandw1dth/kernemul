#include <ntddk.h>

/* Guest-only negative fixture; host runner must enforce a deadline. */
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    (void)KfRaiseIrql(HIGH_LEVEL);
    DbgPrint("IRQL_NEGATIVE PRE_FATAL\n");
    *(volatile ULONG *)(ULONG_PTR)0 = 0x12345678;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);
    DbgPrint("IRQL_NEGATIVE FORBIDDEN_RETURN\n");
    KeLowerIrql(PASSIVE_LEVEL);
    return STATUS_UNSUCCESSFUL;
}
