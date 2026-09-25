#include <ntddk.h>

/* Emulator-only fault injection: never install or execute on a real kernel. */
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    LARGE_INTEGER due;
    PKTIMER invalid = (PKTIMER)(ULONG_PTR)0xFFFFFE00BAD00000ull;
    BOOLEAN retained;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);
    due.QuadPart = -10000;
    DbgPrint("CONFORMANCE BEGIN invalid-timer-memory\n");
    /* The redirect diagnoses the unmapped object; its return value is unspecified. */
    (void)KeSetTimer(invalid, due, NULL);
    due.QuadPart = -500000;
    KeDelayExecutionThread(KernelMode, FALSE, &due);
    retained = KeCancelTimer(invalid);
    DbgPrint("CONFORMANCE %s invalid-timer-not-retained\n", retained ? "FAIL" : "PASS");
    DbgPrint("CONFORMANCE PASS invalid-timer-survived-timekeeper\n");
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", retained ? 1L : 0L);
    return retained ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
