#include <ntddk.h>
static void extended(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{ UNREFERENCED_PARAMETER(process); UNREFERENCED_PARAMETER(pid); UNREFERENCED_PARAMETER(info); }
static void classic(HANDLE parent, HANDLE pid, BOOLEAN create)
{ UNREFERENCED_PARAMETER(parent); UNREFERENCED_PARAMETER(pid); UNREFERENCED_PARAMETER(create); }
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    LONG failures = 0;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    status = PsSetCreateProcessNotifyRoutineEx(extended, FALSE);
    if (status != STATUS_ACCESS_DENIED) { ++failures; DbgPrint("CONFORMANCE FAIL Ex-without-integrity-flag\n"); }
    else DbgPrint("CONFORMANCE PASS Ex-without-integrity-flag\n");
    status = PsSetCreateProcessNotifyRoutine(classic, FALSE);
    if (!NT_SUCCESS(status)) { ++failures; DbgPrint("CONFORMANCE FAIL classic-without-integrity-flag\n"); }
    else {
        DbgPrint("CONFORMANCE PASS classic-without-integrity-flag\n");
        if (!NT_SUCCESS(PsSetCreateProcessNotifyRoutine(classic, TRUE))) ++failures;
    }
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
