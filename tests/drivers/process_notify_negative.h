#include <ntddk.h>
static KTIMER timer;
static void observe(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{
    LARGE_INTEGER delay;
    UNREFERENCED_PARAMETER(process); UNREFERENCED_PARAMETER(pid);
#if PROCESS_NEGATIVE == 5
    if (info) return;
#else
    if (!info) return;
#endif
    DbgPrint("PROCESS_NEGATIVE BEGIN %d\n", PROCESS_NEGATIVE);
#if PROCESS_NEGATIVE == 1 || PROCESS_NEGATIVE == 5
    delay.QuadPart = -10000000;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
#elif PROCESS_NEGATIVE == 2
    PsSetCreateProcessNotifyRoutineEx(observe, TRUE);
#elif PROCESS_NEGATIVE == 3
    delay.QuadPart = -10000;
    KeSetTimerEx(&timer, delay, -1, NULL);
#elif PROCESS_NEGATIVE == 4
    info->ParentProcessId = (HANDLE)0x1234;
    DbgPrint("PROCESS_NEGATIVE MUTATED\n");
    return;
#endif
    DbgPrint("PROCESS_NEGATIVE FORBIDDEN_CONTINUATION\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    KeInitializeTimer(&timer);
    status = PsSetCreateProcessNotifyRoutineEx(observe, FALSE);
    if (!NT_SUCCESS(status)) DbgPrint("PROCESS_NEGATIVE SETUP_FAILED 0x%08X\n", status);
    else DbgPrint("PROCESS_NEGATIVE READY\n");
    return status;
}
