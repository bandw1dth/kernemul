#include <ntddk.h>

/* Emulator-only negative test; never install on a real kernel.
 * Arm static storage and return so expiry can run without a guest thread.
 * Expected host evidence: one BEGIN, one unsupported-export diagnostic,
 * one failed DPC dispatch, prompt process exit, and no AFTER marker.
 * Confirm the DPC log has tid=0; otherwise threadless coverage is inconclusive.
 */
static KTIMER timer;
static KDPC dpc;

static void unsupported_dpc(PKDPC deferred, PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(deferred);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);
    DbgPrint("CONFORMANCE BEGIN threadless-unsupported-dpc\n");
    /* Exported by ntoskrnl, but has no emulator redirect. */
    (void)KeQueryActiveGroupCount();
    DbgPrint("CONFORMANCE FAIL unsupported-dpc-AFTER\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    LARGE_INTEGER due;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);
    KeInitializeTimer(&timer);
    KeInitializeDpc(&dpc, unsupported_dpc, NULL);
    due.QuadPart = -5000000; /* Expire 500 ms after arming, after DriverEntry returns. */
    KeSetTimer(&timer, due, &dpc);
    DbgPrint("CONFORMANCE ARMED threadless-unsupported-dpc returning-driver-entry\n");
    return STATUS_SUCCESS;
}
