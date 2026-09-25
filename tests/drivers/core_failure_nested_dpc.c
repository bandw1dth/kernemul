#include <ntddk.h>

/* Emulator-only negative test: threadless DPC -> ExNotifyCallback -> unsupported
 * export. Expect one unsupported diagnostic and no forbidden continuation.
 * Static storage remains valid after DriverEntry returns.
 */
static KTIMER timer;
static KDPC dpc;
static PCALLBACK_OBJECT object;

static void notify(PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);
    DbgPrint("NESTED_DPC PRE_UNSUPPORTED\n");
    (void)KeQueryActiveGroupCount();
    DbgPrint("NESTED_DPC FORBIDDEN_POST_CALLBACK\n");
}

static void nested_dpc(PKDPC deferred, PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(deferred);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);
    DbgPrint("NESTED_DPC PRE_NOTIFY\n");
    ExNotifyCallback(object, NULL, NULL);
    DbgPrint("NESTED_DPC FORBIDDEN_POST_NOTIFY\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    LARGE_INTEGER due;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);
    RtlInitUnicodeString(&name, L"\\Callback\\KernemulFailureNestedDpc");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ExCreateCallback(&object, &attributes, TRUE, TRUE);
    if (!NT_SUCCESS(status) || !object) {
        DbgPrint("NESTED_DPC SETUP_FAILED_CREATE\n");
        return STATUS_UNSUCCESSFUL;
    }
    if (!ExRegisterCallback(object, notify, NULL)) {
        DbgPrint("NESTED_DPC SETUP_FAILED_REGISTER\n");
        ObDereferenceObject(object);
        return STATUS_UNSUCCESSFUL;
    }
    KeInitializeTimer(&timer);
    KeInitializeDpc(&dpc, nested_dpc, NULL);
    due.QuadPart = -5000000;
    KeSetTimer(&timer, due, &dpc);
    DbgPrint("NESTED_DPC ARMED returning-driver-entry\n");
    return STATUS_SUCCESS;
}
