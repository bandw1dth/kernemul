#include <ntddk.h>

/* Expected: controlled scheduler stop after PRE_WAIT; neither FORBIDDEN marker. */
static void notify(PVOID context, PVOID arg1, PVOID arg2)
{
    LARGE_INTEGER interval;
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    interval.QuadPart = -10000000LL;
    DbgPrint("CALLBACK_DELAY PRE_WAIT\n");
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    DbgPrint("CALLBACK_DELAY FORBIDDEN_POST_WAIT\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    PCALLBACK_OBJECT object = NULL;
    PVOID registration;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);

    RtlInitUnicodeString(&name, L"\\Callback\\KernemulFailureDelay");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ExCreateCallback(&object, &attributes, TRUE, TRUE);
    if (!NT_SUCCESS(status) || !object) {
        DbgPrint("CALLBACK_DELAY SETUP_FAILED_CREATE status=%08lx\n", status);
        return STATUS_UNSUCCESSFUL;
    }
    registration = ExRegisterCallback(object, notify, NULL);
    if (!registration) {
        DbgPrint("CALLBACK_DELAY SETUP_FAILED_REGISTER\n");
        ObDereferenceObject(object);
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("CALLBACK_DELAY PRE_NOTIFY\n");
    ExNotifyCallback(object, NULL, NULL);
    DbgPrint("CALLBACK_DELAY FORBIDDEN_POST_NOTIFY\n");
    ExUnregisterCallback(registration);
    ObDereferenceObject(object);
    return STATUS_UNSUCCESSFUL;
}
