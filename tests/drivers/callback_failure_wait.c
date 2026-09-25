#include <ntddk.h>

static KEVENT never_signalled;

/* Expected: controlled scheduler stop after PRE_WAIT; neither FORBIDDEN marker. */
static void notify(PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    DbgPrint("CALLBACK_WAIT PRE_WAIT\n");
    KeWaitForSingleObject(&never_signalled, Executive, KernelMode, FALSE, NULL);
    DbgPrint("CALLBACK_WAIT FORBIDDEN_POST_WAIT\n");
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

    KeInitializeEvent(&never_signalled, NotificationEvent, FALSE);
    RtlInitUnicodeString(&name, L"\\Callback\\KernemulFailureWait");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ExCreateCallback(&object, &attributes, TRUE, TRUE);
    if (!NT_SUCCESS(status) || !object) {
        DbgPrint("CALLBACK_WAIT SETUP_FAILED_CREATE status=%08lx\n", status);
        return STATUS_UNSUCCESSFUL;
    }
    registration = ExRegisterCallback(object, notify, NULL);
    if (!registration) {
        DbgPrint("CALLBACK_WAIT SETUP_FAILED_REGISTER\n");
        ObDereferenceObject(object);
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("CALLBACK_WAIT PRE_NOTIFY\n");
    ExNotifyCallback(object, NULL, NULL);
    DbgPrint("CALLBACK_WAIT FORBIDDEN_POST_NOTIFY\n");
    ExUnregisterCallback(registration);
    ObDereferenceObject(object);
    return STATUS_UNSUCCESSFUL;
}
