#include <ntifs.h>

#if !defined(REGISTRY_NOTIFY_FAILURE_MODE) || !defined(REGISTRY_NOTIFY_FAILURE_KIND) || !defined(REGISTRY_NOTIFY_FAILURE_KEY)
#error Registry notification failure fixture mode, kind, and key are required.
#endif

static KTIMER invalid_timer;
static LARGE_INTEGER registration_cookie;
static UNICODE_STRING key_name = RTL_CONSTANT_STRING(REGISTRY_NOTIFY_FAILURE_KEY);
static UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"398764.91");
static UNICODE_STRING value_name = RTL_CONSTANT_STRING(L"FailureValue");

static NTSTATUS registry_notify_failure_callback(PVOID context, PVOID argument1, PVOID argument2)
{
    REG_NOTIFY_CLASS notification = (REG_NOTIFY_CLASS)(ULONG_PTR)argument1;
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(argument2);
    if (notification != RegNtPreSetValueKey) return STATUS_SUCCESS;

    DbgPrint("REGISTRY_NOTIFY_FAILURE PRE_CALLBACK_%s\n", REGISTRY_NOTIFY_FAILURE_KIND);
#if REGISTRY_NOTIFY_FAILURE_MODE == 1
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
#elif REGISTRY_NOTIFY_FAILURE_MODE == 2
    CmUnRegisterCallback(registration_cookie);
#elif REGISTRY_NOTIFY_FAILURE_MODE == 3
    {
        LARGE_INTEGER due;
        due.QuadPart = -10000;
        KeSetTimerEx(&invalid_timer, due, -1, NULL);
    }
#elif REGISTRY_NOTIFY_FAILURE_MODE == 4
    PsTerminateSystemThread(STATUS_SUCCESS);
#else
#error Unsupported registry notification failure fixture mode.
#endif
    DbgPrint("REGISTRY_NOTIFY_FAILURE FORBIDDEN_POST_CALLBACK\n");
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE key = NULL;
    ULONG disposition = 0;
    ULONG value = 0x4e4f5449;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(path);

    KeInitializeTimer(&invalid_timer);
    InitializeObjectAttributes(&attributes, &key_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateKey(&key, KEY_ALL_ACCESS, &attributes, 0, NULL,
        REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status) || !key) {
        DbgPrint("REGISTRY_NOTIFY_FAILURE SETUP_FAILED create-key status=%lx\n", status);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    status = CmRegisterCallbackEx(registry_notify_failure_callback, &altitude,
        driver, NULL, &registration_cookie, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("REGISTRY_NOTIFY_FAILURE SETUP_FAILED register status=%lx\n", status);
        ZwClose(key);
        return status;
    }

    DbgPrint("REGISTRY_NOTIFY_FAILURE PRE_SET\n");
    status = ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value));
    DbgPrint("REGISTRY_NOTIFY_FAILURE FORBIDDEN_POST_SET status=%lx\n", status);
    return STATUS_UNSUCCESSFUL;
}
