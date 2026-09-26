#include <ntifs.h>
#include "ob_test_access.h"

#if !defined(OB_NOTIFY_FAILURE_MODE) || !defined(OB_NOTIFY_FAILURE_KIND)
#error Object notification failure fixture mode and kind are required.
#endif

static KTIMER invalid_timer;
static PVOID registration_handle;
static LONG nested_callback_depth;
static UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"398766.71");

static OB_PREOP_CALLBACK_STATUS ob_notify_failure_pre(
    PVOID context, POB_PRE_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(info);
    DbgPrint("OB_NOTIFY_%s PRE_%s\n", OB_NOTIFY_FAILURE_KIND,
        OB_NOTIFY_FAILURE_KIND);

#if OB_NOTIFY_FAILURE_MODE == 1
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
#elif OB_NOTIFY_FAILURE_MODE == 2
    ObUnRegisterCallbacks(registration_handle);
#elif OB_NOTIFY_FAILURE_MODE == 3
    {
        LARGE_INTEGER due;
        due.QuadPart = -10000;
        KeSetTimerEx(&invalid_timer, due, -1, NULL);
    }
#elif OB_NOTIFY_FAILURE_MODE == 4
    return (OB_PREOP_CALLBACK_STATUS)1;
#elif OB_NOTIFY_FAILURE_MODE == 5
    if (InterlockedIncrement(&nested_callback_depth) > 1) {
        DbgPrint("OB_NOTIFY_%s FORBIDDEN_REENTRANT_CALLBACK\n",
            OB_NOTIFY_FAILURE_KIND);
        InterlockedDecrement(&nested_callback_depth);
        return OB_PREOP_SUCCESS;
    }
    {
        HANDLE nested_handle = NULL;
        NTSTATUS status = ObOpenObjectByPointer(PsGetCurrentProcess(), 0, NULL,
            PROCESS_TERMINATE, *PsProcessType, KernelMode, &nested_handle);
        DbgPrint("OB_NOTIFY_%s FORBIDDEN_AFTER_NESTED_OPEN status=%lx\n",
            OB_NOTIFY_FAILURE_KIND, status);
    }
    InterlockedDecrement(&nested_callback_depth);
#else
#error Unsupported object notification failure fixture mode.
#endif

    DbgPrint("OB_NOTIFY_%s FORBIDDEN_AFTER_CALLBACK\n",
        OB_NOTIFY_FAILURE_KIND);
    return OB_PREOP_SUCCESS;
}

static void ob_notify_failure_post(PVOID context,
    POB_POST_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(info);
    DbgPrint("OB_NOTIFY_%s FORBIDDEN_POST_OPERATION\n",
        OB_NOTIFY_FAILURE_KIND);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    OB_CALLBACK_REGISTRATION registration = {0};
    OB_OPERATION_REGISTRATION operation = {0};
    HANDLE process_handle = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(path);

    KeInitializeTimer(&invalid_timer);
    operation.ObjectType = PsProcessType;
    operation.Operations = OB_OPERATION_HANDLE_CREATE;
    operation.PreOperation = ob_notify_failure_pre;
    operation.PostOperation = ob_notify_failure_post;

    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.Altitude = altitude;
    registration.RegistrationContext = driver;
    registration.OperationRegistration = &operation;
    status = ObRegisterCallbacks(&registration, &registration_handle);
    if (!NT_SUCCESS(status) || !registration_handle) {
        DbgPrint("OB_NOTIFY_%s SETUP_FAILED register status=%lx\n",
            OB_NOTIFY_FAILURE_KIND, status);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    DbgPrint("OB_NOTIFY_%s PRE_OPERATION\n", OB_NOTIFY_FAILURE_KIND);
    status = ObOpenObjectByPointer(PsGetCurrentProcess(), 0, NULL,
        PROCESS_TERMINATE, *PsProcessType, KernelMode, &process_handle);
    DbgPrint("OB_NOTIFY_%s FORBIDDEN_POST_OPERATION status=%lx\n",
        OB_NOTIFY_FAILURE_KIND, status);
    return STATUS_UNSUCCESSFUL;
}
