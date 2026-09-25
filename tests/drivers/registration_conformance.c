#include <ntddk.h>

static LONG failures;
static void check(BOOLEAN ok, const char* name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}
static NTSTATUS registry_callback(PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(arg1); UNREFERENCED_PARAMETER(arg2);
    return STATUS_SUCCESS;
}
static OB_PREOP_CALLBACK_STATUS object_pre(PVOID context, POB_PRE_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(info);
    return OB_PREOP_SUCCESS;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    UNICODE_STRING altitude;
    LARGE_INTEGER first, duplicate, next;
    OB_CALLBACK_REGISTRATION registration = {0};
    OB_OPERATION_REGISTRATION operation = {0};
    PVOID handle = NULL, other = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registry);
    RtlInitUnicodeString(&altitude, L"398765.42");
    status = CmRegisterCallbackEx(registry_callback, &altitude, driver, (PVOID)0x1234, &first, NULL);
    check(NT_SUCCESS(status), "cm-register");
    if (NT_SUCCESS(status)) {
        status = CmRegisterCallbackEx(registry_callback, &altitude, driver, NULL, &duplicate, NULL);
        check(status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION, "cm-altitude-collision");
        check(CmUnRegisterCallback(first) == STATUS_SUCCESS, "cm-unregister");
        check(!NT_SUCCESS(CmUnRegisterCallback(first)), "cm-invalid-cookie-rejected");
        status = CmRegisterCallbackEx(registry_callback, &altitude, driver, NULL, &next, NULL);
        check(NT_SUCCESS(status) && next.QuadPart != first.QuadPart, "cm-altitude-reusable-new-cookie");
        if (NT_SUCCESS(status)) CmUnRegisterCallback(next);
    }

    operation.ObjectType = PsProcessType;
    operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation.PreOperation = object_pre;
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.Altitude = altitude;
    registration.RegistrationContext = (PVOID)0x5678;
    registration.OperationRegistration = &operation;
    status = ObRegisterCallbacks(&registration, &handle);
    check(NT_SUCCESS(status) && handle, "ob-register");
    if (NT_SUCCESS(status) && handle) {
        status = ObRegisterCallbacks(&registration, &other);
        check(status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION, "ob-altitude-collision");
        ObUnRegisterCallbacks(handle);
        status = ObRegisterCallbacks(&registration, &other);
        check(NT_SUCCESS(status) && other && other != handle, "ob-altitude-reusable-new-handle");
        if (NT_SUCCESS(status) && other) ObUnRegisterCallbacks(other);
    }
    registration.Version = 0;
    check(!NT_SUCCESS(ObRegisterCallbacks(&registration, &other)), "ob-invalid-version-rejected");
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
