#include <ntddk.h>

static LONG failures, calls, bad_args;
static LONG order[16];
static KIRQL expected_irql;

static void check(BOOLEAN ok, const char* name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

static void notify(PVOID context, PVOID arg1, PVOID arg2)
{
    if (arg1 != (PVOID)0x1234 || arg2 != (PVOID)0x5678 || KeGetCurrentIrql() != expected_irql)
        ++bad_args;
    if (calls < 16) order[calls] = (LONG)(LONG_PTR)context;
    ++calls;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    PCALLBACK_OBJECT object = NULL, reopened = NULL, single = NULL;
    PVOID first, second, duplicate, only;
    NTSTATUS status;
    KIRQL old_irql;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);

    RtlInitUnicodeString(&name, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ExCreateCallback(&reopened, &attributes, FALSE, TRUE);
    check(NT_SUCCESS(status) && reopened, "system-power-callback-preexists");
    if (NT_SUCCESS(status) && reopened) ObDereferenceObject(reopened);
    reopened = NULL;
    RtlInitUnicodeString(&name, L"\\Callback\\SetSystemTime");
    status = ExCreateCallback(&reopened, &attributes, FALSE, TRUE);
    check(NT_SUCCESS(status) && reopened, "system-time-callback-preexists");
    if (NT_SUCCESS(status) && reopened) ObDereferenceObject(reopened);
    reopened = NULL;
    attributes.ObjectName = NULL;
    check(ExCreateCallback(&object, &attributes, TRUE, TRUE) == STATUS_UNSUCCESSFUL,
        "unnamed-callback-rejected");

    RtlInitUnicodeString(&name, L"\\Callback\\KernemulConformanceAbsent");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ExCreateCallback(&object, &attributes, FALSE, TRUE);
    check(!NT_SUCCESS(status), "open-missing-does-not-create");
    status = ExCreateCallback(&object, &attributes, TRUE, TRUE);
    check(NT_SUCCESS(status) && object != NULL, "create-callback");
    if (!NT_SUCCESS(status) || !object) return STATUS_UNSUCCESSFUL;
    status = ExCreateCallback(&reopened, &attributes, FALSE, TRUE);
    check(NT_SUCCESS(status) && reopened == object, "open-existing-identity");

    first = ExRegisterCallback(object, notify, (PVOID)1);
    second = ExRegisterCallback(object, notify, (PVOID)2);
    duplicate = ExRegisterCallback(object, notify, (PVOID)1);
    check(first && second && duplicate && first != duplicate, "distinct-registration-identities");
    expected_irql = PASSIVE_LEVEL;
    ExNotifyCallback(object, (PVOID)0x1234, (PVOID)0x5678);
    check(calls == 3 && order[0] == 1 && order[1] == 2 && order[2] == 1 && !bad_args,
        "synchronous-registration-order-and-arguments");
    if (first) ExUnregisterCallback(first);
    calls = 0;
    ExNotifyCallback(object, (PVOID)0x1234, (PVOID)0x5678);
    check(calls == 2 && order[0] == 2 && order[1] == 1, "remove-exact-duplicate-registration");
    if (duplicate) ExUnregisterCallback(duplicate);
    calls = 0;
    expected_irql = DISPATCH_LEVEL;
    KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
    ExNotifyCallback(object, (PVOID)0x1234, (PVOID)0x5678);
    KeLowerIrql(old_irql);
    check(calls == 1 && order[0] == 2 && !bad_args, "notification-preserves-caller-irql");
    if (second) ExUnregisterCallback(second);
    calls = 0;
    expected_irql = PASSIVE_LEVEL;
    ExNotifyCallback(object, (PVOID)0x1234, (PVOID)0x5678);
    check(calls == 0, "removed-callbacks-not-delivered");

    RtlInitUnicodeString(&name, L"\\Callback\\KernemulConformanceSingle");
    status = ExCreateCallback(&single, &attributes, TRUE, FALSE);
    check(NT_SUCCESS(status) && single, "create-single-callback-object");
    if (NT_SUCCESS(status) && single) {
        only = ExRegisterCallback(single, notify, (PVOID)1);
        check(only && !ExRegisterCallback(single, notify, (PVOID)2), "single-registration-enforced");
        if (only) ExUnregisterCallback(only);
        only = ExRegisterCallback(single, notify, (PVOID)2);
        check(only != NULL, "register-after-unregister");
        if (only) ExUnregisterCallback(only);
        ObDereferenceObject(single);
    }
    if (reopened) ObDereferenceObject(reopened);
    ObDereferenceObject(object);
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
