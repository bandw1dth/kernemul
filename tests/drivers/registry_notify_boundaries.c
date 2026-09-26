#include <ntifs.h>

/* Emulator conformance fixture; never install on the host. */
static LONG failures, pre_count, post_count;
static ULONG mode;
static HANDLE closing_handle;
static PVOID operation_object;

static void check(BOOLEAN ok, const char* label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}

static NTSTATUS callback(PVOID context, PVOID argument1, PVOID argument2)
{
    REG_NOTIFY_CLASS kind = (REG_NOTIFY_CLASS)(ULONG_PTR)argument1;
    UNREFERENCED_PARAMETER(context);
    if (kind == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)argument2;
        ++pre_count;
        if (mode == 1) info->Type = REG_QWORD;
        if (mode == 2) {
            operation_object = info->Object;
            check(operation_object != NULL, "closing-handle-pre-has-key-object");
            check(NT_SUCCESS(ZwClose(closing_handle)), "callback-can-close-initiating-handle");
            closing_handle = NULL;
        }
    } else if (kind == RegNtPostSetValueKey) {
        PREG_POST_OPERATION_INFORMATION info = (PREG_POST_OPERATION_INFORMATION)argument2;
        ++post_count;
        if (mode == 2) {
            NTSTATUS status = ObReferenceObjectByPointer(info->Object, 0, NULL, KernelMode);
            check(info->Object == operation_object && NT_SUCCESS(status), "operation-retains-key-through-post");
            if (NT_SUCCESS(status)) ObDereferenceObject(info->Object);
        }
    }
    return STATUS_SUCCESS;
}

static BOOLEAN value_is(HANDLE key, PUNICODE_STRING name, ULONG expected)
{
    UCHAR buffer[64];
    ULONG length = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    NTSTATUS status = ZwQueryValueKey(key, name, KeyValuePartialInformation, buffer, sizeof(buffer), &length);
    return NT_SUCCESS(status) && info->Type == REG_DWORD && info->DataLength == sizeof(ULONG)
        && *(UNALIGNED ULONG*)info->Data == expected;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNICODE_STRING key_name, value_name, altitude;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key = NULL, reopened = NULL;
    LARGE_INTEGER cookie = {0}, bad_cookie;
    ULONG value = 17;
    NTSTATUS status;
    BOOLEAN registered = FALSE;
    LONG before;
    UNREFERENCED_PARAMETER(path);
    RtlInitUnicodeString(&key_name, L"\\Registry\\Machine\\Software\\KernemulRegistryBoundary");
    RtlInitUnicodeString(&value_name, L"Value");
    RtlInitUnicodeString(&altitude, L"398764.33");
    InitializeObjectAttributes(&attributes, &key_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateKey(&key, KEY_ALL_ACCESS, &attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    check(NT_SUCCESS(status) && key, "create-boundary-key");
    if (!NT_SUCCESS(status) || !key) goto cleanup;
    check(NT_SUCCESS(ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value))), "seed-boundary-value");
    status = CmRegisterCallbackEx(callback, &altitude, driver, NULL, &cookie, NULL);
    registered = NT_SUCCESS(status);
    check(registered, "register-boundary-filter");
    if (!registered) goto cleanup;

    before = pre_count;
    status = ZwSetValueKey((HANDLE)(ULONG_PTR)0x12345678, &value_name, 0, REG_DWORD, &value, sizeof(value));
    check(status == STATUS_INVALID_HANDLE && pre_count == before, "invalid-key-no-callback");
    status = ZwSetValueKey(key, &value_name, 0, REG_DWORD, (PVOID)(ULONG_PTR)0xFFFFFE00BAD00000ull, sizeof(value));
    check(status == STATUS_ACCESS_VIOLATION && pre_count == before, "unmapped-data-no-callback");
    check(value_is(key, &value_name, 17), "invalid-write-preserves-value");
    bad_cookie.QuadPart = 0x123456789;
    check(CmUnRegisterCallback(bad_cookie) == STATUS_INVALID_PARAMETER, "invalid-cookie-rejected");

    mode = 1; value = 99;
    status = ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value));
    mode = 0;
    check(status == STATUS_NOT_SUPPORTED, "input-structure-redirection-explicitly-rejected");
    check(value_is(key, &value_name, 17), "rejected-input-change-does-not-mutate");

    check(NT_SUCCESS(ZwOpenKey(&reopened, KEY_ALL_ACCESS, &attributes)) && reopened, "open-second-key-handle");
    if (reopened) {
        mode = 2; closing_handle = key; value = 42;
        before = post_count;
        status = ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value));
        key = closing_handle; mode = 0;
        check(NT_SUCCESS(status) && post_count == before + 1, "operation-finishes-after-handle-close");
        check(value_is(reopened, &value_name, 42), "closed-handle-operation-reaches-store");
    }

cleanup:
    if (registered) {
        check(CmUnRegisterCallback(cookie) == STATUS_SUCCESS, "boundary-filter-unregisters");
        check(CmUnRegisterCallback(cookie) == STATUS_INVALID_PARAMETER, "removed-cookie-stays-invalid");
    }
    if (reopened) ZwClose(reopened);
    if (key) ZwClose(key);
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
