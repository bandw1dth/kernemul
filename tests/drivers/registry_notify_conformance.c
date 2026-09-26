#include <ntifs.h>
C_ASSERT((ULONG)STATUS_CALLBACK_BYPASS == 0xC0000503UL);

/* Runs only inside the emulator. */
enum { NORMAL, VETO, BYPASS, POST_OVERRIDE, POST_IGNORE, QUERY_EDIT,
       QUERY_BYPASS, NESTED_PRE, NESTED_POST };
static LONG failures;
static HANDLE key, initiating_thread;
static UNICODE_STRING value_name;
static ULONG mode, depth, event_count, events[64], bad_payload;
static PVOID pre_information[3][2];
static NTSTATUS post_status[3];
static const ULONG normal_order[] = {10,11,12,22,21,20};
static const ULONG stopped_order[] = {10,11,20};
static const ULONG nested_pre_order[] = {10,111,112,122,121,11,12,22,21,20};
static const ULONG nested_post_order[] = {10,11,12,22,21,20,111,112,122,121};

static void check(BOOLEAN ok, const char* label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}
static void reset(ULONG next_mode)
{
    mode = next_mode; depth = 0; event_count = 0; bad_payload = 0;
    RtlZeroMemory(pre_information, sizeof(pre_information));
    RtlZeroMemory(post_status, sizeof(post_status));
}
static void order(const ULONG* expected, ULONG count, const char* label)
{
    ULONG i;
    BOOLEAN same = event_count == count;
    for (i = 0; same && i < count; ++i) same = events[i] == expected[i];
    check(same, label);
    check(!bad_payload, "callback-payload-context-and-thread-valid");
}
static NTSTATUS query(HANDLE handle, PUNICODE_STRING name, PULONG value)
{
    UCHAR bytes[80];
    ULONG length = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)bytes;
    NTSTATUS status = ZwQueryValueKey(handle, name, KeyValuePartialInformation, bytes, sizeof(bytes), &length);
    if (NT_SUCCESS(status)) {
        if (length < FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)
            || info->Type != REG_DWORD || info->DataLength != sizeof(ULONG)) return STATUS_UNSUCCESSFUL;
        *value = *(UNALIGNED ULONG*)info->Data;
    }
    return status;
}
static void fill_query(PREG_QUERY_VALUE_KEY_INFORMATION info, ULONG value)
{
    PKEY_VALUE_PARTIAL_INFORMATION output = (PKEY_VALUE_PARTIAL_INFORMATION)info->KeyValueInformation;
    if (info->KeyValueInformationClass != KeyValuePartialInformation || info->Length < 16) {
        ++bad_payload; return;
    }
    output->TitleIndex = 0; output->Type = REG_DWORD; output->DataLength = sizeof(ULONG);
    *(UNALIGNED ULONG*)output->Data = value;
    *info->ResultLength = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG);
}
static NTSTATUS callback(PVOID context, PVOID argument1, PVOID argument2)
{
    ULONG id = (ULONG)(ULONG_PTR)context;
    REG_NOTIFY_CLASS kind = (REG_NOTIFY_CLASS)(ULONG_PTR)argument1;
    BOOLEAN pre = kind == RegNtPreSetValueKey || kind == RegNtPreQueryValueKey || kind == RegNtPreDeleteValueKey;
    BOOLEAN post = kind == RegNtPostSetValueKey || kind == RegNtPostQueryValueKey || kind == RegNtPostDeleteValueKey;
    PVOID* call_context = NULL;
    PVOID object = NULL;
    if (!pre && !post) return STATUS_SUCCESS;
    if (id >= 3 || depth > 1) { ++bad_payload; return STATUS_SUCCESS; }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || PsGetCurrentThreadId() != initiating_thread) ++bad_payload;
    if (event_count < RTL_NUMBER_OF(events)) events[event_count++] = depth * 100 + (pre ? 10 : 20) + id;
    else ++bad_payload;
    if (pre) {
        if (kind == RegNtPreSetValueKey) {
            PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)argument2;
            object = info->Object; call_context = &info->CallContext;
        } else if (kind == RegNtPreQueryValueKey) {
            PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)argument2;
            object = info->Object; call_context = &info->CallContext;
        } else {
            PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)argument2;
            object = info->Object; call_context = &info->CallContext;
        }
        if (!object || *call_context) ++bad_payload;
        pre_information[id][depth] = argument2;
        *call_context = (PVOID)(ULONG_PTR)(0xA000 + id * 0x100 + depth);
        if (!depth && id == 0 && mode == NESTED_PRE && kind == RegNtPreQueryValueKey) {
            ULONG value = 77;
            NTSTATUS status;
            depth = 1;
            status = ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value));
            depth = 0;
            if (!NT_SUCCESS(status)) ++bad_payload;
        }
        if (!depth && id == 1) {
            if (mode == VETO) return STATUS_ACCESS_DENIED;
            if (mode == BYPASS) return STATUS_CALLBACK_BYPASS;
            if (mode == QUERY_BYPASS && kind == RegNtPreQueryValueKey) {
                fill_query((PREG_QUERY_VALUE_KEY_INFORMATION)argument2, 88);
                return STATUS_CALLBACK_BYPASS;
            }
        }
    } else {
        PREG_POST_OPERATION_INFORMATION info = (PREG_POST_OPERATION_INFORMATION)argument2;
        if (!info->Object || info->PreInformation != pre_information[id][depth]
            || info->CallContext != (PVOID)(ULONG_PTR)(0xA000 + id * 0x100 + depth)) ++bad_payload;
        if (!depth) post_status[id] = info->Status;
        if (!depth && id == 2 && mode == QUERY_EDIT && kind == RegNtPostQueryValueKey)
            fill_query((PREG_QUERY_VALUE_KEY_INFORMATION)info->PreInformation, 100);
        if (!depth && id == 1 && (mode == POST_OVERRIDE || mode == POST_IGNORE)) {
            info->ReturnStatus = STATUS_ACCESS_DENIED;
            return mode == POST_OVERRIDE ? STATUS_CALLBACK_BYPASS : STATUS_SUCCESS;
        }
        if (!depth && id == 0 && mode == NESTED_POST && kind == RegNtPostSetValueKey) {
            ULONG value = 0;
            NTSTATUS status;
            depth = 1; status = query(key, &value_name, &value); depth = 0;
            if (!NT_SUCCESS(status) || value != 42) ++bad_payload;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNICODE_STRING key_name, altitude, missing;
    PCWSTR altitudes[] = {L"100.1", L"10.2", L"9.9"};
    OBJECT_ATTRIBUTES attributes;
    LARGE_INTEGER cookies[3];
    ULONG registered = 0, i, value, result_length;
    UCHAR output[128];
    NTSTATUS status;
    UNREFERENCED_PARAMETER(path);
    initiating_thread = PsGetCurrentThreadId();
    RtlInitUnicodeString(&key_name, L"\\Registry\\Machine\\Software\\KernemulRegistryNotifyTest");
    RtlInitUnicodeString(&value_name, L"Value");
    RtlInitUnicodeString(&missing, L"Missing");
    InitializeObjectAttributes(&attributes, &key_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateKey(&key, KEY_ALL_ACCESS, &attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    check(NT_SUCCESS(status) && key, "create-notification-key");
    if (!NT_SUCCESS(status) || !key) goto cleanup;
    /* Registration order is deliberately unrelated to numeric altitude. */
    for (i = 0; i < 3; ++i) {
        ULONG id = (i + 1) % 3;
        RtlInitUnicodeString(&altitude, altitudes[id]);
        status = CmRegisterCallbackEx(callback, &altitude, driver, (PVOID)(ULONG_PTR)id, &cookies[id], NULL);
        check(NT_SUCCESS(status), "register-layered-filter");
        if (!NT_SUCCESS(status)) goto cleanup;
        registered |= 1u << id;
    }
    reset(NORMAL); value = 17;
    status = ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value));
    check(NT_SUCCESS(status), "set-value-succeeds"); order(normal_order, 6, "numeric-pre-and-reverse-post-order");
    reset(NORMAL); value = 0;
    check(NT_SUCCESS(query(key, &value_name, &value)) && value == 17, "query-observes-set-value");
    order(normal_order, 6, "query-paired-notifications");
    reset(VETO); value = 99;
    check(ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value)) == STATUS_ACCESS_DENIED, "pre-veto-status");
    order(stopped_order, 3, "veto-unwinds-only-higher-filter");
    check(post_status[0] == STATUS_ACCESS_DENIED, "veto-status-reaches-higher-post");
    reset(NORMAL); check(NT_SUCCESS(query(key, &value_name, &value)) && value == 17, "veto-prevents-write");
    reset(BYPASS); value = 99;
    check(NT_SUCCESS(ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value))), "pre-bypass-returns-success");
    order(stopped_order, 3, "bypass-unwinds-only-higher-filter");
    reset(NORMAL); check(NT_SUCCESS(query(key, &value_name, &value)) && value == 17, "bypass-skips-store-write");
    reset(POST_OVERRIDE); value = 31;
    check(ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value)) == STATUS_ACCESS_DENIED, "post-bypass-overrides-status");
    order(normal_order, 6, "post-override-unwinds-all-filters");
    check(post_status[2] == STATUS_SUCCESS && post_status[0] == STATUS_ACCESS_DENIED, "post-status-propagates-upward");
    reset(NORMAL); check(NT_SUCCESS(query(key, &value_name, &value)) && value == 31, "post-error-does-not-rollback-write");
    reset(POST_IGNORE); value = 32;
    check(NT_SUCCESS(ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value))), "post-returnstatus-ignored-without-bypass");
    order(normal_order, 6, "ordinary-post-return-continues");
    reset(QUERY_EDIT); check(NT_SUCCESS(query(key, &value_name, &value)) && value == 100, "query-post-can-edit-output");
    order(normal_order, 6, "query-output-edit-unwinds");
    reset(NORMAL); check(NT_SUCCESS(query(key, &value_name, &value)) && value == 32, "query-output-edit-does-not-change-store");
    reset(QUERY_BYPASS); check(NT_SUCCESS(query(key, &missing, &value)) && value == 88, "query-pre-bypass-supplies-output");
    order(stopped_order, 3, "query-bypass-higher-post-only");
    reset(NORMAL); check(query(key, &missing, &value) == STATUS_OBJECT_NAME_NOT_FOUND, "missing-query-fails");
    order(normal_order, 6, "failed-body-still-delivers-post");
    check(post_status[0] == STATUS_OBJECT_NAME_NOT_FOUND, "failed-query-post-status");
    reset(NORMAL); result_length = 0;
    status = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation, output, 1, &result_length);
    check((status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) && result_length >= 16, "short-query-buffer-reports-required-size");
    order(normal_order, 6, "short-query-buffer-still-paired");
    for (i = 0; i < 2; ++i) {
        reset(NORMAL);
        check(NT_SUCCESS(ZwQueryValueKey(key, &value_name, (KEY_VALUE_INFORMATION_CLASS)i, output, sizeof(output), &result_length)), "query-basic-or-full-information");
        order(normal_order, 6, "query-information-class-paired");
    }
    reset(NESTED_PRE); check(NT_SUCCESS(query(key, &value_name, &value)) && value == 77, "outer-query-sees-nested-pre-write");
    order(nested_pre_order, 10, "nested-pre-delivered-below-invoking-altitude");
    reset(NESTED_POST); value = 42;
    check(NT_SUCCESS(ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value))), "nested-post-query-succeeds");
    order(nested_post_order, 10, "nested-post-delivered-below-invoking-altitude");
    reset(VETO); check(ZwDeleteValueKey(key, &value_name) == STATUS_ACCESS_DENIED, "delete-veto-status");
    order(stopped_order, 3, "delete-veto-unwinds-higher");
    reset(NORMAL); check(NT_SUCCESS(query(key, &value_name, &value)) && value == 42, "delete-veto-preserves-value");
    reset(NORMAL); check(NT_SUCCESS(ZwDeleteValueKey(key, &value_name)), "delete-value-succeeds");
    order(normal_order, 6, "delete-paired-notifications");
    reset(NORMAL); check(query(key, &value_name, &value) == STATUS_OBJECT_NAME_NOT_FOUND, "delete-removes-value");
cleanup:
    for (i = 0; i < 3; ++i) if (registered & (1u << i)) check(CmUnRegisterCallback(cookies[i]) == STATUS_SUCCESS, "unregister-layered-filter");
    if (key) {
        reset(NORMAL); value = 5;
        check(NT_SUCCESS(ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value))) && !event_count, "unregistered-filters-no-longer-called");
        ZwClose(key);
    }
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
