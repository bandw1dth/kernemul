#include <ntifs.h>
#include "ob_test_access.h"

/* WHP-only fixture. Includes intentionally unmapped guest addresses. */
static LONG failures, pre_count, post_count, child_count, thread_creates, thread_exits;
static PVOID cookie;
static void check(BOOLEAN ok, const char* label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}
static OB_PREOP_CALLBACK_STATUS pre(PVOID context, POB_PRE_OPERATION_INFORMATION info)
{
    ++pre_count;
    check(context == (PVOID)0x789 && info->ObjectType == *PsThreadType && info->Operation == OB_OPERATION_HANDLE_CREATE, "copied-registration-and-operation-match");
    info->CallContext = (PVOID)0x456;
    info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
    return OB_PREOP_SUCCESS;
}
static void post(PVOID context, POB_POST_OPERATION_INFORMATION info)
{
    ++post_count;
    check(context == (PVOID)0x789 && info->CallContext == (PVOID)0x456, "copied-post-context");
    check(NT_SUCCESS(info->ReturnStatus) && info->Parameters && !(info->Parameters->CreateHandleInformation.GrantedAccess & THREAD_TERMINATE), "thread-create-reduced-grant");
}
static void only_post(PVOID context, POB_POST_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(context);
    ++post_count;
    check(info->CallContext == NULL && NT_SUCCESS(info->ReturnStatus) && info->ObjectType == *PsProcessType, "post-only-filter-null-context");
}
static void child(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    InterlockedIncrement(&child_count);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
static void thread_notify(HANDLE process, HANDLE thread, BOOLEAN create)
{
    UNREFERENCED_PARAMETER(process); UNREFERENCED_PARAMETER(thread);
    if (create) ++thread_creates; else ++thread_exits;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    OB_CALLBACK_REGISTRATION reg = {0};
    OB_OPERATION_REGISTRATION op = {0};
    PVOID other = NULL, object = NULL;
    HANDLE handle = NULL, duplicate = NULL;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    LONG before;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING file_name;
    IO_STATUS_BLOCK io;
    BOOLEAN thread_registered = FALSE;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    reg.Version = OB_FLT_REGISTRATION_VERSION; reg.OperationRegistrationCount = 1; reg.OperationRegistration = &op;
    reg.RegistrationContext = (PVOID)0x789;
    RtlInitUnicodeString(&reg.Altitude, L"120.50");
    op.ObjectType = PsThreadType; op.Operations = OB_OPERATION_HANDLE_CREATE; op.PreOperation = pre; op.PostOperation = post;
    status = ObRegisterCallbacks(&reg, (PVOID*)(ULONG_PTR)0xFFFFFE00BAD00000ull);
    check(status == STATUS_ACCESS_VIOLATION, "bad-registration-output-rejected");
    status = ObRegisterCallbacks(&reg, &cookie);
    check(NT_SUCCESS(status) && cookie, "registration-output-failure-rolled-back");
    if (!NT_SUCCESS(status)) goto done;
    RtlInitUnicodeString(&reg.Altitude, L"00120.5000");
    check(ObRegisterCallbacks(&reg, &other) == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION, "numeric-equivalent-altitude-collision");
    /* Registration owns its descriptors, not these caller-owned buffers. */
    op.ObjectType = PsProcessType; op.Operations = OB_OPERATION_HANDLE_DUPLICATE; op.PreOperation = NULL; op.PostOperation = NULL;
    reg.RegistrationContext = NULL;
    status = ObOpenObjectByPointer(PsGetCurrentProcess(), 0, NULL, PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &handle);
    check(NT_SUCCESS(status) && pre_count == 0 && post_count == 0, "nonmatching-type-not-notified");
    if (NT_SUCCESS(status) && handle) ZwClose(handle);
    handle = NULL;
    status = ObOpenObjectByPointer(PsGetCurrentThread(), 0, NULL, THREAD_TERMINATE | THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, &handle);
    check(NT_SUCCESS(status) && handle && pre_count == 1 && post_count == 1, "copied-thread-registration-delivered");
    if (NT_SUCCESS(status) && handle) {
        status = ObReferenceObjectByHandle(handle, 0, *PsProcessType, KernelMode, &object, NULL);
        check(status == STATUS_OBJECT_TYPE_MISMATCH, "reference-rejects-wrong-object-type");
        if (NT_SUCCESS(status)) ObDereferenceObject(object);
        status = ZwDuplicateObject(NtCurrentProcess(), handle, NtCurrentProcess(), &duplicate, 0, 0, DUPLICATE_SAME_ACCESS);
        check(NT_SUCCESS(status) && pre_count == 1 && post_count == 1, "nonmatching-operation-not-notified");
        if (NT_SUCCESS(status) && duplicate) ZwClose(duplicate);
        duplicate = NULL;
        status = ZwDuplicateObject(NtCurrentProcess(), handle, NtCurrentProcess(), &duplicate, THREAD_TERMINATE, 0, 0);
        check(status == STATUS_ACCESS_DENIED && !duplicate && pre_count == 1, "duplicate-cannot-expand-source-grant");
        if (NT_SUCCESS(status) && duplicate) ZwClose(duplicate);
        ZwClose(handle);
    }
    before = pre_count;
    status = ObOpenObjectByPointer(PsGetCurrentThread(), 0, NULL, THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, (PHANDLE)(ULONG_PTR)0xFFFFFE00BAD00000ull);
    check(status == STATUS_ACCESS_VIOLATION && pre_count == before, "unmapped-output-before-callback");
    status = ObOpenObjectByPointer(PsGetCurrentThread(), 0, NULL, THREAD_QUERY_INFORMATION, *PsProcessType, KernelMode, &handle);
    check(status == STATUS_OBJECT_TYPE_MISMATCH && pre_count == before, "open-rejects-wrong-type-before-callback");
    status = ObOpenObjectByPointer((PVOID)(ULONG_PTR)0xFFFFFE00BAD00000ull, 0, NULL, 0, *PsThreadType, KernelMode, &handle);
    check(!NT_SUCCESS(status) && pre_count == before, "unknown-object-not-opened");
    status = ObOpenObjectByPointer(PsGetCurrentThread(), 0, NULL, GENERIC_READ, *PsThreadType, KernelMode, &handle);
    check(status == STATUS_NOT_SUPPORTED && pre_count == before, "generic-access-explicitly-unsupported");
    status = ObOpenObjectByPointer(PsGetCurrentThread(), 0, NULL, MAXIMUM_ALLOWED, *PsThreadType, KernelMode, &handle);
    check(status == STATUS_NOT_SUPPORTED && pre_count == before, "maximum-allowed-explicitly-unsupported");
    status = PsSetCreateThreadNotifyRoutine(thread_notify);
    thread_registered = NT_SUCCESS(status);
    check(thread_registered, "register-lifecycle-regression-observer");
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    handle = NULL;
    status = PsCreateSystemThread(&handle, GENERIC_READ, &attributes, NULL, NULL, child, NULL);
    check(status == STATUS_NOT_SUPPORTED && !handle && pre_count == before && !thread_creates && !child_count,
        "unsupported-thread-grant-does-not-publish-child");
    handle = NULL;
    status = PsCreateSystemThread(&handle, SYNCHRONIZE | THREAD_TERMINATE | THREAD_QUERY_INFORMATION, &attributes, NULL, NULL, child, NULL);
    check(NT_SUCCESS(status) && handle && pre_count == before + 1 && post_count == pre_count, "system-thread-handle-notified");
    if (NT_SUCCESS(status) && handle) {
        timeout.QuadPart = -20000000;
        check(ZwWaitForSingleObject(handle, FALSE, &timeout) == STATUS_SUCCESS && child_count == 1 && thread_creates == 1 && thread_exits == 1, "created-thread-runs-and-keeps-lifecycle-events");
        ZwClose(handle);
    }
    ObUnRegisterCallbacks(cookie); cookie = NULL;
    op.ObjectType = PsProcessType; op.Operations = OB_OPERATION_HANDLE_CREATE; op.PreOperation = NULL; op.PostOperation = only_post;
    RtlInitUnicodeString(&reg.Altitude, L"120.5");
    status = ObRegisterCallbacks(&reg, &cookie);
    check(NT_SUCCESS(status), "post-only-registration");
    if (NT_SUCCESS(status)) {
        before = post_count; handle = NULL;
        status = ObOpenObjectByPointer(PsGetCurrentProcess(), 0, NULL, 0, *PsProcessType, KernelMode, &handle);
        check(NT_SUCCESS(status) && post_count == before + 1, "post-only-delivery");
        if (NT_SUCCESS(status) && handle) ZwClose(handle);
    }
    /* Legacy file grants are not modeled yet; OB enforcement must stay scoped. */
    RtlInitUnicodeString(&file_name, L"\\??\\C:\\ob_notify_boundaries.sys");
    InitializeObjectAttributes(&attributes, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    handle = NULL;
    status = ZwOpenFile(&handle, FILE_GENERIC_READ, &attributes, &io, FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    check(NT_SUCCESS(status) && handle, "open-file-for-reference-regression");
    if (NT_SUCCESS(status) && handle) {
        status = ObReferenceObjectByHandle(handle, FILE_READ_DATA, *IoFileObjectType, UserMode, &object, NULL);
        check(NT_SUCCESS(status), "unmodeled-file-grants-not-denied-by-ob-upgrade");
        if (NT_SUCCESS(status)) ObDereferenceObject(object);
        ZwClose(handle);
    }
done:
    if (thread_registered) PsRemoveCreateThreadNotifyRoutine(thread_notify);
    if (cookie) ObUnRegisterCallbacks(cookie);
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
