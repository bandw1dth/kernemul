#include <ntifs.h>
#include "ob_test_access.h"

NTSYSAPI NTSTATUS NTAPI ZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

/* WHP guest fixture only; never install as a host driver. */
static LONG failures, count, sequence[12];
static PVOID registrations[3], expected_object;
static POBJECT_TYPE expected_type;
static ACCESS_MASK requested, expected_granted;
static OB_OPERATION expected_operation;
static BOOLEAN expected_kernel;

static void check(BOOLEAN ok, const char* label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}
static OB_PREOP_CALLBACK_STATUS pre(PVOID context, POB_PRE_OPERATION_INFORMATION info)
{
    ULONG id = (ULONG)(ULONG_PTR)context;
    ACCESS_MASK *desired, original;
    check(KeGetCurrentIrql() == PASSIVE_LEVEL && KeAreApcsDisabled() && !KeAreAllApcsDisabled(), "pre-passive-normal-apcs-disabled");
    check(info->Object == expected_object && info->ObjectType == expected_type, "pre-object-type");
    check(info->Operation == expected_operation && info->KernelHandle == expected_kernel, "pre-operation-kernel-flag");
    check(info->CallContext == NULL, "pre-context-initially-null");
    info->CallContext = (PVOID)(ULONG_PTR)(id + 0x100);
    if (count < 12) sequence[count++] = (LONG)id;
    if (info->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &info->Parameters->CreateHandleInformation.DesiredAccess;
        original = info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else {
        desired = &info->Parameters->DuplicateHandleInformation.DesiredAccess;
        original = info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        check(info->Parameters->DuplicateHandleInformation.SourceProcess == PsGetCurrentProcess() &&
            info->Parameters->DuplicateHandleInformation.TargetProcess == PsGetCurrentProcess(), "duplicate-source-target-process");
    }
    check(original == requested, "original-access-preserved");
    if (expected_type == *PsProcessType) {
        if (id == 3) *desired &= ~(PROCESS_TERMINATE | PROCESS_VM_READ);
        if (id == 2) {
            check(!(*desired & PROCESS_TERMINATE) && (*desired & PROCESS_VM_READ), "process-only-modifiable-rights-removed");
            *desired |= PROCESS_TERMINATE | PROCESS_CREATE_THREAD;
        }
        if (id == 1) {
            check(!(*desired & (PROCESS_TERMINATE | PROCESS_CREATE_THREAD)), "process-rights-cannot-be-added-back");
            *desired &= ~PROCESS_VM_WRITE;
        }
    } else {
        if (id == 3) *desired &= ~(THREAD_TERMINATE | THREAD_QUERY_INFORMATION);
        if (id == 2) {
            check(!(*desired & THREAD_TERMINATE) && (*desired & THREAD_QUERY_INFORMATION), "thread-only-modifiable-rights-removed");
            *desired |= THREAD_TERMINATE | THREAD_IMPERSONATE;
        }
        if (id == 1) {
            check(!(*desired & (THREAD_TERMINATE | THREAD_IMPERSONATE)), "thread-rights-cannot-be-added-back");
            *desired &= ~THREAD_SET_CONTEXT;
        }
    }
    return OB_PREOP_SUCCESS;
}
static void post(PVOID context, POB_POST_OPERATION_INFORMATION info)
{
    ULONG id = (ULONG)(ULONG_PTR)context;
    check(KeGetCurrentIrql() == PASSIVE_LEVEL && KeAreApcsDisabled() && !KeAreAllApcsDisabled(), "post-passive-normal-apcs-disabled");
    check(info->Object == expected_object && info->ObjectType == expected_type && info->Operation == expected_operation && info->KernelHandle == expected_kernel, "post-identity");
    check(info->CallContext == (PVOID)(ULONG_PTR)(id + 0x100), "matching-pre-post-context");
    check(NT_SUCCESS(info->ReturnStatus) && info->Parameters != NULL, "post-success-parameters");
    if (NT_SUCCESS(info->ReturnStatus) && info->Parameters)
        check(info->Parameters->CreateHandleInformation.GrantedAccess == expected_granted, "post-final-granted-access");
    if (count < 12) sequence[count++] = -(LONG)id;
}
static void prepare(PVOID object, POBJECT_TYPE type, OB_OPERATION operation, ACCESS_MASK access, ACCESS_MASK granted, BOOLEAN kernel)
{
    expected_object = object; expected_type = type; expected_operation = operation;
    requested = access; expected_granted = granted; expected_kernel = kernel; count = 0;
}
static void verify(HANDLE handle, ACCESS_MASK denied)
{
    PVOID object = NULL;
    OBJECT_HANDLE_INFORMATION information;
    NTSTATUS status;
    check(count == 6 && sequence[0] == 3 && sequence[1] == 2 && sequence[2] == 1 && sequence[3] == -1 && sequence[4] == -2 && sequence[5] == -3, "numeric-altitude-pre-post-order");
    check(!KeAreApcsDisabled(), "caller-apc-context-restored");
    status = ObReferenceObjectByHandle(handle, expected_granted, expected_type, KernelMode, &object, &information);
    check(NT_SUCCESS(status) && object == expected_object && information.GrantedAccess == expected_granted, "handle-stores-final-rights");
    if (NT_SUCCESS(status)) ObDereferenceObject(object);
    if (!expected_kernel) {
        status = ObReferenceObjectByHandle(handle, denied, expected_type, UserMode, &object, NULL);
        check(status == STATUS_ACCESS_DENIED, "removed-right-denied-to-user-reference");
        if (NT_SUCCESS(status)) ObDereferenceObject(object);
        status = ObReferenceObjectByHandle(handle, expected_granted, expected_type, UserMode, &object, NULL);
        check(NT_SUCCESS(status), "retained-right-usable-by-user-reference");
        if (NT_SUCCESS(status)) ObDereferenceObject(object);
    } else {
        status = ObReferenceObjectByHandle(handle, 0, expected_type, UserMode, &object, NULL);
        check(status == STATUS_INVALID_HANDLE, "kernel-handle-unavailable-to-user-reference");
        if (NT_SUCCESS(status)) ObDereferenceObject(object);
    }
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    OB_CALLBACK_REGISTRATION reg = {0};
    OB_OPERATION_REGISTRATION ops[2] = {0};
    PCWSTR altitudes[3] = {L"9.9", L"100.1", L"10.2"};
    ULONG ids[3] = {1, 3, 2}, i;
    HANDLE handle = NULL, duplicate = NULL;
    NTSTATUS status;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES attributes;
    ACCESS_MASK process_access = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    ACCESS_MASK process_granted = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    ACCESS_MASK thread_access = THREAD_TERMINATE | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    ops[0].ObjectType = PsProcessType; ops[1].ObjectType = PsThreadType;
    for (i = 0; i < 2; ++i) { ops[i].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE; ops[i].PreOperation = pre; ops[i].PostOperation = post; }
    reg.Version = OB_FLT_REGISTRATION_VERSION; reg.OperationRegistrationCount = 2; reg.OperationRegistration = ops;
    for (i = 0; i < 3; ++i) {
        RtlInitUnicodeString(&reg.Altitude, altitudes[i]); reg.RegistrationContext = (PVOID)(ULONG_PTR)ids[i];
        status = ObRegisterCallbacks(&reg, &registrations[i]);
        check(NT_SUCCESS(status), "register-ob-filter");
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    prepare(PsGetCurrentProcess(), *PsProcessType, OB_OPERATION_HANDLE_CREATE, process_access, process_granted, FALSE);
    status = ObOpenObjectByPointer(expected_object, 0, NULL, requested, expected_type, KernelMode, &handle);
    check(NT_SUCCESS(status) && handle, "open-process-object");
    if (NT_SUCCESS(status) && handle) {
        verify(handle, PROCESS_TERMINATE);
        prepare(expected_object, expected_type, OB_OPERATION_HANDLE_DUPLICATE, process_granted, process_granted, FALSE);
        status = ZwDuplicateObject(NtCurrentProcess(), handle, NtCurrentProcess(), &duplicate, 0, 0, DUPLICATE_SAME_ACCESS);
        check(NT_SUCCESS(status) && duplicate, "duplicate-filtered-process-handle");
        if (NT_SUCCESS(status) && duplicate) { verify(duplicate, PROCESS_VM_WRITE); ZwClose(duplicate); }
        ZwClose(handle); handle = NULL;
    }
    prepare(PsGetCurrentThread(), *PsThreadType, OB_OPERATION_HANDLE_CREATE, thread_access, THREAD_QUERY_INFORMATION, FALSE);
    InitializeObjectAttributes(&attributes, NULL, 0, NULL, NULL);
    cid.UniqueProcess = PsGetCurrentProcessId(); cid.UniqueThread = PsGetCurrentThreadId();
    status = ZwOpenThread(&handle, requested, &attributes, &cid);
    check(NT_SUCCESS(status) && handle, "open-thread-by-client-id");
    if (NT_SUCCESS(status) && handle) { verify(handle, THREAD_SET_CONTEXT); ZwClose(handle); handle = NULL; }
    prepare(PsGetCurrentProcess(), *PsProcessType, OB_OPERATION_HANDLE_CREATE, process_access, process_granted, TRUE);
    status = ObOpenObjectByPointer(expected_object, OBJ_KERNEL_HANDLE, NULL, requested, expected_type, KernelMode, &handle);
    check(NT_SUCCESS(status) && handle, "kernel-handle-also-filtered");
    if (NT_SUCCESS(status) && handle) {
        verify(handle, PROCESS_TERMINATE);
        prepare(expected_object, expected_type, OB_OPERATION_HANDLE_DUPLICATE, process_granted, process_granted, TRUE);
        duplicate = NULL;
        status = ZwDuplicateObject(NtCurrentProcess(), handle, NtCurrentProcess(), &duplicate, 0, 0,
            DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
        check(NT_SUCCESS(status) && duplicate, "duplicate-preserves-kernel-handle-attributes");
        if (NT_SUCCESS(status) && duplicate) { verify(duplicate, PROCESS_TERMINATE); ZwClose(duplicate); }
        ZwClose(handle);
    }
cleanup:
    for (i = 0; i < 3; ++i) if (registrations[i]) ObUnRegisterCallbacks(registrations[i]);
    count = 0; handle = NULL;
    status = ObOpenObjectByPointer(PsGetCurrentProcess(), 0, NULL, process_access, *PsProcessType, KernelMode, &handle);
    check(NT_SUCCESS(status) && count == 0, "removed-filters-no-longer-called");
    if (NT_SUCCESS(status) && handle) ZwClose(handle);
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
