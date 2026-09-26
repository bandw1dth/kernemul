#include <ntifs.h>
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

/* Emulator guest only. Registration intentionally survives DriverEntry. */
static PVOID registration, caller_thread, pending_object;
static HANDLE system_pid, caller_pid, caller_tid;
static ULONG sequence, posted;
static OB_OPERATION pending_operation;

static void check(BOOLEAN ok, const char* label)
{
    if (!ok) DbgPrint("OB_USER FAIL %s\n", label);
}

static void context_check(void)
{
    check(KeGetCurrentIrql() == PASSIVE_LEVEL && KeAreApcsDisabled() &&
        !KeAreAllApcsDisabled(), "passive-normal-apcs-disabled");
    check(PsGetCurrentProcessId() == caller_pid && caller_pid != system_pid &&
        caller_pid != NULL && caller_pid != (HANDLE)4, "non-system-process");
    check(PsGetCurrentThread() == caller_thread && PsGetCurrentThreadId() == caller_tid &&
        caller_tid != NULL, "user-caller-thread");
}

static OB_PREOP_CALLBACK_STATUS pre(PVOID context, POB_PRE_OPERATION_INFORMATION info)
{
    ACCESS_MASK *desired, original;
    if (!sequence) {
        caller_pid = PsGetCurrentProcessId();
        caller_tid = PsGetCurrentThreadId();
        caller_thread = PsGetCurrentThread();
    }
    context_check();
    check(context == &registration && info->CallContext == NULL, "pre-context");
    check(sequence == posted && sequence < 3, "pre-sequence");
    ++sequence;
    check(info->ObjectType == *PsThreadType && !info->KernelHandle, "thread-user-handle");
    check(info->Operation == (sequence == 2 ? OB_OPERATION_HANDLE_DUPLICATE : OB_OPERATION_HANDLE_CREATE), "operation");
    check(sequence == 3 ? info->Object != caller_thread : info->Object == caller_thread, "target-thread");
    if (info->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &info->Parameters->CreateHandleInformation.DesiredAccess;
        original = info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else {
        desired = &info->Parameters->DuplicateHandleInformation.DesiredAccess;
        original = info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        check(info->Parameters->DuplicateHandleInformation.SourceProcess == PsGetCurrentProcess() &&
            info->Parameters->DuplicateHandleInformation.TargetProcess == PsGetCurrentProcess(), "duplicate-processes");
    }
    check(original == (THREAD_QUERY_INFORMATION | (sequence == 2 ? 0 : THREAD_TERMINATE)) &&
        *desired == original, "requested-access");
    *desired &= ~THREAD_TERMINATE;
    pending_object = info->Object;
    pending_operation = info->Operation;
    info->CallContext = (PVOID)(ULONG_PTR)(0xB000 + sequence);
    DbgPrint("OB_USER PRE %lu pid=%p tid=%p\n", sequence, caller_pid, caller_tid);
    return OB_PREOP_SUCCESS;
}

static void post(PVOID context, POB_POST_OPERATION_INFORMATION info)
{
    ACCESS_MASK granted = 0;
    context_check();
    check(context == &registration && info->CallContext == (PVOID)(ULONG_PTR)(0xB000 + sequence), "post-context");
    check(posted + 1 == sequence, "post-sequence");
    check(info->Object == pending_object && info->ObjectType == *PsThreadType &&
        info->Operation == pending_operation && !info->KernelHandle, "post-identity");
    check(NT_SUCCESS(info->ReturnStatus) && info->Parameters != NULL, "post-status");
    if (NT_SUCCESS(info->ReturnStatus) && info->Parameters)
        granted = info->Operation == OB_OPERATION_HANDLE_CREATE ?
            info->Parameters->CreateHandleInformation.GrantedAccess :
            info->Parameters->DuplicateHandleInformation.GrantedAccess;
    check(granted == THREAD_QUERY_INFORMATION && !(granted & THREAD_TERMINATE), "filtered-grant");
    posted = sequence;
    DbgPrint("OB_USER POST %lu\n", posted);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    OB_CALLBACK_REGISTRATION reg = {0};
    OB_OPERATION_REGISTRATION op = {0};
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    system_pid = PsGetCurrentProcessId();
    op.ObjectType = PsThreadType;
    op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op.PreOperation = pre; op.PostOperation = post;
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.OperationRegistration = &op;
    reg.RegistrationContext = &registration;
    RtlInitUnicodeString(&reg.Altitude, L"321001.7");
    status = ObRegisterCallbacks(&reg, &registration);
    if (!NT_SUCCESS(status)) { DbgPrint("OB_USER FAIL register\n"); return status; }
    DbgPrint("OB_USER READY\n");
    return STATUS_SUCCESS;
}
