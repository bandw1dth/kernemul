#include <ntifs.h>

/* Guest only. Event ordering below is the emulator's lifecycle convention.
 * Registrations survive DriverEntry; only the monitor removes them. */
static volatile LONG failures, accepted_create[2], rejected_create[2], process_exit[2];
static volatile LONG classic_create, classic_exit, thread_create, thread_exit;
static volatile LONG exe_images, ntdll_images;
static HANDLE accepted_pid, rejected_pid, initial_tid, launcher_tid;
static PEPROCESS retained_process;
static BOOLEAN registered[5];
static LARGE_INTEGER registry_cookie;
static BOOLEAN registry_registered;
static volatile LONG user_registry_calls;

static void check(BOOLEAN ok, const char* label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) InterlockedIncrement(&failures);
}

static BOOLEAN valid_string(PCUNICODE_STRING value)
{
    return value && value->Buffer && value->Length &&
        !(value->Length % sizeof(WCHAR)) && value->Length <= value->MaximumLength;
}

static BOOLEAN contains(PCUNICODE_STRING value, PCWSTR text)
{
    USHORT i, j, length = 0, chars;
    if (!valid_string(value)) return FALSE;
    while (text[length]) ++length;
    chars = value->Length / sizeof(WCHAR);
    for (i = 0; i + length <= chars; ++i) {
        for (j = 0; j < length; ++j) {
            WCHAR c = value->Buffer[i + j];
            if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
            if (c != text[j]) break;
        }
        if (j == length) return TRUE;
    }
    return FALSE;
}

static void callback_context(void)
{
    check(KeGetCurrentIrql() == PASSIVE_LEVEL && KeAreApcsDisabled() &&
        !KeAreAllApcsDisabled(), "process-passive-normal-apcs-disabled-special-enabled");
}

static void lookup_visible(HANDLE pid, PEPROCESS expected)
{
    PEPROCESS found = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &found);
    check(status == STATUS_SUCCESS && found && (!expected || found == expected),
        "callback-pid-lookup-visible");
    if (NT_SUCCESS(status) && found) {
        check(PsGetProcessId(found) == pid, "lookup-process-identity");
        ObDereferenceObject(found);
    }
}

static void extended(ULONG slot, PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{
    callback_context();
    check(pid && pid != (HANDLE)4 && process && PsGetProcessId(process) == pid,
        "extended-subject-identity");
    lookup_visible(pid, process);
    if (info) {
        BOOLEAN reject = contains(info->ImageFileName, L"process_notify_reject.exe");
        check(info->Size == sizeof(*info) && info->ParentProcessId == (HANDLE)4 &&
            info->CreatingThreadId.UniqueProcess == (HANDLE)4 &&
            info->CreatingThreadId.UniqueThread == PsGetCurrentThreadId() &&
            PsGetCurrentProcessId() == (HANDLE)4 && PsGetCurrentThread() != NULL,
            "extended-system-launcher-creator-context");
        check(info->FileObject && valid_string(info->ImageFileName) &&
            valid_string(info->CommandLine), "extended-file-image-commandline-payload");
        if (info->FileObject)
            check(valid_string(&info->FileObject->FileName), "extended-file-object-name");
        if (reject) {
            if (!slot) {
                check(!rejected_pid && info->CreationStatus == STATUS_SUCCESS,
                    "reject-first-handler-initial-status");
                rejected_pid = pid;
                info->CreationStatus = STATUS_ACCESS_DENIED;
            } else {
                check(pid == rejected_pid && rejected_create[0] == 1 &&
                    info->CreationStatus == STATUS_ACCESS_DENIED, "reject-second-handler-sees-veto");
                info->CreationStatus = STATUS_SUCCESS; /* Must not undo the first veto. */
            }
            InterlockedIncrement(&rejected_create[slot]);
            DbgPrint("PROCESS_NOTIFY REJECT_EX%lu\n", slot + 1);
        } else {
            check(contains(info->ImageFileName, L"process_notify_user.exe") &&
                contains(info->CommandLine, L"process_notify_user.exe"), "accepted-image-commandline");
            if (!slot) {
                check(!accepted_pid, "accepted-single-process");
                accepted_pid = pid;
                launcher_tid = PsGetCurrentThreadId();
                check(PsLookupProcessByProcessId(pid, &retained_process) == STATUS_SUCCESS &&
                    retained_process == process, "retain-process-through-exit");
            } else {
                check(accepted_create[0] == 1 && pid == accepted_pid &&
                    PsGetCurrentThreadId() == launcher_tid, "accepted-extended-registration-order");
            }
            check(info->CreationStatus == STATUS_SUCCESS && !classic_create &&
                !thread_create && !exe_images && !ntdll_images, "extended-before-classic-thread-images");
            InterlockedIncrement(&accepted_create[slot]);
            DbgPrint("PROCESS_NOTIFY ACCEPT_EX%lu\n", slot + 1);
        }
    } else {
        check(pid == accepted_pid && pid != rejected_pid && thread_exit == 1 &&
            PsGetCurrentProcessId() == pid && PsGetCurrentThreadId() == initial_tid,
            "extended-exit-after-thread-exit-in-last-thread");
        check(!classic_exit && (!slot || process_exit[0] == 1), "extended-exit-before-classic");
        InterlockedIncrement(&process_exit[slot]);
        DbgPrint("PROCESS_NOTIFY EXIT_EX%lu\n", slot + 1);
    }
}

static void ex_primary(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{ extended(0, process, pid, info); }
static void ex_secondary(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{ extended(1, process, pid, info); }

static void classic(HANDLE parent, HANDLE pid, BOOLEAN create)
{
    callback_context();
    check(parent == (HANDLE)4 && pid == accepted_pid && pid != rejected_pid,
        "classic-accepted-only-parent-and-pid");
    lookup_visible(pid, NULL);
    if (create) {
        check(accepted_create[0] == 1 && accepted_create[1] == 1 &&
            !thread_create && PsGetCurrentProcessId() == (HANDLE)4 &&
            PsGetCurrentThreadId() == launcher_tid, "classic-create-after-extended-before-thread");
        InterlockedIncrement(&classic_create);
        DbgPrint("PROCESS_NOTIFY CLASSIC_CREATE\n");
    } else {
        check(process_exit[0] == 1 && process_exit[1] == 1 && thread_exit == 1 &&
            PsGetCurrentProcessId() == pid && PsGetCurrentThreadId() == initial_tid,
            "classic-exit-after-extended-in-last-thread");
        InterlockedIncrement(&classic_exit);
        DbgPrint("PROCESS_NOTIFY CLASSIC_EXIT\n");
    }
}

static void thread_observer(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    if (pid == (HANDLE)4) return; /* Includes the monitor's system thread. */
    check(pid == accepted_pid && pid != rejected_pid && tid, "thread-accepted-subject");
    if (create) {
        check(classic_create == 1 && !thread_create && !exe_images && !ntdll_images &&
            PsGetCurrentProcessId() == (HANDLE)4 && PsGetCurrentThreadId() == launcher_tid &&
            tid != launcher_tid, "initial-thread-create-after-process-before-images");
        initial_tid = tid;
        InterlockedIncrement(&thread_create);
        DbgPrint("PROCESS_NOTIFY THREAD_CREATE\n");
    } else {
        check(thread_create == 1 && tid == initial_tid && exe_images == 1 && ntdll_images == 1 &&
            !process_exit[0] && !process_exit[1] && !classic_exit &&
            PsGetCurrentProcessId() == pid && PsGetCurrentThreadId() == tid,
            "initial-thread-exit-before-process-in-last-thread");
        InterlockedIncrement(&thread_exit);
        DbgPrint("PROCESS_NOTIFY THREAD_EXIT\n");
    }
}

static void image_observer(PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info)
{
    if (pid == (HANDLE)4) return;
    check(pid == accepted_pid && pid != rejected_pid && thread_create == 1 && !thread_exit,
        "user-image-pid-after-initial-thread-create");
    check(info && info->ImageBase && info->ImageSize && !info->SystemModeImage &&
        valid_string(name), "user-image-payload");
    if (contains(name, L"process_notify_user.exe")) {
        InterlockedIncrement(&exe_images);
        DbgPrint("PROCESS_NOTIFY IMAGE_EXE\n");
    } else if (contains(name, L"ntdll.dll")) {
        InterlockedIncrement(&ntdll_images);
        DbgPrint("PROCESS_NOTIFY IMAGE_NTDLL\n");
    } else check(FALSE, "unexpected-user-image");
}

static NTSTATUS registry_observer(PVOID context, PVOID kind, PVOID information)
{
    UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(kind);
    UNREFERENCED_PARAMETER(information);
    if (PsGetCurrentProcessId() == (HANDLE)4) return STATUS_SUCCESS;
    check(PsGetCurrentProcessId() == accepted_pid &&
        PsGetCurrentThreadId() == initial_tid && KeGetCurrentIrql() == PASSIVE_LEVEL,
        "registry-callback-from-user-loader-has-kernel-pcr-and-subject");
    InterlockedIncrement(&user_registry_calls);
    return STATUS_SUCCESS;
}

static void unregister_all(void)
{
    if (registry_registered) check(CmUnRegisterCallback(registry_cookie) == STATUS_SUCCESS, "remove-registry");
    if (registered[4]) check(PsRemoveLoadImageNotifyRoutine(image_observer) == STATUS_SUCCESS, "remove-image");
    if (registered[3]) check(PsRemoveCreateThreadNotifyRoutine(thread_observer) == STATUS_SUCCESS, "remove-thread");
    if (registered[2]) check(PsSetCreateProcessNotifyRoutine(classic, TRUE) == STATUS_SUCCESS, "remove-classic");
    if (registered[1]) check(PsSetCreateProcessNotifyRoutineEx(ex_secondary, TRUE) == STATUS_SUCCESS, "remove-ex-secondary");
    if (registered[0]) check(PsSetCreateProcessNotifyRoutineEx(ex_primary, TRUE) == STATUS_SUCCESS, "remove-ex-primary");
}

static void lookup_removed(HANDLE pid)
{
    PEPROCESS found = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &found);
    check(pid && status == STATUS_INVALID_CID, "completed-process-pid-removed");
    if (NT_SUCCESS(status) && found) ObDereferenceObject(found);
}

static BOOLEAN is_removed(HANDLE pid)
{
    PEPROCESS found = NULL;
    NTSTATUS status;
    if (!pid) return FALSE;
    status = PsLookupProcessByProcessId(pid, &found);
    if (NT_SUCCESS(status) && found) ObDereferenceObject(found);
    return status == STATUS_INVALID_CID;
}

static void monitor(PVOID unused)
{
    LARGE_INTEGER interval;
    LARGE_INTEGER poll;
    ULONG attempt;
    UNREFERENCED_PARAMETER(unused);
    interval.QuadPart = -1000000; /* 100 ms; at most ten seconds of guest waits. */
    for (attempt = 0; attempt < 100; ++attempt) {
        /* Always yield once so completed callback stacks can unwind and remove PIDs. */
        if (KeDelayExecutionThread(KernelMode, FALSE, &interval) != STATUS_SUCCESS) {
            check(FALSE, "monitor-delay");
            break;
        }
        if (classic_exit && rejected_create[1] &&
            is_removed(accepted_pid) && is_removed(rejected_pid)) break;
    }
    check(attempt < 100 && classic_exit == 1 && rejected_create[1] == 1,
        "monitor-completed-within-ten-seconds");
    check(accepted_create[0] == 1 && accepted_create[1] == 1 &&
        rejected_create[0] == 1 && rejected_create[1] == 1 &&
        process_exit[0] == 1 && process_exit[1] == 1 && classic_create == 1 && classic_exit == 1,
        "exact-process-counts-sticky-veto-no-rejected-exit");
    check(thread_create == 1 && thread_exit == 1 && exe_images == 1 && ntdll_images == 1,
        "exact-accepted-thread-and-image-counts");
    check(accepted_pid && rejected_pid && accepted_pid != rejected_pid, "distinct-subject-pids");
    lookup_removed(accepted_pid);
    lookup_removed(rejected_pid);
    poll.QuadPart = 0;
    check(retained_process && KeWaitForSingleObject(retained_process, Executive,
        KernelMode, FALSE, &poll) == STATUS_SUCCESS, "exited-process-object-signaled-after-pid-removal");
    if (retained_process) ObDereferenceObject(retained_process);
    check(user_registry_calls > 0, "user-loader-registry-callbacks-delivered-before-ring3-entry");
    unregister_all();
    DbgPrint("PROCESS_NOTIFY COMPLETE\n");
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    NTSTATUS status;
    HANDLE handle = NULL;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    check(PsGetCurrentProcessId() == (HANDLE)4, "driver-system-context");
    /* Register classic first: dispatch must still run extended callbacks first. */
    registered[2] = NT_SUCCESS(PsSetCreateProcessNotifyRoutine(classic, FALSE));
    registered[0] = NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(ex_primary, FALSE));
    registered[1] = NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(ex_secondary, FALSE));
    registered[3] = NT_SUCCESS(PsSetCreateThreadNotifyRoutine(thread_observer));
    registered[4] = NT_SUCCESS(PsSetLoadImageNotifyRoutine(image_observer));
    {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"321004.1");
        registry_registered = NT_SUCCESS(CmRegisterCallbackEx(registry_observer, &altitude,
            driver, NULL, &registry_cookie, NULL));
        check(registry_registered, "register-user-loader-registry-observer");
    }
    check(registered[0] && registered[1] && registered[2] && registered[3] && registered[4], "register-all-observers");
    check(!accepted_create[0] && !accepted_create[1] && !rejected_create[0] && !rejected_create[1] &&
        !process_exit[0] && !process_exit[1] && !classic_create && !classic_exit &&
        !thread_create && !thread_exit && !exe_images && !ntdll_images, "no-seed-replay");
    if (failures) { unregister_all(); return STATUS_UNSUCCESSFUL; }
    status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, monitor, NULL);
    check(NT_SUCCESS(status) && handle, "create-monitor-before-entry-return");
    if (!NT_SUCCESS(status) || !handle) { unregister_all(); return STATUS_UNSUCCESSFUL; }
    check(ZwClose(handle) == STATUS_SUCCESS, "close-monitor-handle");
    DbgPrint("PROCESS_NOTIFY READY\n");
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
