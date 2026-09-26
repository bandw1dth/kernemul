#include <ntifs.h>
static KAPC_STATE first, second;
static KTIMER timer;
static void ex_callback(PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(arg1); UNREFERENCED_PARAMETER(arg2);
#if ATTACH_NEGATIVE == 9
    KeStackAttachProcess(PsGetCurrentProcess(), &second);
    DbgPrint("ATTACH_NEGATIVE UNBALANCED_RETURN\n");
#else
    KeUnstackDetachProcess(&first);
    DbgPrint("ATTACH_NEGATIVE FORBIDDEN_CONTINUATION\n");
#endif
}
static void callback(HANDLE parent, HANDLE pid, BOOLEAN create)
{
    PEPROCESS target = NULL;
    UNREFERENCED_PARAMETER(parent);
    if (!create) return;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &target))) {
        DbgPrint("ATTACH_NEGATIVE SETUP_FAILED\n"); return;
    }
    DbgPrint("ATTACH_NEGATIVE BEGIN %d\n", ATTACH_NEGATIVE);
    KeStackAttachProcess(target, &first);
    ObDereferenceObject(target);
#if ATTACH_NEGATIVE == 6
    {
        LARGE_INTEGER due;
        due.QuadPart = -10000;
        KeSetTimerEx(&timer, due, -1, NULL);
        DbgPrint("ATTACH_NEGATIVE FORBIDDEN_CONTINUATION\n");
    }
#else
    DbgPrint("ATTACH_NEGATIVE UNBALANCED_RETURN\n");
#endif
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    KeInitializeTimer(&timer);
#if ATTACH_NEGATIVE == 5 || ATTACH_NEGATIVE == 6
    if (!NT_SUCCESS(PsSetCreateProcessNotifyRoutine(callback, FALSE))) {
        DbgPrint("ATTACH_NEGATIVE SETUP_FAILED\n"); return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("ATTACH_NEGATIVE READY\n");
    return STATUS_SUCCESS;
#else
    DbgPrint("ATTACH_NEGATIVE BEGIN %d\n", ATTACH_NEGATIVE);
#if ATTACH_NEGATIVE == 1
    KeUnstackDetachProcess(&first);
#elif ATTACH_NEGATIVE == 2
    KeStackAttachProcess(PsGetCurrentProcess(), &first);
    KeStackAttachProcess(PsGetCurrentProcess(), &second);
    KeUnstackDetachProcess(&first);
#elif ATTACH_NEGATIVE == 3
    KeStackAttachProcess(PsGetCurrentProcess(), &first);
    KeStackAttachProcess(PsGetCurrentProcess(), &first);
#elif ATTACH_NEGATIVE == 4
    KeRaiseIrqlToDpcLevel();
    KeStackAttachProcess(PsGetCurrentProcess(), &first);
#elif ATTACH_NEGATIVE == 7
    KeStackAttachProcess(PsGetCurrentProcess(), &first);
    PsTerminateSystemThread(STATUS_SUCCESS);
#elif ATTACH_NEGATIVE == 8
    KeStackAttachProcess((PEPROCESS)(ULONG_PTR)0x1234, &first);
#elif ATTACH_NEGATIVE == 9 || ATTACH_NEGATIVE == 10
    {
        PCALLBACK_OBJECT object = NULL;
        UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Callback\\AttachBoundary");
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (!NT_SUCCESS(ExCreateCallback(&object, &attributes, TRUE, TRUE)) ||
            !ExRegisterCallback(object, ex_callback, NULL)) {
            DbgPrint("ATTACH_NEGATIVE SETUP_FAILED\n"); return STATUS_UNSUCCESSFUL;
        }
#if ATTACH_NEGATIVE == 10
        KeStackAttachProcess(PsGetCurrentProcess(), &first);
#endif
        ExNotifyCallback(object, NULL, NULL);
    }
#endif
    DbgPrint("ATTACH_NEGATIVE FORBIDDEN_CONTINUATION\n");
    return STATUS_SUCCESS;
#endif
}
