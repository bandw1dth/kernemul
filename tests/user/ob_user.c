/* Emulator guest only. Never execute this native image on the host. */
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

NTSYSAPI NTSTATUS NTAPI NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
extern unsigned int ob_user_cpl(void);

static ULONG_PTR saved_teb, saved_pid, saved_tid;
#define CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)

__declspec(noreturn) static void finish(ULONG status)
{
    NtTerminateProcess(CURRENT_PROCESS, (NTSTATUS)status);
    for (;;) { /* Termination must not return. Runner times out if it does. */ }
}

static void restored(ULONG stage)
{
    if (ob_user_cpl() != 3 || __readgsqword(0x30) != saved_teb ||
        __readgsqword(0x40) != saved_pid || __readgsqword(0x48) != saved_tid)
        finish(0xC0B00100u + stage);
}

static void completed(NTSTATUS status, HANDLE handle, ULONG stage)
{
    restored(stage);
    if (status < 0 || !handle) finish(0xC0B00200u + stage);
}

static NTSTATUS NTAPI child(PVOID argument)
{
    (void)argument;
    finish(0xC0B00300u); /* CREATE_SUSPENDED must prevent execution. */
}

void NTAPI entry(void)
{
    OBJECT_ATTRIBUTES attributes = { sizeof(OBJECT_ATTRIBUTES), 0, 0, 0, 0, 0 };
    CLIENT_ID cid;
    HANDLE opened = NULL, duplicate = NULL, created = NULL;
    NTSTATUS status;
    saved_teb = __readgsqword(0x30);
    saved_pid = __readgsqword(0x40);
    saved_tid = __readgsqword(0x48);
    restored(0);
    if (!saved_teb || !saved_pid || saved_pid == 4 || !saved_tid) finish(0xC0B00400u);
    cid.UniqueProcess = (HANDLE)saved_pid;
    cid.UniqueThread = (HANDLE)saved_tid;
    status = NtOpenThread(&opened, THREAD_QUERY_INFORMATION | THREAD_TERMINATE, &attributes, &cid);
    completed(status, opened, 1);
    status = NtDuplicateObject(CURRENT_PROCESS, opened, CURRENT_PROCESS, &duplicate, 0, 0, DUPLICATE_SAME_ACCESS);
    completed(status, duplicate, 2);
    status = NtCreateThreadEx(&created, THREAD_QUERY_INFORMATION | THREAD_TERMINATE, &attributes,
        CURRENT_PROCESS, (PVOID)child, NULL, 1 /* CREATE_SUSPENDED */, 0, 0, 0, NULL);
    completed(status, created, 3);
    status = NtClose(created);
    completed(status, created, 4);
    status = NtClose(duplicate);
    completed(status, duplicate, 5);
    status = NtClose(opened);
    completed(status, opened, 6);
    finish(0);
}
