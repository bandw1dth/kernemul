/* Emulator guest only. Never execute this native image on the host. */
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID *);
NTSYSAPI NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#define SELF ((HANDLE)(LONG_PTR)-1)
#define ACCESS_DENIED ((NTSTATUS)0xC0000022u)
extern unsigned int ob_user_cpl(void);

void NTAPI entry(void)
{
    volatile ULONG *control = (volatile ULONG *)(ULONG_PTR)0x200000000ULL;
    LARGE_INTEGER delay;
    ULONG attempt, sentinel;
    ULONG value, other;
    SIZE_T copied;
    HANDLE peer = NULL, read_only = NULL, query_only = NULL, rejected = NULL;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES attributes = { sizeof(OBJECT_ATTRIBUTES) };
    NTSTATUS result = (NTSTATUS)0xC0A11001u;
    delay.QuadPart = -100000; /* 10 ms, at most ten seconds. */
    if (ob_user_cpl() != 3 || __readgsqword(0x40) == 4) goto done;
    sentinel = control[0];
    if (sentinel != 0xA11CA001u && sentinel != 0xA11CB002u) goto done;
    for (attempt = 0; attempt < 1000 && control[3] != 1; ++attempt)
        if (NtDelayExecution(FALSE, &delay) != 0) goto done;
    if (attempt == 1000 || control[0] != sentinel) goto done;
    if (control[1] != (sentinel == 0xA11CA001u ? 0xCCCCCCCCu : 0xBEEF1234u)) goto done;
    if (control[2] != (sentinel == 0xA11CA001u ? 0xCCCCCCCCu : 0xA11CA001u)) goto done;
    other = sentinel == 0xA11CA001u ? 0xA11CB002u : 0xA11CA001u;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)control[6];
    cid.UniqueThread = NULL;
    if (!cid.UniqueProcess || NtOpenProcess(&peer, PROCESS_VM_READ, &attributes, &cid) != 0) goto done;
    value = 0; copied = 99;
    if (NtReadVirtualMemory(peer, (PVOID)control, &value, sizeof(value), &copied) != 0 ||
        copied != sizeof(value) || value != other) goto done;
    value = 0;
    if (NtReadVirtualMemory(peer, (PVOID)control, &value, sizeof(value), NULL) != 0 || value != other) goto done;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)__readgsqword(0x40);
    if (NtOpenProcess(NULL, PROCESS_VM_READ, &attributes, &cid) >= 0) goto done;
    if (NtOpenProcess((PHANDLE)(ULONG_PTR)0xFFFFF80000000000ULL,
        PROCESS_VM_READ, &attributes, &cid) >= 0) goto done;
    attributes.Attributes = 0x200; /* OBJ_KERNEL_HANDLE is not a user handle request. */
    if (NtOpenProcess(&rejected, PROCESS_VM_READ, &attributes, &cid) >= 0 || rejected) goto done;
    attributes.Attributes = 0;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)0x12345678;
    if (NtOpenProcess(&rejected, PROCESS_VM_READ, &attributes, &cid) >= 0 || rejected) goto done;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)__readgsqword(0x40);
    if (NtOpenProcess(&read_only, PROCESS_VM_READ, &attributes, &cid) != 0) goto done;
    if (NtOpenProcess(&query_only, PROCESS_QUERY_INFORMATION, &attributes, &cid) != 0) goto done;
    value = 0x1234ABCDu; copied = 99;
    if (NtWriteVirtualMemory(SELF, (PVOID)&control[8], &value, sizeof(value), &copied) != 0 ||
        copied != sizeof(value) || control[8] != value) goto done;
    value = 0; copied = 99;
    if (NtReadVirtualMemory(read_only, (PVOID)&control[8], &value, sizeof(value), &copied) != 0 ||
        copied != sizeof(value) || value != 0x1234ABCDu) goto done;
    value = 0x5678DCBAu;
    if (NtWriteVirtualMemory(SELF, (PVOID)&control[8], &value, sizeof(value), NULL) != 0 ||
        control[8] != value) goto done;
    value = 0xDEADBEEFu; copied = 99;
    if (NtWriteVirtualMemory(read_only, (PVOID)&control[8], &value, sizeof(value), &copied) != ACCESS_DENIED ||
        control[8] != 0x5678DCBAu) goto done;
    if (NtReadVirtualMemory(query_only, (PVOID)&control[8], &value, sizeof(value), &copied) != ACCESS_DENIED ||
        value != 0xDEADBEEFu) goto done;
    if (NtReadVirtualMemory((HANDLE)(ULONG_PTR)0x12345678, (PVOID)control, &value,
        sizeof(value), &copied) >= 0 || value != 0xDEADBEEFu) goto done;
    if (NtWriteVirtualMemory((HANDLE)(ULONG_PTR)0x12345678, (PVOID)&control[8], &value,
        sizeof(value), &copied) >= 0 || control[8] != 0x5678DCBAu) goto done;
    {
        HANDLE kernel_handle = (HANDLE)(ULONG_PTR)((ULONGLONG)control[12] | ((ULONGLONG)control[13] << 32));
        if (!kernel_handle) goto done;
        value = 0xDEADBEEFu;
        if (NtReadVirtualMemory(kernel_handle, (PVOID)control, &value, sizeof(value), &copied) !=
            (NTSTATUS)0xC0000008u || value != 0xDEADBEEFu) goto done;
        if (NtWriteVirtualMemory(kernel_handle, (PVOID)&control[8], &value, sizeof(value), &copied) !=
            (NTSTATUS)0xC0000008u || control[8] != 0x5678DCBAu) goto done;
    }
    /* The monitor releases both subjects after their peer reads finish. */
    control[9] = 1;
    for (attempt = 0; attempt < 1000 && control[10] != 1; ++attempt)
        if (NtDelayExecution(FALSE, &delay) != 0) goto done;
    if (attempt == 1000) goto done;
    result = (NTSTATUS)0xA11C;
done:
    if (query_only && NtClose(query_only) != 0) result = (NTSTATUS)0xC0A11001u;
    if (read_only && NtClose(read_only) != 0) result = (NTSTATUS)0xC0A11001u;
    if (peer && NtClose(peer) != 0) result = (NTSTATUS)0xC0A11001u;
    NtTerminateProcess(SELF, result);
    for (;;) { /* Runner deadline catches a returning termination. */ }
}
