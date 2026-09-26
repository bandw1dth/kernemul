#include <ntifs.h>

/* Emulator-only execution fault probe; never install on the host. */
__declspec(noinline) static ULONG probe(void) { return 0x12345678; }
typedef ULONG (*PROBE)(void);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE file, section;
    PVOID base = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    volatile PROBE mapped_probe;
    PVOID protect_base;
    SIZE_T protect_size;
    ULONG old_protection;
    ULONG_PTR offset = (ULONG_PTR)probe - (ULONG_PTR)driver->DriverStart;
    UNREFERENCED_PARAMETER(path);
    RtlInitUnicodeString(&name, L"\\??\\C:\\image_noexecute_enforcement.sys");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenFile(&file, FILE_GENERIC_READ, &attributes, &io, FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) goto failed;
    /* Positive control: the same relocated code executes from an ordinary view. */
    status = ZwCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    if (!NT_SUCCESS(status)) goto failed;
    status = ZwMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, NULL, &size,
        ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status) || !base || offset >= size) goto failed;
    mapped_probe = (PROBE)((ULONG_PTR)base + offset);
    if (mapped_probe() != 0x12345678) goto failed;
    DbgPrint("IMAGE_NOEXECUTE CONTROL_EXECUTED\n");
    ZwUnmapViewOfSection(NtCurrentProcess(), base);
    ZwClose(section);
    base = NULL; size = 0;
    status = ZwCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, file);
    if (!NT_SUCCESS(status)) goto failed;
    /* Even an executable protection request must not override the section policy. */
    status = ZwMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, NULL, &size,
        ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status) || !base || offset >= size) goto failed;
    DbgPrint("IMAGE_NOEXECUTE READABLE_MZ=%x\n", *(volatile USHORT*)base);
    /* Read/write changes remain valid, but later execution cannot be enabled. */
    protect_base = (PVOID)((ULONG_PTR)base + offset); protect_size = 1;
    status = ZwProtectVirtualMemory(NtCurrentProcess(), &protect_base, &protect_size,
        PAGE_READWRITE, &old_protection);
    if (!NT_SUCCESS(status)) goto failed;
    protect_base = (PVOID)((ULONG_PTR)base + offset); protect_size = 1;
    old_protection = 0x1234;
    status = ZwProtectVirtualMemory(NtCurrentProcess(), &protect_base, &protect_size,
        PAGE_EXECUTE_READ, &old_protection);
    if (status != STATUS_SECTION_PROTECTION || old_protection != 0x1234 ||
        protect_base != (PVOID)((ULONG_PTR)base + offset) || protect_size != 1) goto failed;
    status = ZwProtectVirtualMemory(NtCurrentProcess(), &protect_base, &protect_size,
        PAGE_EXECUTE_READWRITE, &old_protection);
    if (status != STATUS_SECTION_PROTECTION) goto failed;
    DbgPrint("IMAGE_NOEXECUTE REPROTECT_REJECTED\n");
    mapped_probe = (PROBE)((ULONG_PTR)base + offset);
    DbgPrint("IMAGE_NOEXECUTE PRE_EXECUTE\n");
    (void)mapped_probe();
    DbgPrint("IMAGE_NOEXECUTE FORBIDDEN_EXECUTED\n");
    return STATUS_UNSUCCESSFUL;
failed:
    DbgPrint("IMAGE_NOEXECUTE SETUP_FAILED status=%lx\n", status);
    return STATUS_UNSUCCESSFUL;
}
