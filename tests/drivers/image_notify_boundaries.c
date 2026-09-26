#include <ntifs.h>

/* Emulator-only output-pointer and malformed-image fault injection. */
static LONG failures, calls;
static void check(BOOLEAN ok, const char* label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}
static void notify(PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info)
{
    UNREFERENCED_PARAMETER(name); UNREFERENCED_PARAMETER(pid); UNREFERENCED_PARAMETER(info);
    ++calls;
}
static NTSTATUS open_file(PCWSTR path, PHANDLE file)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwOpenFile(file, FILE_GENERIC_READ, &attributes, &io, FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    HANDLE file = NULL, section = NULL, invalid_file = NULL, invalid_section = NULL;
    PVOID base = NULL;
    SIZE_T size = 0;
    LARGE_INTEGER offset, maximum;
    NTSTATUS status;
    BOOLEAN registered = FALSE;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    UCHAR malformed[64] = {0};
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    check(PsSetLoadImageNotifyRoutineEx(notify, 0x80000000) == STATUS_INVALID_PARAMETER_2,
        "invalid-ex-flags-rejected");
    check(PsSetLoadImageNotifyRoutineEx(notify, PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE) == STATUS_NOT_SUPPORTED,
        "cross-architecture-mode-explicitly-unsupported");
    status = PsSetLoadImageNotifyRoutineEx(notify, 0);
    registered = NT_SUCCESS(status);
    check(registered, "register-ex-zero-flags");
    if (!registered) goto cleanup;
    status = open_file(L"\\??\\C:\\image_notify_boundaries.sys", &file);
    check(NT_SUCCESS(status) && file, "open-boundary-image");
    if (!NT_SUCCESS(status) || !file) goto cleanup;
    status = ZwCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    check(NT_SUCCESS(status) && section, "create-boundary-section");
    if (!NT_SUCCESS(status) || !section) goto cleanup;
    status = ZwMapViewOfSection(section, NtCurrentProcess(), NULL, 0, 0, NULL, &size, ViewUnmap, 0, PAGE_READONLY);
    check(!NT_SUCCESS(status) && !calls, "null-base-output-no-notification");
    status = ZwMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, NULL, NULL, ViewUnmap, 0, PAGE_READONLY);
    check(!NT_SUCCESS(status) && !calls, "null-size-output-no-notification");
    size = 0;
    status = ZwMapViewOfSection(section, NtCurrentProcess(), (PVOID*)(ULONG_PTR)0xFFFFFE00BAD00000ull,
        0, 0, NULL, &size, ViewUnmap, 0, PAGE_READONLY);
    check(status == STATUS_ACCESS_VIOLATION && !calls && !size, "unmapped-output-no-notification");
    offset.QuadPart = 1;
    status = ZwMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, &offset, &size, ViewUnmap, 0, PAGE_READONLY);
    check(!NT_SUCCESS(status) && !calls, "nonzero-image-offset-rejected");
    status = ZwMapViewOfSection(section, (HANDLE)(ULONG_PTR)0x123456, &base, 0, 0, NULL,
        &size, ViewUnmap, 0, PAGE_READONLY);
    check(!NT_SUCCESS(status) && !calls, "unsupported-process-handle-no-notification");
    maximum.QuadPart = 4096;
    status = ZwCreateSection(&invalid_section, SECTION_ALL_ACCESS, NULL, &maximum, PAGE_READONLY, SEC_IMAGE, NULL);
    check(!NT_SUCCESS(status) && !calls, "image-requires-file");
    if (NT_SUCCESS(status) && invalid_section) ZwClose(invalid_section);
    invalid_section = NULL;

    RtlInitUnicodeString(&name, L"\\??\\C:\\image_notify_invalid.bin");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&invalid_file, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attributes, &io,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    check(NT_SUCCESS(status) && invalid_file, "create-malformed-image-fixture");
    if (NT_SUCCESS(status) && invalid_file) {
        malformed[0] = 'M'; malformed[1] = 'Z';
        malformed[60] = 0xF0; malformed[61] = 0xFF; malformed[62] = 0xFF; malformed[63] = 0x7F;
        status = ZwWriteFile(invalid_file, NULL, NULL, NULL, &io, malformed, sizeof(malformed), NULL, NULL);
        check(NT_SUCCESS(status), "write-malformed-image-fixture");
        status = ZwCreateSection(&invalid_section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, invalid_file);
        check(status == STATUS_INVALID_IMAGE_FORMAT && !calls, "malformed-pe-rejected-without-notification");
    }
    base = NULL; size = 0;
    status = ZwMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, NULL, &size, ViewUnmap, 0, PAGE_READONLY);
    check(NT_SUCCESS(status) && base && size && calls == 1, "valid-map-after-failures-notifies-once");
    if (base) {
        check(!NT_SUCCESS(ZwUnmapViewOfSection((HANDLE)(ULONG_PTR)0x123456, base)), "invalid-owner-unmap-rejected");
        check(*(volatile USHORT*)base == 0x5A4D, "failed-unmap-preserves-image");
        check(NT_SUCCESS(ZwUnmapViewOfSection(NtCurrentProcess(), base)), "owner-unmap-succeeds");
        check(!NT_SUCCESS(ZwUnmapViewOfSection(NtCurrentProcess(), base)), "double-unmap-rejected");
    }
    {
        HANDLE data_section = NULL;
        PVOID data_base = NULL, free_base;
        SIZE_T data_size = 0, free_size;
        status = ZwCreateSection(&data_section, SECTION_ALL_ACCESS, NULL, NULL,
            PAGE_READONLY, SEC_COMMIT, file);
        check(NT_SUCCESS(status) && data_section, "create-data-ownership-section");
        if (NT_SUCCESS(status) && data_section) {
            status = ZwMapViewOfSection(data_section, NtCurrentProcess(), &data_base,
                0, 0, NULL, &data_size, ViewUnmap, 0, PAGE_READONLY);
            check(NT_SUCCESS(status) && data_base && data_size, "map-data-ownership-view");
            if (NT_SUCCESS(status) && data_base) {
                free_base = data_base; free_size = 0;
                status = ZwFreeVirtualMemory(NtCurrentProcess(), &free_base, &free_size, MEM_RELEASE);
                check(status == STATUS_UNABLE_TO_FREE_VM && free_base == data_base && !free_size,
                    "section-release-rejected-without-output-changes");
                free_base = data_base; free_size = 4096;
                status = ZwFreeVirtualMemory(NtCurrentProcess(), &free_base, &free_size, MEM_DECOMMIT);
                check(status == STATUS_UNABLE_TO_FREE_VM && free_base == data_base && free_size == 4096,
                    "section-decommit-rejected-without-output-changes");
                check(*(volatile USHORT*)data_base == 0x5A4D, "rejected-free-preserves-data-view");
                check(NT_SUCCESS(ZwUnmapViewOfSection(NtCurrentProcess(), data_base)), "data-view-unmap-succeeds");
                check(!NT_SUCCESS(ZwUnmapViewOfSection(NtCurrentProcess(), data_base)), "data-view-double-unmap-rejected");
            }
            ZwClose(data_section);
        }
    }
cleanup:
    if (registered) check(PsRemoveLoadImageNotifyRoutine(notify) == STATUS_SUCCESS, "remove-ex-registration");
    if (invalid_section) ZwClose(invalid_section);
    if (invalid_file) ZwClose(invalid_file);
    if (section) ZwClose(section);
    if (file) ZwClose(file);
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
