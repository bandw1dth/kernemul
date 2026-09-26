#include <ntifs.h>

static LONG failures, calls[2], bad_payload;
static HANDLE owner_pid, owner_tid;
static PVOID observed_base;
static SIZE_T observed_size;
static BOOLEAN original_apcs;

static void check(BOOLEAN ok, const char* label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}
static void observe(ULONG slot, PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info)
{
    static const WCHAR suffix[] = L"image_notify_conformance.sys";
    ULONG i, chars;
    ++calls[slot];
    if (!info || pid != owner_pid || PsGetCurrentProcessId() != owner_pid ||
        PsGetCurrentThreadId() != owner_tid || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !KeAreApcsDisabled()) { ++bad_payload; return; }
    if (!info->ImageBase || !info->ImageSize || info->SystemModeImage ||
        info->ExtendedInfoPresent || info->ImagePartialMap || info->ImageMappedToAllPids)
        ++bad_payload;
    if (info->ImageBase && *(volatile USHORT*)info->ImageBase != 0x5A4D) ++bad_payload;
    if (!name || !name->Buffer || name->Length % sizeof(WCHAR)) { ++bad_payload; return; }
    chars = name->Length / sizeof(WCHAR);
    if (chars < RTL_NUMBER_OF(suffix) - 1) { ++bad_payload; return; }
    for (i = 0; i < RTL_NUMBER_OF(suffix) - 1; ++i)
        if (name->Buffer[chars - (RTL_NUMBER_OF(suffix) - 1) + i] != suffix[i]) ++bad_payload;
    observed_base = info->ImageBase;
    observed_size = info->ImageSize;
}
static void notify_a(PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info) { observe(0, name, pid, info); }
static void notify_b(PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info) { observe(1, name, pid, info); }

static PVOID map_section(HANDLE section, BOOLEAN notification_expected)
{
    PVOID base = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    observed_base = NULL;
    observed_size = 0;
    status = ZwMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, NULL, &size,
        ViewUnmap, 0, PAGE_READONLY);
    check(NT_SUCCESS(status) && base && size, "map-section-success");
    if (notification_expected)
        check(observed_base == base && observed_size == size && !bad_payload,
            "callback-sees-committed-image-and-correct-context");
    check(KeAreApcsDisabled() == original_apcs && KeGetCurrentIrql() == PASSIVE_LEVEL,
        "callback-restores-apc-and-irql-context");
    return base;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE file = NULL, image = NULL, data = NULL, no_execute = NULL;
    PVOID first = NULL, second = NULL, temporary = NULL;
    NTSTATUS a, b, status;
    LONG before_a, before_b;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    owner_pid = PsGetCurrentProcessId(); owner_tid = PsGetCurrentThreadId();
    original_apcs = KeAreApcsDisabled();
    RtlInitUnicodeString(&name, L"\\??\\C:\\image_notify_conformance.sys");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenFile(&file, FILE_GENERIC_READ, &attributes, &io, FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    check(NT_SUCCESS(status) && file, "open-image-file");
    if (!NT_SUCCESS(status) || !file) goto done;
    status = ZwCreateSection(&image, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    check(NT_SUCCESS(status) && image, "create-image-section");
    if (!NT_SUCCESS(status) || !image) goto cleanup;
    a = PsSetLoadImageNotifyRoutine(notify_a); b = PsSetLoadImageNotifyRoutine(notify_b);
    check(NT_SUCCESS(a) && NT_SUCCESS(b), "register-two-image-observers");
    check(!calls[0] && !calls[1], "no-notification-for-existing-images-or-section-creation");
    if (!NT_SUCCESS(a) || !NT_SUCCESS(b)) goto unregister;
    first = map_section(image, TRUE);
    check(calls[0] == 1 && calls[1] == 1, "first-image-view-notifies-both");
    second = map_section(image, TRUE);
    check(first != second && calls[0] == 2 && calls[1] == 2, "distinct-second-image-view-notifies");
    before_a = calls[0]; before_b = calls[1];
    status = ZwCreateSection(&data, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_COMMIT, file);
    check(NT_SUCCESS(status) && data, "create-data-section");
    if (NT_SUCCESS(status) && data) {
        temporary = map_section(data, FALSE);
        if (temporary) ZwUnmapViewOfSection(NtCurrentProcess(), temporary);
    }
    status = ZwCreateSection(&no_execute, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY,
        SEC_IMAGE_NO_EXECUTE, file);
    check(NT_SUCCESS(status) && no_execute, "create-noexecute-image-section");
    if (NT_SUCCESS(status) && no_execute) {
        temporary = map_section(no_execute, FALSE);
        if (temporary) ZwUnmapViewOfSection(NtCurrentProcess(), temporary);
    }
    check(calls[0] == before_a && calls[1] == before_b, "data-and-noexecute-views-do-not-notify");
    if (first) check(NT_SUCCESS(ZwUnmapViewOfSection(NtCurrentProcess(), first)), "unmap-first-image");
    if (second) check(NT_SUCCESS(ZwUnmapViewOfSection(NtCurrentProcess(), second)), "unmap-second-image");
    check(calls[0] == before_a && calls[1] == before_b, "unmap-does-not-notify");
    check(PsRemoveLoadImageNotifyRoutine(notify_a) == STATUS_SUCCESS, "remove-first-image-observer");
    a = STATUS_UNSUCCESSFUL;
    temporary = map_section(image, TRUE);
    check(calls[0] == before_a && calls[1] == before_b + 1, "removed-observer-not-called");
    if (temporary) ZwUnmapViewOfSection(NtCurrentProcess(), temporary);
unregister:
    if (NT_SUCCESS(a)) PsRemoveLoadImageNotifyRoutine(notify_a);
    if (NT_SUCCESS(b)) check(PsRemoveLoadImageNotifyRoutine(notify_b) == STATUS_SUCCESS, "remove-second-image-observer");
    check(PsRemoveLoadImageNotifyRoutine(notify_a) == STATUS_PROCEDURE_NOT_FOUND, "remove-absent-image-observer");
    before_a = calls[0]; before_b = calls[1];
    temporary = map_section(image, FALSE);
    check(calls[0] == before_a && calls[1] == before_b, "no-callbacks-after-all-removals");
    if (temporary) ZwUnmapViewOfSection(NtCurrentProcess(), temporary);
cleanup:
    if (image) ZwClose(image);
    if (data) ZwClose(data);
    if (no_execute) ZwClose(no_execute);
    if (file) ZwClose(file);
done:
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
