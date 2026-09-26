#include <ntifs.h>

/* Emulator-only negative callback fixtures; never install on the host. */
static KTIMER invalid_timer;
static void image_failure(PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info)
{
    LARGE_INTEGER delay;
    UNREFERENCED_PARAMETER(name); UNREFERENCED_PARAMETER(pid); UNREFERENCED_PARAMETER(info);
    DbgPrint("IMAGE_NOTIFY_FAILURE PRE_FAULT\n");
    delay.QuadPart = -10000000;
#if IMAGE_FAILURE_MODE == 1
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
#elif IMAGE_FAILURE_MODE == 2
    PsRemoveLoadImageNotifyRoutine(image_failure);
#elif IMAGE_FAILURE_MODE == 3
    KeSetTimerEx(&invalid_timer, delay, -1, NULL);
#elif IMAGE_FAILURE_MODE == 4
    PsTerminateSystemThread(STATUS_SUCCESS);
#endif
    DbgPrint("IMAGE_NOTIFY_FAILURE FORBIDDEN_POST_FAULT\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE file, section;
    PVOID base = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    KeInitializeTimer(&invalid_timer);
    RtlInitUnicodeString(&name, IMAGE_FAILURE_PATH);
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenFile(&file, FILE_GENERIC_READ, &attributes, &io, FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) goto failed;
    status = ZwCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    if (!NT_SUCCESS(status)) goto failed;
    status = PsSetLoadImageNotifyRoutine(image_failure);
    if (!NT_SUCCESS(status)) goto failed;
    DbgPrint("IMAGE_NOTIFY_FAILURE PRE_MAP\n");
    ZwMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, NULL, &size, ViewUnmap, 0, PAGE_READONLY);
    DbgPrint("IMAGE_NOTIFY_FAILURE FORBIDDEN_POST_MAP\n");
    return STATUS_UNSUCCESSFUL;
failed:
    DbgPrint("IMAGE_NOTIFY_FAILURE SETUP_FAILED status=%lx\n", status);
    return status;
}
