#include <ntifs.h>

/* Guest-only fixture: never install or load this driver on the host.
 * The negative wrapper verifies publication rollback before the expected fatal
 * export-hook exception. Use its dedicated runner, not run-conformance.ps1.
 */
typedef NTSTATUS (NTAPI *OPEN_FILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, ULONG, ULONG);
static LONG failures, creates, cleanups, closes, sequence;
static PFILE_OBJECT opened_file;
#ifdef DEVICE_HANDLE_ROLLBACK_NEGATIVE
static BOOLEAN publication_fault;
#endif

static void check(BOOLEAN ok, const char *name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

static NTSTATUS dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    UNREFERENCED_PARAMETER(device);
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        ++creates;
        check(sequence == 0 && stack->FileObject != NULL, "create-first-with-file-object");
        opened_file = stack->FileObject;
        sequence = 1;
        break;
    case IRP_MJ_CLEANUP:
        ++cleanups;
        check(sequence == 1 && stack->FileObject == opened_file, "cleanup-after-create-same-file");
        sequence = 2;
        break;
    case IRP_MJ_CLOSE:
        ++closes;
        check(sequence == 2 && stack->FileObject == opened_file, "close-after-cleanup-same-file");
        sequence = 3;
        break;
    default:
        check(FALSE, "unexpected-dispatch");
        break;
    }
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = stack->MajorFunction == IRP_MJ_CREATE ? FILE_OPENED : 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
#ifdef DEVICE_HANDLE_ROLLBACK_NEGATIVE
    if (publication_fault)
        DbgPrint("DEVICE_ROLLBACK_NEGATIVE DISPATCH sequence=%ld create=%ld cleanup=%ld close=%ld failures=%ld\n",
            sequence, creates, cleanups, closes, failures);
#endif
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    UNICODE_STRING name, routine;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    PDEVICE_OBJECT device = NULL;
    HANDLE handle = NULL, duplicate = NULL;
    OPEN_FILE nt_open;
    NTSTATUS status;
    volatile UCHAR *previous;
    UCHAR saved;
    UNREFERENCED_PARAMETER(registry_path);
    driver->MajorFunction[IRP_MJ_CREATE] = dispatch;
    driver->MajorFunction[IRP_MJ_CLEANUP] = dispatch;
    driver->MajorFunction[IRP_MJ_CLOSE] = dispatch;
    RtlInitUnicodeString(&name, L"\\Device\\DeviceHandleRollback");
    status = IoCreateDevice(driver, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device);
    check(NT_SUCCESS(status) && device != NULL, "create-custom-device");
    if (!NT_SUCCESS(status) || !device) goto done;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    RtlInitUnicodeString(&routine, L"NtOpenFile");
    nt_open = (OPEN_FILE)MmGetSystemRoutineAddress(&routine);
    check(nt_open != NULL, "resolve-nt-open-file");
    if (nt_open) {
        /* Fixed guest ABI, as in storage_conformance.c: KTHREAD.PreviousMode. */
        previous = (volatile UCHAR *)PsGetCurrentThread() + 0x232;
        saved = *previous;
        __try {
            *previous = UserMode;
            status = nt_open(&handle, FILE_READ_DATA, &attributes, &io, FILE_SHARE_READ, 0);
        } __finally {
            *previous = saved;
        }
        check(status == STATUS_INVALID_PARAMETER && handle == NULL,
            "user-kernel-handle-rejected");
        check(creates == 0 && cleanups == 0 && closes == 0,
            "user-kernel-handle-rejected-before-create");
        if (handle) { ZwClose(handle); handle = NULL; }
    }
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    status = ZwOpenFile(&handle, FILE_READ_DATA, &attributes, &io, FILE_SHARE_READ, 0);
    check(NT_SUCCESS(status) && handle != NULL, "valid-custom-device-open");
    check(creates == 1 && cleanups == 0 && closes == 0, "open-dispatches-only-create");
    if (NT_SUCCESS(status) && handle) {
        status = ZwDuplicateObject(NtCurrentProcess(), handle, NtCurrentProcess(), &duplicate,
            0, 0, DUPLICATE_SAME_ACCESS);
        check(NT_SUCCESS(status) && duplicate != NULL, "duplicate-device-handle");
        check(creates == 1 && cleanups == 0 && closes == 0, "duplicate-has-no-dispatch");
        check(NT_SUCCESS(ZwClose(handle)), "close-original-handle");
        handle = NULL;
        if (duplicate) {
            check(creates == 1 && cleanups == 0 && closes == 0,
                "nonlast-handle-close-has-no-dispatch");
            check(NT_SUCCESS(ZwClose(duplicate)), "close-last-handle");
            duplicate = NULL;
        }
        check(creates == 1 && cleanups == 1 && closes == 1 && sequence == 3,
            "last-handle-exactly-one-cleanup-then-close");
    }
#ifdef DEVICE_HANDLE_ROLLBACK_NEGATIVE
    if (failures) goto done;
    creates = cleanups = closes = sequence = 0;
    opened_file = NULL;
    publication_fault = TRUE;
    attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
    DbgPrint("DEVICE_ROLLBACK_NEGATIVE BEGIN\n");
    ZwOpenFile((PHANDLE)(ULONG_PTR)0xFFFFFE00BAD00000ull, FILE_READ_DATA,
        &attributes, &io, FILE_SHARE_READ, 0);
    DbgPrint("DEVICE_ROLLBACK_NEGATIVE FORBIDDEN_CONTINUATION\n");
    ++failures;
#endif
    IoDeleteDevice(device);
done:
#ifdef DEVICE_HANDLE_ROLLBACK_NEGATIVE
    DbgPrint("DEVICE_ROLLBACK_NEGATIVE UNEXPECTED_COMPLETION\n");
#else
    DbgPrint("CONFORMANCE COVERAGE publication-fault-rollback=separate-negative-fixture\n");
#endif
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
