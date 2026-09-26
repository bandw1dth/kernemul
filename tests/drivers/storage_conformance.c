/* Guest input only; never load this fixture on the host. */
#include <ntifs.h>
#include <intrin.h>
#include <ntddstor.h>
#include <ntddscsi.h>
#include <ata.h>

C_ASSERT(sizeof(STORAGE_PROPERTY_QUERY) == 12);
C_ASSERT(sizeof(STORAGE_DEVICE_DESCRIPTOR) == 40);
C_ASSERT(sizeof(ATA_PASS_THROUGH_EX) == 48);
C_ASSERT(sizeof(IDENTIFY_DEVICE_DATA) == 512);
C_ASSERT(IOCTL_ATA_PASS_THROUGH == 0x4d02c);

typedef NTSTATUS (NTAPI *FIRMWARE_QUERY)(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG);
typedef NTSTATUS (NTAPI *RAW_IO)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
    PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
static LONG failures;
static volatile LONG apc_calls;
static UCHAR descriptor[4096], identity[560];
static ULONG descriptor_size;
/* Real backing for cap tests: rejection must not depend on an unmapped tail. */
static struct { ULONGLONG before; UCHAR data[65537]; ULONGLONG after; } output;
static const ULONGLONG guard = 0x1234567887654321ui64;
static void check(BOOLEAN ok, const char *name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}
static BOOLEAN filled(const UCHAR *p, ULONG n, UCHAR value)
{
    ULONG i;
    for (i=0; i<n; ++i) if (p[i] != value) return FALSE;
    return TRUE;
}
static USHORT word(const UCHAR *p) { return (USHORT)(p[0] | ((USHORT)p[1] << 8)); }
static ULONGLONG qword(const UCHAR *p)
{
    ULONG i; ULONGLONG v = 0;
    for (i=0; i<8; ++i) v |= (ULONGLONG)p[i] << (8*i);
    return v;
}
static void reset_output(void)
{
    output.before = output.after = guard;
    RtlFillMemory(output.data, sizeof(output.data), 0xa5);
}
static BOOLEAN untouched(ULONG start)
{
    return output.before == guard && output.after == guard &&
        filled(output.data+start, (ULONG)sizeof(output.data)-start, 0xa5);
}
static NTSTATUS control(HANDLE disk, ULONG code, PVOID input, ULONG in_size,
    PVOID out, ULONG out_size, PIO_STATUS_BLOCK iosb)
{
    RtlFillMemory(iosb, sizeof(*iosb), 0xcc);
    return ZwDeviceIoControlFile(disk, NULL, NULL, NULL, iosb, code,
        input, in_size, out, out_size);
}
static BOOLEAN result(NTSTATUS status, const IO_STATUS_BLOCK *iosb, NTSTATUS expected, ULONG_PTR count)
{
    return status == expected && iosb->Status == expected && iosb->Information == count;
}
static HANDLE open_disk(PCWSTR path, ULONG disposition, BOOLEAN present)
{
    UNICODE_STRING name; OBJECT_ATTRIBUTES attributes; IO_STATUS_BLOCK iosb;
    HANDLE disk = NULL; NTSTATUS status;
    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    RtlFillMemory(&iosb, sizeof(iosb), 0xcc);
    status = ZwCreateFile(&disk, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &attributes, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        disposition, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (present) check(result(status, &iosb, STATUS_SUCCESS, FILE_OPENED) && disk != NULL, "disk-open-existing");
    else check(!NT_SUCCESS(status) && disk == NULL, "absent-disk-no-fake-file");
    if (!NT_SUCCESS(status)) return NULL;
    if (!present) { check(ZwClose(disk) == STATUS_SUCCESS, "close-unexpected-disk"); return NULL; }
    return disk;
}
static BOOLEAN string_at(ULONG offset)
{
    ULONG i;
    if (offset < (ULONG)FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR,RawDeviceProperties) || offset >= descriptor_size) return FALSE;
    for (i=offset; i<descriptor_size; ++i) if (!descriptor[i]) return i > offset;
    return FALSE;
}
static BOOLEAN matches(ULONG offset, const UCHAR *ata, ULONG width)
{
    UCHAR decoded[41]; ULONG i, n = width;
    if (!string_at(offset) || width >= sizeof(decoded)) return FALSE;
    for (i=0; i<width; ++i) decoded[i] = ata[i ^ 1];
    while (n && decoded[n-1] == ' ') --n;
    return offset+n < descriptor_size && descriptor[offset+n] == 0 &&
        RtlCompareMemory(descriptor+offset, decoded, n) == n;
}
static BOOLEAN query_descriptor(HANDLE disk)
{
    STORAGE_PROPERTY_QUERY query; IO_STATUS_BLOCK iosb; NTSTATUS status; ULONG size, i;
    PSTORAGE_DEVICE_DESCRIPTOR d;
    RtlZeroMemory(&query, sizeof(query));
    reset_output();
    status = control(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), output.data, 8, &iosb);
    check(result(status,&iosb,STATUS_SUCCESS,8) && untouched(8), "descriptor-header-status-information-tail");
    /* Baseline adapters do not support this contract. Avoid unsafe follow-up probes. */
    if (status != STATUS_SUCCESS || iosb.Information != 8) return FALSE;
    size = ((PSTORAGE_DESCRIPTOR_HEADER)output.data)->Size;
    check(((PSTORAGE_DESCRIPTOR_HEADER)output.data)->Version == 40 && size >= 40 && size <= sizeof(descriptor), "descriptor-header-version-full-size");
    if (size < 40 || size > sizeof(descriptor)) return FALSE;
    reset_output();
    status = control(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), NULL, 0, &iosb);
    check(result(status,&iosb,STATUS_SUCCESS,0) && untouched(0), "standard-zero-output-exists");
    for (i=1; i<size; ++i) {
        if (i == 8) continue;
        reset_output();
        status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),output.data,i,&iosb);
        if (!result(status,&iosb,STATUS_BUFFER_TOO_SMALL,0) || !untouched(0)) {
            DbgPrint("CONFORMANCE short descriptor length=%lu\n",i);
            check(FALSE,"descriptor-all-short-lengths-preserved"); break;
        }
    }
    if (i == size) check(TRUE,"descriptor-all-short-lengths-preserved");
    reset_output();
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),output.data,size,&iosb);
    check(result(status,&iosb,STATUS_SUCCESS,size) && untouched(size), "descriptor-full-exact");
    if (status != STATUS_SUCCESS || iosb.Information != size) return FALSE;
    if (descriptor_size) check(size == descriptor_size && RtlCompareMemory(descriptor,output.data,size)==size,"descriptor-repeat-alias-reopen-stable");
    else { descriptor_size = size; RtlCopyMemory(descriptor,output.data,size); }
    d = (PSTORAGE_DEVICE_DESCRIPTOR)descriptor;
    check(d->Version == 40 && d->Size == size && d->DeviceType == 0 && d->DeviceTypeModifier == 0 &&
        !d->RemovableMedia && d->BusType == BusTypeAta &&
        d->RawPropertiesLength <= size-FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR,RawDeviceProperties) &&
        string_at(d->ProductIdOffset) && string_at(d->ProductRevisionOffset) && string_at(d->SerialNumberOffset) &&
        (!d->VendorIdOffset || string_at(d->VendorIdOffset)), "descriptor-fields-bounded-nul-strings-ata");
    query.QueryType = PropertyExistsQuery;
    reset_output();
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),output.data,sizeof(descriptor),&iosb);
    check(result(status,&iosb,STATUS_SUCCESS,0) && untouched(0),"property-exists-no-output");
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),NULL,0,&iosb);
    check(result(status,&iosb,STATUS_SUCCESS,0) && untouched(0),"property-exists-null-zero-output");
    query.PropertyId = (STORAGE_PROPERTY_ID)0x7fffffff;
    query.QueryType = PropertyStandardQuery;
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),output.data,sizeof(descriptor),&iosb);
    check(result(status,&iosb,STATUS_NOT_SUPPORTED,0) && untouched(0),"unsupported-property");
    query.PropertyId = StorageDeviceProperty; query.QueryType = (STORAGE_QUERY_TYPE)0x7fffffff;
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),output.data,sizeof(descriptor),&iosb);
    check(result(status,&iosb,STATUS_INVALID_PARAMETER,0) && untouched(0),"unknown-query-type");
    query.QueryType = PropertyStandardQuery;
    reset_output(); RtlCopyMemory(output.data,&query,sizeof(query));
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,output.data,sizeof(query),output.data,size,&iosb);
    check(result(status,&iosb,STATUS_SUCCESS,size) && untouched(size) &&
        RtlCompareMemory(output.data,descriptor,size)==size,"descriptor-in-place-method-buffered");
    return TRUE;
}
static ATA_PASS_THROUGH_EX ata_request(void)
{
    ATA_PASS_THROUGH_EX a;
    RtlZeroMemory(&a,sizeof(a)); a.Length = sizeof(a);
    a.AtaFlags = ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED;
    a.DataTransferLength = 512; a.DataBufferOffset = 48; a.TimeOutValue = 10;
    a.CurrentTaskFile[6] = 0xec;
    return a;
}
static void ata_failure(HANDLE disk, ATA_PASS_THROUGH_EX *a, ULONG out_size, NTSTATUS expected, const char *label)
{
    ATA_PASS_THROUGH_EX saved = *a; IO_STATUS_BLOCK iosb; NTSTATUS status;
    reset_output();
    status = control(disk,IOCTL_ATA_PASS_THROUGH,a,sizeof(*a),output.data,out_size,&iosb);
    /* Validation ordering outside the exact VGK contract is deliberately unspecified. */
    check((expected ? status == expected :
        (status == STATUS_INVALID_PARAMETER || status == STATUS_BUFFER_TOO_SMALL ||
         status == STATUS_NOT_SUPPORTED || status == STATUS_INVALID_DEVICE_REQUEST)) &&
        iosb.Status == status && iosb.Information == 0 && untouched(0) &&
        RtlCompareMemory(a,&saved,sizeof(saved)) == sizeof(saved), label);
}
static void firmware_capacity(ULONG sectors)
{
    UNICODE_STRING name; FIRMWARE_QUERY query; UCHAR data[512]; ULONG size = sizeof(data), pos, end;
    GUID vendor = {0x8be4df61,0x93ca,0x11d2,{0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c}};
    NTSTATUS status; BOOLEAN found = FALSE;
    RtlInitUnicodeString(&name,L"ExGetFirmwareEnvironmentVariable");
    query = (FIRMWARE_QUERY)MmGetSystemRoutineAddress(&name);
    check(query != NULL,"firmware-exget-resolved"); if (!query) return;
    RtlInitUnicodeString(&name,L"Boot0000");
    status = query(&name,&vendor,data,&size,NULL);
    check(status == STATUS_SUCCESS && size >= 6 && size <= sizeof(data),"firmware-boot-option");
    if (status != STATUS_SUCCESS || size < 6 || size > sizeof(data)) return;
    pos = 6; while (pos+2 <= size && word(data+pos)) pos += 2;
    pos += 2; end = pos + word(data+4);
    if (end <= size) while (pos+4 <= end) {
        ULONG n = word(data+pos+2);
        if (n < 4 || n > end-pos) break;
        if (data[pos] == 4 && data[pos+1] == 1 && n == 42) {
            ULONGLONG start = qword(data+pos+8), count = qword(data+pos+16);
            found = start == 2048 && count == 524288 && start <= sectors && count <= sectors-start;
            break;
        }
        pos += n;
    }
    check(found,"identify-capacity-covers-firmware-partition");
}
static void exercise_ata(HANDLE disk, BOOLEAN first)
{
    ATA_PASS_THROUGH_EX a = ata_request(), saved;
    IO_STATUS_BLOCK iosb; NTSTATUS status; PSTORAGE_DEVICE_DESCRIPTOR d = (PSTORAGE_DEVICE_DESCRIPTOR)descriptor;
    ULONG sectors, logical = 512; const UCHAR *id;
    saved = a; reset_output();
    status = control(disk,IOCTL_ATA_PASS_THROUGH,&a,sizeof(a),output.data,560,&iosb);
    check(result(status,&iosb,STATUS_SUCCESS,560) && untouched(560) &&
        RtlCompareMemory(&a,&saved,sizeof(a)) == sizeof(a),"identify-success-input-immutable-tail");
    if (status == STATUS_SUCCESS && iosb.Information == 560) {
        PATA_PASS_THROUGH_EX response = (PATA_PASS_THROUGH_EX)output.data;
        check(response->Length == 48 && response->DataTransferLength == 512 && response->DataBufferOffset == 48 &&
            response->CurrentTaskFile[0] == 0 && response->CurrentTaskFile[6] == 0x50,"identify-taskfile-completion");
        if (first) RtlCopyMemory(identity,output.data,560);
        else check(RtlCompareMemory(identity,output.data,560)==560,"identify-repeat-alias-reopen-stable");
        id = output.data+48;
        check(matches(d->SerialNumberOffset,id+20,20) && matches(d->ProductRevisionOffset,id+46,8) &&
            matches(d->ProductIdOffset,id+54,40),"identify-word-swapped-identity-matches-descriptor");
        sectors = (ULONG)word(id+120) | ((ULONG)word(id+122) << 16);
        if ((word(id+212) & 0xc000) == 0x4000 && (word(id+212) & 0x1000))
            logical = 2 * ((ULONG)word(id+234) | ((ULONG)word(id+236) << 16));
        check(sectors == 16777216 && sectors >= 2048+524288 && logical == 512,"identify-8gib-capacity-logical512");
        if (first) firmware_capacity(sectors);
    }
    reset_output(); RtlCopyMemory(output.data,&saved,sizeof(saved));
    status = control(disk,IOCTL_ATA_PASS_THROUGH,output.data,48,output.data,560,&iosb);
    check(result(status,&iosb,STATUS_SUCCESS,560) && untouched(560) &&
        RtlCompareMemory(output.data,identity,560)==560,"identify-in-place-method-buffered");
    a = ata_request(); a.CurrentTaskFile[0] = 0xec; a.CurrentTaskFile[6] = 0;
    ata_failure(disk,&a,512,STATUS_BUFFER_TOO_SMALL,"vgk-exact-short-output-before-command-no-patch");
    a = ata_request(); a.CurrentTaskFile[6] = 0;
    ata_failure(disk,&a,560,STATUS_INVALID_DEVICE_REQUEST,"unsupported-ata-command");
    a = ata_request(); a.AtaFlags = ATA_FLAGS_DATA_OUT | ATA_FLAGS_DRDY_REQUIRED;
    ata_failure(disk,&a,560,0,"ata-data-out-rejected");
    a = ata_request(); a.AtaFlags |= ATA_FLAGS_48BIT_COMMAND;
    ata_failure(disk,&a,560,0,"ata-48bit-rejected");
    a = ata_request(); a.AtaFlags |= ATA_FLAGS_USE_DMA;
    ata_failure(disk,&a,560,0,"ata-dma-rejected");
    a = ata_request(); a.DataBufferOffset = (ULONG_PTR)-16;
    ata_failure(disk,&a,560,0,"ata-offset-overflow-rejected");
    a = ata_request(); a.DataBufferOffset = 47;
    ata_failure(disk,&a,560,0,"ata-offset-inside-header-rejected");
    a = ata_request(); a.Length = 47;
    ata_failure(disk,&a,560,0,"ata-header-length-rejected");
    a = ata_request(); a.DataTransferLength = 65537;
    ata_failure(disk,&a,65537,0,"ata-request-cap-rejected");
    a = ata_request();
    ata_failure(disk,&a,65537,0,"ata-output-cap-rejected");
}
static void NTAPI dummy_apc(PVOID context, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(iosb); UNREFERENCED_PARAMETER(reserved);
    ++apc_calls;
}
static void previous_mode_io_tests(HANDLE disk)
{
    static const WCHAR *apis[] = {L"NtReadFile", L"NtWriteFile", L"ZwReadFile", L"ZwWriteFile"};
    static const char *labels[] = {
        "nt-read-usermode-kernel-iosb-preserved", "nt-write-usermode-kernel-iosb-preserved",
        "zw-read-kernel-bypasses-previousmode", "zw-write-kernel-bypasses-previousmode"
    };
    static const char *invalid_labels[] = {
        "nt-read-invalid-handle-kernel-iosb-preserved", "nt-write-invalid-handle-kernel-iosb-preserved"
    };
    static const char *kernel_labels[] = {
        "nt-read-kernel-handle-kernel-iosb-preserved", "nt-write-kernel-handle-kernel-iosb-preserved"
    };
    UNICODE_STRING name; OBJECT_ATTRIBUTES attributes; RAW_IO io; IO_STATUS_BLOCK iosb, saved_iosb;
    LARGE_INTEGER offset; NTSTATUS status; ULONG i, j; HANDLE local_disk = NULL;
    volatile UCHAR *previous; UCHAR saved_mode;
    /* Nt pointer checks need a process-local handle; Zw retains the kernel handle. */
    RtlInitUnicodeString(&name,L"\\Device\\Harddisk0\\DR0");
    InitializeObjectAttributes(&attributes,&name,OBJ_CASE_INSENSITIVE,NULL,NULL);
    status = ZwCreateFile(&local_disk,GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &attributes,&iosb,NULL,0,FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
    check(result(status,&iosb,STATUS_SUCCESS,FILE_OPENED) && local_disk != NULL,
        "raw-io-process-local-disk-open");
    if (!NT_SUCCESS(status) || !local_disk) return;
    /* Guest ABI fixed by types_x64.hpp, ntkrnlmp.pdb
     * 8CB8E27C9BCA95EA7FD026E739740C9D1: KTHREAD.PreviousMode is 0x232.
     * Restore before diagnostics or other kernel services, including on exceptions. */
    previous = (volatile UCHAR *)PsGetCurrentThread() + 0x232;
    offset.QuadPart = 0;
    for (i=0; i<RTL_NUMBER_OF(apis); ++i) {
        RtlInitUnicodeString(&name,apis[i]);
        io = (RAW_IO)MmGetSystemRoutineAddress(&name);
        check(io != NULL,"raw-io-api-resolved");
        if (!io) continue;
        for (j=0; j<(i < 2 ? 3u : 1u); ++j) {
            HANDLE target = i >= 2 ? disk : j == 0 ? local_disk : j == 1 ? NULL : disk;
            reset_output();
            RtlFillMemory(&iosb,sizeof(iosb),0xcc); saved_iosb = iosb;
            saved_mode = *previous;
            __try {
                *previous = UserMode;
                status = io(target,NULL,NULL,NULL,&iosb,output.data,512,&offset,NULL);
            } __finally {
                *previous = saved_mode;
            }
            check(untouched(0) && (i < 2 ?
                (status == STATUS_ACCESS_VIOLATION &&
                 RtlCompareMemory(&iosb,&saved_iosb,sizeof(iosb)) == sizeof(iosb)) :
                result(status,&iosb,STATUS_INVALID_DEVICE_REQUEST,0)),
                j == 0 ? labels[i] : j == 1 ? invalid_labels[i] : kernel_labels[i]);
        }
    }
    check(ZwClose(local_disk) == STATUS_SUCCESS,"raw-io-process-local-disk-close");
}
static void pointer_and_io_tests(HANDLE disk)
{
    STORAGE_PROPERTY_QUERY query; IO_STATUS_BLOCK iosb; NTSTATUS status; LARGE_INTEGER offset;
    IO_STATUS_BLOCK saved_iosb; KIRQL old_irql;
    ULONG i; PVOID bad[] = {(PVOID)1,(PVOID)(ULONG_PTR)-1};
    RtlZeroMemory(&query,sizeof(query));
    reset_output();
    RtlFillMemory(&iosb,sizeof(iosb),0xcc);
    status = ZwFsControlFile(disk,NULL,NULL,NULL,&iosb,IOCTL_STORAGE_QUERY_PROPERTY,
        &query,sizeof(query),output.data,descriptor_size);
    check(result(status,&iosb,STATUS_INVALID_DEVICE_REQUEST,0) && untouched(0),
        "fs-control-storage-query-rejected-output-preserved");
    reset_output();
    RtlFillMemory(&iosb,sizeof(iosb),0xcc); saved_iosb = iosb;
    old_irql = KfRaiseIrql(DISPATCH_LEVEL);
    status = ZwDeviceIoControlFile(disk,NULL,NULL,NULL,&iosb,IOCTL_STORAGE_QUERY_PROPERTY,
        &query,sizeof(query),output.data,descriptor_size);
    KeLowerIrql(old_irql);
    check(status == (NTSTATUS)0xc0000184 && untouched(0) &&
        (result(status,&iosb,(NTSTATUS)0xc0000184,0) ||
         RtlCompareMemory(&iosb,&saved_iosb,sizeof(iosb)) == sizeof(iosb)),
        "nonpassive-controlled-invalid-device-state");
    for (i=0;i<RTL_NUMBER_OF(bad);++i) {
        reset_output();
        status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,bad[i],sizeof(query),output.data,descriptor_size,&iosb);
        check(result(status,&iosb,STATUS_ACCESS_VIOLATION,0) && untouched(0),"bad-input-controlled-av");
        status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),bad[i],descriptor_size,&iosb);
        check(result(status,&iosb,STATUS_ACCESS_VIOLATION,0) && untouched(0),"bad-output-controlled-av");
        status = ZwDeviceIoControlFile(disk,NULL,NULL,NULL,(PIO_STATUS_BLOCK)bad[i],IOCTL_STORAGE_QUERY_PROPERTY,
            &query,sizeof(query),output.data,descriptor_size);
        check(status == STATUS_ACCESS_VIOLATION && untouched(0),"bad-iosb-preflight-before-output");
    }
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,NULL,sizeof(query),output.data,descriptor_size,&iosb);
    check((status == STATUS_INVALID_PARAMETER || status == STATUS_ACCESS_VIOLATION) && iosb.Status == status &&
        iosb.Information == 0 && untouched(0),"null-nonzero-input-rejected");
    status = control(disk,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),NULL,descriptor_size,&iosb);
    check((status == STATUS_INVALID_PARAMETER || status == STATUS_ACCESS_VIOLATION) && iosb.Status == status &&
        iosb.Information == 0 && untouched(0),"null-nonzero-output-rejected");
    reset_output();
    RtlFillMemory(&iosb,sizeof(iosb),0xcc);
    status = ZwDeviceIoControlFile(disk,NULL,dummy_apc,NULL,&iosb,IOCTL_STORAGE_QUERY_PROPERTY,
        &query,sizeof(query),output.data,descriptor_size);
    check(result(status,&iosb,STATUS_NOT_SUPPORTED,0) && untouched(0) && !apc_calls,"apc-rejected-before-dispatch");
    reset_output();
    status = ZwDeviceIoControlFile(disk,NULL,NULL,(PVOID)1,&iosb,IOCTL_STORAGE_QUERY_PROPERTY,
        &query,sizeof(query),output.data,descriptor_size);
    check(result(status,&iosb,STATUS_NOT_SUPPORTED,0) && untouched(0),"apc-context-rejected-before-dispatch");
    /* A deliberately invalid nonzero event must be rejected without dereference. */
    reset_output();
    status = ZwDeviceIoControlFile(disk,(HANDLE)1,NULL,NULL,&iosb,IOCTL_STORAGE_QUERY_PROPERTY,
        &query,sizeof(query),output.data,descriptor_size);
    check(result(status,&iosb,STATUS_NOT_SUPPORTED,0) && untouched(0),"event-rejected-before-dispatch");
    offset.QuadPart = 0;
    reset_output();
    RtlFillMemory(&iosb,sizeof(iosb),0xcc);
    status = ZwReadFile(disk,NULL,NULL,NULL,&iosb,output.data,512,&offset,NULL);
    check(result(status,&iosb,STATUS_INVALID_DEVICE_REQUEST,0) && untouched(0),"raw-read-no-blocks");
    reset_output();
    RtlFillMemory(&iosb,sizeof(iosb),0xcc);
    status = ZwWriteFile(disk,NULL,NULL,NULL,&iosb,output.data,512,&offset,NULL);
    check(result(status,&iosb,STATUS_INVALID_DEVICE_REQUEST,0) && untouched(0),"raw-write-no-blocks");
    previous_mode_io_tests(disk);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    static const WCHAR *paths[] = {L"\\Device\\Harddisk0\\DR0",L"\\??\\PhysicalDrive0",L"\\DosDevices\\PhysicalDrive0",L"\\Device\\Harddisk0\\DR0"};
    WCHAR native[] = L"\\Device\\Harddisk0\\DR0";
    WCHAR alias[] = L"\\??\\PhysicalDrive0";
    WCHAR dos[] = L"\\DosDevices\\PhysicalDrive0";
    ULONG i, pass; HANDLE disk, duplicate; BOOLEAN first = TRUE; NTSTATUS status;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(registry);
    for (i=0;i<RTL_NUMBER_OF(paths);++i) {
        disk = open_disk(paths[i],FILE_OPEN,TRUE);
        if (!disk) continue;
        if (!query_descriptor(disk)) {
            check(ZwClose(disk) == STATUS_SUCCESS,"baseline-disk-close");
            goto done;
        }
        exercise_ata(disk,first); if (first) pointer_and_io_tests(disk);
        first = FALSE;
        /* Repeat while the same handle is live, then verify again after reopening. */
        query_descriptor(disk);
        duplicate = NULL;
        status = ZwDuplicateObject((HANDLE)(LONG_PTR)-1,disk,(HANDLE)(LONG_PTR)-1,
            &duplicate,0,0,DUPLICATE_SAME_ACCESS);
        check(status == STATUS_SUCCESS && duplicate != NULL && duplicate != disk,
            "duplicate-builtin-disk-same-access");
        check(ZwClose(disk) == STATUS_SUCCESS,"disk-close");
        if (status == STATUS_SUCCESS && duplicate != NULL && duplicate != disk) {
            check(query_descriptor(duplicate),"duplicate-survives-original-close");
            check(ZwClose(duplicate) == STATUS_SUCCESS,"duplicate-disk-close");
        }
    }
    for (i=1;i<=5;++i) {
        native[16] = (WCHAR)(L'0'+i); alias[17] = (WCHAR)(L'0'+i); dos[25] = (WCHAR)(L'0'+i);
        for (pass=0;pass<2;++pass) {
            ULONG disposition = pass ? FILE_OPEN_IF : FILE_OPEN;
            open_disk(native,disposition,FALSE); open_disk(alias,disposition,FALSE); open_disk(dos,disposition,FALSE);
        }
    }
done:
    DbgPrint("CONFORMANCE RESULT failures=%ld\n",failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
