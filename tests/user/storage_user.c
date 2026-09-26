/* Emulator guest only. Never execute this native image on the host. */
#include <windows.h>
#include <winternl.h>
#include <ntddstor.h>
#include <ntddscsi.h>
#include <intrin.h>

NTSYSAPI NTSTATUS NTAPI ZwCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI ZwDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE,
    PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR,
    PSIZE_T, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

extern unsigned int ob_user_cpl(void);

typedef NTSTATUS (NTAPI *CREATE_FILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *DEVICE_CONTROL)(HANDLE, HANDLE, PIO_APC_ROUTINE,
    PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

typedef char assert_query_size[(sizeof(STORAGE_PROPERTY_QUERY) == 12) ? 1 : -1];
typedef char assert_descriptor_header[(sizeof(STORAGE_DESCRIPTOR_HEADER) == 8) ? 1 : -1];
typedef char assert_descriptor_size[(sizeof(STORAGE_DEVICE_DESCRIPTOR) == 40) ? 1 : -1];
typedef char assert_ata_size[(sizeof(ATA_PASS_THROUGH_EX) == 48) ? 1 : -1];

#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034L)
#define KERNEL_ADDRESS ((ULONG_PTR)0xffff800000000000ui64)
#define IOCTL_QUERY_PROPERTY 0x002d1400u
#define RESPONSE_SIZE 65537u
#define RESPONSE_ALLOCATION_FAILURE 0xc0560000u
#define RESPONSE_RELEASE_FAILURE 0xc0570000u

static ULONG_PTR saved_teb, saved_pid, saved_tid;
static ULONG stage, control_calls;
typedef struct {
    ULONGLONG before;
    UCHAR bytes[RESPONSE_SIZE];
    ULONGLONG after;
} RESPONSE_BUFFER;
static RESPONSE_BUFFER *response;
static const ULONGLONG guard = 0x1234567887654321ui64;
static const WCHAR disk_name[] = L"\\??\\PhysicalDrive0";
static const WCHAR missing_name[] = L"\\??\\PhysicalDrive1";

__declspec(noreturn) static void finish(ULONG status)
{
    NtTerminateProcess((HANDLE)(LONG_PTR)-1, (NTSTATUS)status);
    for (;;) {}
}

static void restored(void)
{
    if (ob_user_cpl() != 3 || __readgsqword(0x30) != saved_teb ||
        __readgsqword(0x40) != saved_pid || __readgsqword(0x48) != saved_tid)
        finish(0xc0510000u + stage);
}

static void allocate_response(void)
{
    PVOID base = NULL;
    SIZE_T size = sizeof(*response);
    NTSTATUS status = NtAllocateVirtualMemory((HANDLE)(LONG_PTR)-1, &base, 0,
        &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!NT_SUCCESS(status))
        finish(RESPONSE_ALLOCATION_FAILURE | ((ULONG)status & 0xffffu));
    if (!base || size < sizeof(*response))
        finish(RESPONSE_ALLOCATION_FAILURE);
    response = (RESPONSE_BUFFER *)base;
}

static void release_response(void)
{
    PVOID base = response;
    SIZE_T size = 0;
    NTSTATUS status;

    status = NtFreeVirtualMemory((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RELEASE);
    if (!NT_SUCCESS(status))
        finish(RESPONSE_RELEASE_FAILURE | ((ULONG)status & 0xffffu));
    response = NULL;
}

static void reset_response(void)
{
    response->before = response->after = guard;
    __stosb(response->bytes, 0xa5, RESPONSE_SIZE);
}

static int response_filled(ULONG start, UCHAR value)
{
    ULONG i;
    if (start > RESPONSE_SIZE || response->before != guard || response->after != guard)
        return 0;
    for (i = start; i < RESPONSE_SIZE; ++i)
        if (response->bytes[i] != value) return 0;
    return 1;
}

static void expect_response(int valid, ULONG start, UCHAR value)
{
    if (valid != response_filled(start, value)) finish(0xc0530000u + stage);
}

static void init_iosb(PIO_STATUS_BLOCK iosb)
{
    iosb->Status = (NTSTATUS)0xcccccccc;
    iosb->Information = (ULONG_PTR)0xccccccccccccccccui64;
}

static USHORT wide_length(PCWSTR text)
{
    USHORT length = 0;
    while (text[length]) ++length;
    return length;
}

static void expect_status(NTSTATUS returned, const IO_STATUS_BLOCK *iosb,
    NTSTATUS expected, ULONG_PTR information)
{
    if (returned != expected || iosb->Status != expected ||
        iosb->Information != information)
        finish(0xc0520000u + stage);
}

static NTSTATUS open_call(CREATE_FILE create, PCWSTR path, ULONG disposition,
    ACCESS_MASK access, NTSTATUS expected, HANDLE *opened)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status;

    name.Buffer = (PWSTR)path;
    name.Length = (USHORT)(wide_length(path) * sizeof(WCHAR));
    name.MaximumLength = (USHORT)(name.Length + sizeof(WCHAR));
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    init_iosb(&iosb);
    ++stage;
    status = create(&handle, access, &attributes, &iosb, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, disposition,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    restored();
    if (status != expected || iosb.Status != expected)
        finish(0xc0520000u + stage);
    if (expected == 0) {
        if (!handle || iosb.Information != FILE_OPENED)
            finish(0xc0540000u + stage);
    } else if (handle || iosb.Information != 0) {
        finish(0xc0540000u + stage);
    }
    *opened = handle;
    return status;
}

static void close_call(HANDLE handle)
{
    NTSTATUS status;
    ++stage;
    status = NtClose(handle);
    restored();
    if (status != 0) finish(0xc0520000u + stage);
}

static NTSTATUS control_call(DEVICE_CONTROL control, HANDLE handle,
    PIO_STATUS_BLOCK iosb, ULONG code, PVOID input, ULONG input_length,
    PVOID output, ULONG output_length)
{
    NTSTATUS status;
    ++stage;
    ++control_calls;
    status = control(handle, NULL, NULL, NULL, iosb, code,
        input, input_length, output, output_length);
    restored();
    return status;
}

static void expect_control(NTSTATUS returned, const IO_STATUS_BLOCK *iosb,
    NTSTATUS expected, ULONG_PTR information)
{
    expect_status(returned, iosb, expected, information);
}

static void property_query(STORAGE_PROPERTY_QUERY *query)
{
    __stosb((UCHAR *)query, 0, sizeof(*query));
    query->PropertyId = StorageDeviceProperty;
    query->QueryType = PropertyStandardQuery;
}

static void ata_request(ATA_PASS_THROUGH_EX *request)
{
    __stosb((UCHAR *)request, 0, sizeof(*request));
    request->Length = sizeof(*request);
    request->AtaFlags = ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN;
    request->DataTransferLength = 512;
    request->TimeOutValue = 5;
    request->DataBufferOffset = sizeof(*request);
    request->CurrentTaskFile[6] = 0xec;
}

static int same_bytes(const UCHAR *left, const UCHAR *right, ULONG length)
{
    ULONG i;
    for (i = 0; i < length; ++i)
        if (left[i] != right[i]) return 0;
    return 1;
}

static void property_probe(HANDLE handle, DEVICE_CONTROL control)
{
    STORAGE_PROPERTY_QUERY query;
    IO_STATUS_BLOCK iosb;
    STORAGE_DESCRIPTOR_HEADER *header;
    NTSTATUS status;

    property_query(&query);
    reset_response();
    init_iosb(&iosb);
    status = control_call(control, handle, &iosb, IOCTL_QUERY_PROPERTY,
        &query, sizeof(query), response->bytes, sizeof(*header));
    expect_control(status, &iosb, 0, sizeof(*header));
    header = (STORAGE_DESCRIPTOR_HEADER *)response->bytes;
    if (header->Version != sizeof(STORAGE_DEVICE_DESCRIPTOR) || header->Size < 40)
        finish(0xc0540000u + stage);
    expect_response(1, sizeof(*header), 0xa5);
}

static void full_property_query(HANDLE handle, DEVICE_CONTROL control)
{
    STORAGE_PROPERTY_QUERY query;
    IO_STATUS_BLOCK iosb;
    STORAGE_DEVICE_DESCRIPTOR *descriptor;
    NTSTATUS status;

    property_query(&query);
    reset_response();
    init_iosb(&iosb);
    status = control_call(control, handle, &iosb, IOCTL_QUERY_PROPERTY,
        &query, sizeof(query), response->bytes, 512);
    descriptor = (STORAGE_DEVICE_DESCRIPTOR *)response->bytes;
    if (status != 0 || iosb.Status != 0 || descriptor->Version != 40 ||
        descriptor->Size < 40 || descriptor->Size > 512 ||
        iosb.Information != descriptor->Size)
        finish(0xc0540000u + stage);
    expect_response(1, descriptor->Size, 0xa5);
}

static void denied_ata(HANDLE handle, DEVICE_CONTROL control)
{
    ATA_PASS_THROUGH_EX request;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    ata_request(&request);
    reset_response();
    for (ULONG i = 0; i < sizeof(request); ++i)
        response->bytes[i] = ((const UCHAR *)&request)[i];
    init_iosb(&iosb);
    status = control_call(control, handle, &iosb, IOCTL_ATA_PASS_THROUGH,
        response->bytes, sizeof(request), response->bytes, 560);
    expect_control(status, &iosb, STATUS_ACCESS_DENIED, 0);
    if (!same_bytes(response->bytes, (const UCHAR *)&request, sizeof(request)))
        finish(0xc0530000u + stage);
    expect_response(1, sizeof(request), 0xa5);
}

static void invalid_control_pointers(HANDLE handle)
{
    STORAGE_PROPERTY_QUERY query;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    PVOID bad[2] = {(PVOID)(ULONG_PTR)1, (PVOID)KERNEL_ADDRESS};
    ULONG i;

    property_query(&query);
    for (i = 0; i < 2; ++i) {
        reset_response();
        init_iosb(&iosb);
        status = control_call(i ? ZwDeviceIoControlFile : NtDeviceIoControlFile,
            handle, &iosb, IOCTL_QUERY_PROPERTY, bad[i], sizeof(query),
            response->bytes, 8);
        expect_control(status, &iosb, STATUS_ACCESS_VIOLATION, 0);
        expect_response(1, 0, 0xa5);

        reset_response();
        init_iosb(&iosb);
        status = control_call(i ? ZwDeviceIoControlFile : NtDeviceIoControlFile,
            handle, &iosb, IOCTL_QUERY_PROPERTY, &query, sizeof(query),
            bad[i], 8);
        expect_control(status, &iosb, STATUS_ACCESS_VIOLATION, 0);
        expect_response(1, 0, 0xa5);

        reset_response();
        status = control_call(i ? ZwDeviceIoControlFile : NtDeviceIoControlFile,
            handle, (PIO_STATUS_BLOCK)bad[i], IOCTL_QUERY_PROPERTY, &query,
            sizeof(query), response->bytes, 8);
        if (status != STATUS_ACCESS_VIOLATION)
            finish(0xc0520000u + stage);
        expect_response(1, 0, 0xa5);
    }
}

static void overlap_and_limit(HANDLE handle)
{
    STORAGE_PROPERTY_QUERY query;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    property_query(&query);
    init_iosb(&iosb);
    status = control_call(NtDeviceIoControlFile, handle, &iosb,
        IOCTL_QUERY_PROPERTY, &query, sizeof(query), &iosb, sizeof(ULONG));
    if (status != STATUS_INVALID_PARAMETER || iosb.Status != (NTSTATUS)0xcccccccc ||
        iosb.Information != (ULONG_PTR)0xccccccccccccccccui64)
        finish(0xc0530000u + stage);

    reset_response();
    init_iosb(&iosb);
    status = control_call(NtDeviceIoControlFile, handle, &iosb,
        IOCTL_QUERY_PROPERTY, &query, sizeof(query), response->bytes,
        RESPONSE_SIZE);
    expect_control(status, &iosb, STATUS_INVALID_PARAMETER, 0);
    expect_response(1, 0, 0xa5);

    /* A null IOSB must be rejected before the method-buffered output is committed. */
    reset_response();
    status = control_call(NtDeviceIoControlFile, handle, NULL,
        IOCTL_QUERY_PROPERTY, &query, sizeof(query), response->bytes, 8);
    if (status != STATUS_ACCESS_VIOLATION)
        finish(0xc0520000u + stage);
    expect_response(1, 0, 0xa5);
}

static void valid_ata(HANDLE handle, DEVICE_CONTROL control)
{
    ATA_PASS_THROUGH_EX request;
    ATA_PASS_THROUGH_EX *result;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    UCHAR sum = 0;
    ULONG i;

    ata_request(&request);
    reset_response();
    for (i = 0; i < sizeof(request); ++i)
        response->bytes[i] = ((const UCHAR *)&request)[i];
    init_iosb(&iosb);
    status = control_call(control, handle, &iosb, IOCTL_ATA_PASS_THROUGH,
        response->bytes, sizeof(request), response->bytes, 560);
    expect_control(status, &iosb, 0, 560);
    result = (ATA_PASS_THROUGH_EX *)response->bytes;
    if (result->Length != 48 || result->DataTransferLength != 512 ||
        result->DataBufferOffset != 48 || result->CurrentTaskFile[0] != 0 ||
        result->CurrentTaskFile[6] != 0x50 || response->bytes[48 + 510] != 0xa5)
        finish(0xc0540000u + stage);
    for (i = 48; i < 560; ++i) sum = (UCHAR)(sum + response->bytes[i]);
    if (sum != 0) finish(0xc0540000u + stage);
    expect_response(1, 560, 0xa5);
}

void NTAPI entry(void)
{
    HANDLE disk = NULL;
    ACCESS_MASK open_access = SYNCHRONIZE;

    saved_teb = __readgsqword(0x30);
    saved_pid = __readgsqword(0x40);
    saved_tid = __readgsqword(0x48);
    restored();
    if (!saved_teb || !saved_pid || saved_pid == 4 || !saved_tid)
        finish(0xc0510000u);
    allocate_response();

    open_call(NtCreateFile, missing_name, FILE_OPEN, open_access,
        STATUS_OBJECT_NAME_NOT_FOUND, &disk);
    open_call(ZwCreateFile, missing_name, FILE_OPEN_IF, open_access,
        STATUS_OBJECT_NAME_NOT_FOUND, &disk);
    open_call(NtCreateFile, disk_name, FILE_OPEN, open_access, 0, &disk);

    property_probe(disk, NtDeviceIoControlFile);
    full_property_query(disk, ZwDeviceIoControlFile);
    denied_ata(disk, NtDeviceIoControlFile);
    denied_ata(disk, ZwDeviceIoControlFile);
    invalid_control_pointers(disk);
    overlap_and_limit(disk);
    close_call(disk);

    open_call(ZwCreateFile, disk_name, FILE_OPEN,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, &disk);
    valid_ata(disk, NtDeviceIoControlFile);
    valid_ata(disk, ZwDeviceIoControlFile);
    close_call(disk);

    if (control_calls != 15) finish(0xc0550000u + stage);
    release_response();
    finish(0);
}
