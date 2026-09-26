#include <ntifs.h>

/* Guest only: actual CI exports and actual guest files, never a host driver. */
typedef struct { ULONG size; PVOID data; } CI_BLOB;
typedef struct { PCHAR data; USHORT size, unknown; } CI_NAME;
typedef struct {
    ULONG algorithm, hash_size; UCHAR hash[64];
    CI_NAME subject, issuer; CI_BLOB certificate;
} CI_ELEMENT;
typedef struct {
    ULONG size; CI_BLOB *keys; ULONG key_count; CI_BLOB *ekus; ULONG eku_count;
    CI_ELEMENT *elements; ULONG element_count, unknown; CI_BLOB attributes;
} CI_CHAIN;
typedef struct {
    ULONG size; NTSTATUS status; ULONG bits, padding; CI_CHAIN *chain;
    LARGE_INTEGER revoked, from, to;
} CI_POLICY;
C_ASSERT(sizeof(CI_POLICY) == 48);
C_ASSERT(sizeof(CI_CHAIN) == 72);
C_ASSERT(sizeof(CI_ELEMENT) == 120);
__declspec(dllimport) NTSTATUS CiCheckSignedFile(PVOID, ULONG, ULONG, PVOID, ULONG,
    CI_POLICY*, LARGE_INTEGER*, CI_POLICY*);
__declspec(dllimport) VOID CiFreePolicyInfo(CI_POLICY*);
__declspec(dllimport) NTSTATUS CiVerifyHashInCatalog(PVOID, ULONG, ULONG, ULONG, ULONG, ULONG,
    CI_POLICY*, UNICODE_STRING*, LARGE_INTEGER*, CI_POLICY*);
__declspec(dllimport) NTSTATUS CiValidateFileObject(PVOID, ULONG, UCHAR, CI_POLICY*, CI_POLICY*,
    LARGE_INTEGER*, PVOID, ULONG*, ULONG*);
static LONG failures;
static void check(BOOLEAN ok, const char *label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}
static BOOLEAN chain_ok(const CI_POLICY *p)
{
    const CI_CHAIN *c = p->chain;
    ULONG i;
    if (p->size != 48 || p->status != STATUS_SUCCESS || !c || c->size != 72 ||
        !c->elements || c->element_count < 1 || c->element_count > 32 ||
        p->from.QuadPart <= 0 || p->to.QuadPart <= p->from.QuadPart) return FALSE;
    for (i = 0; i < c->element_count; ++i) {
        const CI_ELEMENT *e = &c->elements[i];
        if (e->algorithm != 0x800c || e->hash_size != 32 || !e->certificate.data ||
            e->certificate.size < 64 || ((PUCHAR)e->certificate.data)[0] != 0x30 ||
            !e->subject.data || !e->subject.size) return FALSE;
    }
    return TRUE;
}
static void clear_policies(CI_POLICY *p, CI_POLICY *t)
{
    CI_POLICY zero = {0};
    CiFreePolicyInfo(p); CiFreePolicyInfo(t);
    check(RtlCompareMemory(p, &zero, sizeof(zero)) == sizeof(zero) &&
        RtlCompareMemory(t, &zero, sizeof(zero)) == sizeof(zero), "owned-policy-cleared");
    CiFreePolicyInfo(p); CiFreePolicyInfo(t);
}
static NTSTATUS open_file(PCWSTR path, PHANDLE handle)
{
    UNICODE_STRING name; OBJECT_ATTRIBUTES attributes; IO_STATUS_BLOCK iosb;
    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwOpenFile(handle, FILE_READ_DATA | SYNCHRONIZE, &attributes, &iosb,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
}
static PUCHAR read_file(HANDLE handle, PULONG length)
{
    FILE_STANDARD_INFORMATION info; IO_STATUS_BLOCK iosb; LARGE_INTEGER offset;
    PUCHAR bytes;
    if (!NT_SUCCESS(ZwQueryInformationFile(handle, &iosb, &info, sizeof(info), FileStandardInformation)) ||
        info.EndOfFile.QuadPart <= 0 || info.EndOfFile.QuadPart > 32 * 1024 * 1024) return NULL;
    *length = (ULONG)info.EndOfFile.QuadPart;
    bytes = ExAllocatePoolWithTag(NonPagedPoolNx, *length, 'tViC');
    if (!bytes) return NULL;
    offset.QuadPart = 0;
    if (!NT_SUCCESS(ZwReadFile(handle, NULL, NULL, NULL, &iosb, bytes, *length, &offset, NULL)) ||
        iosb.Information != *length) { ExFreePool(bytes); return NULL; }
    return bytes;
}
static void signed_file(PCWSTR path)
{
    HANDLE handle = NULL; PVOID object = NULL; CI_POLICY p = {0}, t = {0};
    LARGE_INTEGER time; UCHAR digest[64], changed[64]; ULONG size = sizeof(digest), alg = 0;
    ULONG length = 0, pe, offset, cert_size; PUCHAR bytes = NULL; NTSTATUS status;
    status = open_file(path, &handle);
    check(NT_SUCCESS(status) && handle, "open-signed-system-file");
    if (!NT_SUCCESS(status) || !handle) return;
    status = ObReferenceObjectByHandle(handle, 0, *IoFileObjectType, KernelMode, &object, NULL);
    check(NT_SUCCESS(status) && object, "reference-signed-system-file");
    if (!NT_SUCCESS(status) || !object) goto done;
    status = CiValidateFileObject(object, 0, 0, &p, &t, &time, digest, &size, &alg);
    check(status == STATUS_SUCCESS && size == 32 && alg == 0x800c, "file-object-authenticode-verified");
    check(chain_ok(&p), "file-object-owned-chain");
    check(time.QuadPart > 0 && chain_ok(&t), "file-object-authenticated-timestamp");
    clear_policies(&p, &t);
    if (status != STATUS_SUCCESS || size != 32 || alg != 0x800c) goto done;
    bytes = read_file(handle, &length);
    check(bytes && length > 512, "read-signed-system-snapshot");
    if (!bytes || length < 512) goto done;
    pe = *(UNALIGNED ULONG*)(bytes + 60);
    if (pe > length - 176) { check(FALSE, "bounded-pe-header"); goto done; }
    offset = *(UNALIGNED ULONG*)(bytes + pe + 24 + 144);
    cert_size = *(UNALIGNED ULONG*)(bytes + pe + 24 + 148);
    check(offset <= length && cert_size >= 8 && cert_size <= length - offset, "bounded-security-directory");
    if (offset > length || cert_size < 8 || cert_size > length - offset) goto done;
    status = CiCheckSignedFile(digest, size, alg, bytes + offset, cert_size, &p, &time, &t);
    check(status == STATUS_SUCCESS && chain_ok(&p), "signed-digest-and-signature-verified");
    check(time.QuadPart > 0 && chain_ok(&t), "signed-digest-timestamp-verified");
    if (status == STATUS_SUCCESS) {
        CI_POLICY copy = p;
        CiFreePolicyInfo(&copy);
        check(!copy.chain && copy.size == 0 && chain_ok(&p), "copied-policy-cannot-free-owner");
    }
    clear_policies(&p, &t);
    RtlCopyMemory(changed, digest, size); changed[0] ^= 1;
    status = CiCheckSignedFile(changed, size, alg, bytes + offset, cert_size, &p, &time, &t);
    check(status == STATUS_INVALID_IMAGE_HASH && p.status == status && !p.chain && !time.QuadPart,
        "changed-digest-rejected");
    clear_policies(&p, &t);
    status = CiCheckSignedFile(digest, 20, 0x8004, bytes + offset, cert_size, &p, &time, &t);
    check(status == STATUS_INVALID_IMAGE_HASH && !p.chain, "different-algorithm-not-falsely-trusted");
    clear_policies(&p, &t);
    status = CiCheckSignedFile(digest, size, alg, bytes + offset, 7, &p, &time, &t);
    check(!NT_SUCCESS(status) && !p.chain, "truncated-certificate-rejected");
    clear_policies(&p, &t);
    RtlFillMemory(changed, sizeof(changed), 0x5a); size = 1; alg = 0;
    status = CiValidateFileObject(object, 0, 0, &p, &t, &time, changed, &size, &alg);
    check(status == STATUS_BUFFER_TOO_SMALL && size == 32 && changed[0] == 0x5a && !p.chain,
        "digest-capacity-checked-before-output");
    clear_policies(&p, &t);
done:
    if (bytes) ExFreePool(bytes);
    if (object) ObDereferenceObject(object);
    check(NT_SUCCESS(ZwClose(handle)), "close-signed-system-file");
}
static void catalog_case(void)
{
    HANDLE handle = NULL; PUCHAR input = NULL; ULONG length = 0, alg, size;
    CI_POLICY p = {0}, t = {0}; LARGE_INTEGER time; UNICODE_STRING name = {0}; NTSTATUS status;
    status = open_file(L"\\??\\C:\\ci_catalog_input.bin", &handle);
    check(NT_SUCCESS(status) && handle, "open-catalog-evidence");
    if (!NT_SUCCESS(status) || !handle) return;
    input = read_file(handle, &length); ZwClose(handle);
    check(input && length >= 28 && length <= 72, "read-catalog-evidence");
    if (!input || length < 28 || length > 72) goto done;
    alg = *(UNALIGNED ULONG*)input; size = *(UNALIGNED ULONG*)(input + 4);
    if (size != length - 8) { check(FALSE, "catalog-evidence-size"); goto done; }
    status = CiVerifyHashInCatalog(input + 8, size, alg, 1, 0, 0, &p, &name, &time, &t);
    check(status == STATUS_SUCCESS && chain_ok(&p), "catalog-membership-and-trust-verified");
    check(name.Buffer && name.Length > 0 && name.Length <= name.MaximumLength, "catalog-name-owned-output");
    if (name.Buffer) ExFreePool(name.Buffer);
    clear_policies(&p, &t);
    RtlZeroMemory(&name, sizeof(name)); input[8] ^= 1;
    status = CiVerifyHashInCatalog(input + 8, size, alg, 0, 0, 0, &p, &name, &time, &t);
    check(status == STATUS_INVALID_IMAGE_HASH && !p.chain && !name.Buffer, "absent-catalog-member-rejected");
    clear_policies(&p, &t);
done:
    if (input) ExFreePool(input);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    signed_file(L"\\SystemRoot\\System32\\ntoskrnl.exe");
    signed_file(L"\\SystemRoot\\System32\\drivers\\fltmgr.sys");
    catalog_case();
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
