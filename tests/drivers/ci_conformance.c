#include <ntifs.h>

/* Guest-only modern x64 CI ABI checks with malformed and unsigned inputs. */
typedef struct {
    ULONG size;
    NTSTATUS status;
    ULONG bits;
    ULONG padding;
    PVOID chain;
    LARGE_INTEGER revoked, from, to;
} CI_POLICY;
C_ASSERT(sizeof(CI_POLICY) == 48);
C_ASSERT(FIELD_OFFSET(CI_POLICY, chain) == 16);
C_ASSERT(FIELD_OFFSET(CI_POLICY, to) == 40);

/* The ellipsis deliberately places poison beyond the eight real arguments. */
__declspec(dllimport) NTSTATUS CiCheckSignedFile(PVOID, ULONG, ULONG, PVOID,
    ULONG, CI_POLICY*, LARGE_INTEGER*, CI_POLICY*, ...);
__declspec(dllimport) VOID CiFreePolicyInfo(CI_POLICY*);
__declspec(dllimport) NTSTATUS CiVerifyHashInCatalog(PVOID, ULONG, ULONG, ULONG,
    ULONG, ULONG, CI_POLICY*, UNICODE_STRING*, LARGE_INTEGER*, CI_POLICY*);
__declspec(dllimport) NTSTATUS CiValidateFileObject(PVOID, ULONG, UCHAR,
    CI_POLICY*, CI_POLICY*, LARGE_INTEGER*, PVOID, ULONG*, ULONG*);

#define GUARD 0x123456789abcdef0ULL
typedef struct { ULONGLONG before; CI_POLICY policy; ULONGLONG after; } GUARDED_POLICY;
typedef struct { ULONGLONG before; LARGE_INTEGER time; ULONGLONG after; } GUARDED_TIME;
static LONG failures;
static UCHAR hash[64], signature[16];

static void check(BOOLEAN ok, const char* name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}
static BOOLEAN bytes_are(const void* pointer, SIZE_T size, UCHAR value)
{
    const UCHAR* bytes = (const UCHAR*)pointer;
    SIZE_T index;
    for (index = 0; index < size; ++index) if (bytes[index] != value) return FALSE;
    return TRUE;
}
static void prepare(GUARDED_POLICY* info)
{
    info->before = info->after = GUARD;
    RtlFillMemory(&info->policy, sizeof(info->policy), 0xa5);
}
static BOOLEAN policy_is(const GUARDED_POLICY* info, NTSTATUS status)
{
    const CI_POLICY* p = &info->policy;
    return info->before == GUARD && info->after == GUARD && p->size == 48 &&
        p->status == status && p->bits == 0 && p->padding == 0 && p->chain == NULL &&
        p->revoked.QuadPart == 0 && p->from.QuadPart == 0 && p->to.QuadPart == 0;
}
static void signed_case(ULONG size, ULONG algorithm, PVOID poison)
{
    GUARDED_POLICY signer, timestamp;
    GUARDED_TIME time;
    NTSTATUS status;
    prepare(&signer); prepare(&timestamp);
    time.before = time.after = GUARD; time.time.QuadPart = -1;
    status = CiCheckSignedFile(hash, size, algorithm, signature, sizeof(signature),
        &signer.policy, &time.time, &timestamp.policy, poison);
    check(status == STATUS_INVALID_IMAGE_HASH, "signed-file-negative-status");
    check(policy_is(&signer, status), "signer-policy-layout-and-guards");
    check(policy_is(&timestamp, status), "timestamp-policy-layout-and-guards");
    check(time.before == GUARD && time.after == GUARD && time.time.QuadPart == 0,
        "signing-time-and-guards");
    CiFreePolicyInfo(&signer.policy); CiFreePolicyInfo(&timestamp.policy);
    check(bytes_are(&signer.policy, 48, 0) && bytes_are(&timestamp.policy, 48, 0),
        "free-clears-full-policies");
    CiFreePolicyInfo(&signer.policy); CiFreePolicyInfo(&timestamp.policy);
    check(signer.before == GUARD && signer.after == GUARD && timestamp.before == GUARD &&
        timestamp.after == GUARD && bytes_are(&signer.policy, 48, 0) &&
        bytes_are(&timestamp.policy, 48, 0), "repeat-free-preserves-guards");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    static const ULONG sizes[] = {20, 32, 48, 64};
    static const ULONG algorithms[] = {0x8004, 0x800c, 0x800d, 0x800e};
    ULONG index, ninth = 0xcafebabe, digest_size, digest_algorithm;
    GUARDED_POLICY signer, timestamp;
    LARGE_INTEGER time;
    UNICODE_STRING catalog;
    UCHAR digest[64];
    NTSTATUS status;
    HANDLE file = NULL;
    PVOID file_object = NULL;
    UNICODE_STRING filename;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);

    for (index = 0; index < RTL_NUMBER_OF(sizes); ++index) {
        ninth = 0xcafebabe;
        signed_case(sizes[index], algorithms[index], &ninth);
        check(ninth == 0xcafebabe, "unused-ninth-mapped-canary-untouched");
    }
    signed_case(32, 0x800c, (PVOID)1);
    signed_case(32, 0x800c, NULL);
    check(CiCheckSignedFile(hash, 32, 0x800c, signature, sizeof(signature),
        NULL, NULL, NULL, (PVOID)1) == STATUS_INVALID_IMAGE_HASH, "optional-null-outputs");
    CiFreePolicyInfo(NULL);

    prepare(&signer); prepare(&timestamp); time.QuadPart = -1;
    RtlFillMemory(&catalog, sizeof(catalog), 0xa5);
    status = CiVerifyHashInCatalog(hash, 32, 0x800c, 0, 0, 0,
        &signer.policy, &catalog, &time, &timestamp.policy);
    check(status == STATUS_INVALID_IMAGE_HASH && policy_is(&signer, status) &&
        policy_is(&timestamp, status), "catalog-policy-argument-positions");
    check(time.QuadPart == 0 && bytes_are(&catalog, sizeof(catalog), 0),
        "catalog-name-and-time-empty");

    prepare(&signer); prepare(&timestamp); time.QuadPart = -1;
    RtlFillMemory(digest, sizeof(digest), 0x5a);
    digest_size = sizeof(digest); digest_algorithm = 0xdeadbeef;
    status = CiValidateFileObject(NULL, 0, 0, &signer.policy, &timestamp.policy,
        &time, digest, &digest_size, &digest_algorithm);
    check(status == STATUS_INVALID_PARAMETER && policy_is(&signer, status) &&
        policy_is(&timestamp, status), "invalid-file-matching-failure-policies");
    check(time.QuadPart == 0 && digest_size == 0 && digest_algorithm == 0 &&
        bytes_are(digest, sizeof(digest), 0x5a), "no-fabricated-file-digest");

    RtlInitUnicodeString(&filename, L"\\??\\C:\\ci_conformance.sys");
    InitializeObjectAttributes(&attributes, &filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);
    status = ZwOpenFile(&file, FILE_READ_DATA | SYNCHRONIZE, &attributes, &iosb,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    check(NT_SUCCESS(status) && file, "open-file-validation-input");
    if (NT_SUCCESS(status) && file) {
        status = ObReferenceObjectByHandle(file, 0, *IoFileObjectType, KernelMode,
            &file_object, NULL);
        check(NT_SUCCESS(status) && file_object, "reference-file-validation-input");
        if (NT_SUCCESS(status) && file_object) {
            prepare(&signer); prepare(&timestamp); time.QuadPart = -1;
            digest_size = sizeof(digest); digest_algorithm = 0xdeadbeef;
            status = CiValidateFileObject(file_object, 0, 0, &signer.policy, &timestamp.policy,
                &time, digest, &digest_size, &digest_algorithm);
            check(status == STATUS_INVALID_IMAGE_HASH && policy_is(&signer, status) &&
                policy_is(&timestamp, status), "unsigned-file-untrusted-status");
            check(time.QuadPart == 0 && digest_size == 0 && digest_algorithm == 0 &&
                bytes_are(digest, sizeof(digest), 0x5a), "valid-file-no-raw-hash-substitution");
            ObDereferenceObject(file_object);
        }
        check(NT_SUCCESS(ZwClose(file)), "close-file-validation-input");
    }

    prepare(&signer); time.QuadPart = -1;
    status = CiCheckSignedFile(hash, 32, 0x800c, signature, sizeof(signature),
        &signer.policy, &time, (CI_POLICY*)1, NULL);
    check(status == STATUS_ACCESS_VIOLATION && time.QuadPart == -1 &&
        bytes_are(&signer.policy, 48, 0xa5) && signer.before == GUARD && signer.after == GUARD,
        "bad-final-output-preflight-prevents-earlier-writes");
    status = CiCheckSignedFile(hash, 32, 0x800c, signature, sizeof(signature),
        &signer.policy, &time, (CI_POLICY*)(ULONG_PTR)(~(ULONG_PTR)0 - 7), NULL);
    check(status == STATUS_ACCESS_VIOLATION && time.QuadPart == -1 &&
        bytes_are(&signer.policy, 48, 0xa5), "overflow-output-preflight");
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
