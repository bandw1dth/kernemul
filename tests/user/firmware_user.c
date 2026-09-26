/* Emulator guest only. Never execute this native image on the host. */
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
typedef NTSTATUS (NTAPI *QUERY)(PUNICODE_STRING, GUID *, PVOID, PULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(PUNICODE_STRING, GUID *, PVOID, PULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemEnvironmentValueEx(PUNICODE_STRING, GUID *, PVOID, PULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
extern unsigned int ob_user_cpl(void);
static ULONG_PTR saved_teb, saved_pid, saved_tid;
static ULONG stage;
static GUID vendor = {0x8be4df61,0x93ca,0x11d2,{0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c}};
#define DENIED ((NTSTATUS)0xc0000061)
#define INVALID ((NTSTATUS)0xc000000d)
#define ACCESS ((NTSTATUS)0xc0000005)
#define KERNEL ((ULONG_PTR)0xffff800000000000ui64)
__declspec(noreturn) static void finish(ULONG status)
{
    NtTerminateProcess((HANDLE)(LONG_PTR)-1, (NTSTATUS)status);
    for (;;) {}
}
static void restored(void)
{
    if (ob_user_cpl() != 3 || __readgsqword(0x30) != saved_teb ||
        __readgsqword(0x40) != saved_pid || __readgsqword(0x48) != saved_tid)
        finish(0xc0f10000u + stage);
}
static void exercise(QUERY query)
{
    struct { ULONG head; UCHAR value[32]; ULONG length, attrs, tail; } out;
    UNICODE_STRING name = {22, 22, L"BootCurrent"}, bad;
    WCHAR embedded[] = {L'B', 0, L'x'};
    ULONG i;
    out.head = out.tail = 0xdeadbeef;
    out.length = sizeof(out.value); out.attrs = 0xcccccccc;
    for (i = 0; i < sizeof(out.value); ++i) out.value[i] = 0xa5;
    /* Abort class: C0F1=CPL/TEB, C0F2=status, C0F3=canary; low bits=call.
     * Each alias makes 28 calls, audited independently by the runner. */
#define TEST(expected, n, g, v, l, a) do { \
    NTSTATUS result; ++stage; result = query(n,g,v,l,a); restored(); \
    if (result != (expected)) finish(0xc0f20000u + stage); \
    if (out.head != 0xdeadbeef || out.tail != 0xdeadbeef || \
        out.length != sizeof(out.value) || out.attrs != 0xcccccccc) finish(0xc0f30000u + stage); \
    for (i = 0; i < sizeof(out.value); ++i) if (out.value[i] != 0xa5) finish(0xc0f30000u + stage); \
} while (0)
#define NORMAL(expected, n) TEST(expected,n,&vendor,out.value,&out.length,&out.attrs)
    NORMAL(DENIED, &name);
    TEST(DENIED,&name,&vendor,out.value,&out.length,NULL);
    TEST(INVALID,NULL,&vendor,out.value,&out.length,&out.attrs);
    TEST(INVALID,&name,NULL,out.value,&out.length,&out.attrs);
    TEST(INVALID,&name,&vendor,out.value,NULL,&out.attrs);
    TEST(INVALID,&name,&vendor,NULL,&out.length,&out.attrs);
    bad = name; bad.Length = 21; NORMAL(INVALID, &bad);
    bad = name; bad.MaximumLength = 23; NORMAL(INVALID, &bad);
    bad = name; bad.MaximumLength = 2; NORMAL(INVALID, &bad);
    bad = name; bad.Length = 0; NORMAL(INVALID, &bad);
    bad = name; bad.Length = bad.MaximumLength = 2050; NORMAL(INVALID, &bad);
    bad = name; bad.Buffer = NULL; NORMAL(INVALID, &bad);
    bad = name; bad.Buffer = embedded; bad.Length = bad.MaximumLength = sizeof(embedded); NORMAL(INVALID, &bad);
    NORMAL(ACCESS, (PUNICODE_STRING)KERNEL);
    bad = name; bad.Buffer = (PWSTR)KERNEL; NORMAL(ACCESS, &bad);
    TEST(ACCESS,&name,(GUID *)KERNEL,out.value,&out.length,&out.attrs);
    TEST(ACCESS,&name,&vendor,(PVOID)KERNEL,&out.length,&out.attrs);
    TEST(ACCESS,&name,&vendor,out.value,(PULONG)KERNEL,&out.attrs);
    TEST(ACCESS,&name,&vendor,out.value,&out.length,(PULONG)KERNEL);
    NORMAL(ACCESS, (PUNICODE_STRING)1);
    TEST(ACCESS,&name,(GUID *)1,out.value,&out.length,&out.attrs);
    TEST(ACCESS,&name,&vendor,(PVOID)1,&out.length,&out.attrs);
    TEST(ACCESS,&name,&vendor,out.value,(PULONG)1,&out.attrs);
    TEST(ACCESS,&name,&vendor,out.value,&out.length,(PULONG)1);
    TEST(ACCESS,&name,&vendor,(PVOID)(ULONG_PTR)-1,&out.length,&out.attrs);
    TEST(INVALID,&name,&vendor,out.value,&out.length,&out.length);
    TEST(INVALID,&name,&vendor,&out.length,&out.length,&out.attrs);
    TEST(INVALID,&name,&vendor,out.value,&out.length,(PULONG)out.value);
#undef NORMAL
#undef TEST
}
void NTAPI entry(void)
{
    saved_teb = __readgsqword(0x30);
    saved_pid = __readgsqword(0x40);
    saved_tid = __readgsqword(0x48);
    restored();
    if (!saved_teb || !saved_pid || saved_pid == 4 || !saved_tid) finish(0xc0f40000u);
    exercise(NtQuerySystemEnvironmentValueEx);
    exercise(ZwQuerySystemEnvironmentValueEx);
    if (stage != 56) finish(0xc0f50000u + stage);
    finish(0);
}
