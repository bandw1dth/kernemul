/* Guest input only; never load this fixture on the host. */
#include <ntifs.h>
#include <intrin.h>

typedef NTSTATUS (NTAPI *QUERY)(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG);
static LONG failures;
static GUID global_vendor = {0x8be4df61, 0x93ca, 0x11d2, {0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c}};
static void check(BOOLEAN ok, const char *name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}
static BOOLEAN filled(const UCHAR *p, ULONG n, UCHAR b)
{
    ULONG i;
    for (i = 0; i < n; ++i) if (p[i] != b) return FALSE;
    return TRUE;
}
static USHORT u16(const UCHAR *p) { return (USHORT)(p[0] | ((USHORT)p[1] << 8)); }
static BOOLEAN boot_entry(const UCHAR *p, ULONG n)
{
    ULONG pos = 6, path_end, len;
    static const WCHAR path[] = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
    if (n < 12 || p[0] != 1 || p[1] || p[2] || p[3]) return FALSE;
    while (pos + 2 <= n && u16(p + pos)) pos += 2;
    if (pos + 2 > n) return FALSE;
    pos += 2;
    path_end = pos + u16(p + 4);
    if (path_end != n || pos + 42 > n || p[pos] != 4 || p[pos+1] != 1 || u16(p+pos+2) != 42)
        return FALSE;
    /* Hard-drive media device path: GPT partition and GUID signature. */
    if (p[pos+40] != 2 || p[pos+41] != 2) return FALSE;
    pos += 42;
    if (pos + 4 > n || p[pos] != 4 || p[pos+1] != 4) return FALSE;
    len = u16(p + pos + 2);
    if (len != sizeof(path) + 4 || pos + len + 4 != n ||
        RtlCompareMemory(p + pos + 4, path, sizeof(path)) != sizeof(path)) return FALSE;
    pos += len;
    return p[pos] == 0x7f && p[pos+1] == 0xff && u16(p+pos+2) == 4;
}
static void exercise(QUERY query, const char *api)
{
    UNICODE_STRING name, bad;
    GUID vendor;
    UCHAR data[512], saved[512];
    ULONG length, attrs, needed;
    NTSTATUS status;
    KIRQL old;
    volatile UCHAR *previous;
    UCHAR saved_mode;
    WCHAR embedded[] = {L'B',0,L'x'};
    DbgPrint("CONFORMANCE firmware-api %s\n", api);
    RtlInitUnicodeString(&name, L"BootCurrent");
    RtlFillMemory(data, sizeof(data), 0xa5);
    length = sizeof(data); attrs = 0xcccccccc;
    status = query(&name, &global_vendor, data, &length, &attrs);
    check(status == STATUS_SUCCESS && length == 2 && attrs == 6 && data[0] == 0 && data[1] == 0 &&
        filled(data+2, sizeof(data)-2, 0xa5), "current-exact-bytes-attributes-tail");
    /* Old adapters cannot safely handle malformed pointers; baseline still reports failure. */
    if (status != STATUS_SUCCESS) return;
    length = 0; attrs = 0xcccccccc;
    status = query(&name, &global_vendor, NULL, &length, &attrs);
    check(status == STATUS_BUFFER_TOO_SMALL && length == 2 && attrs == 0xcccccccc, "size-probe-preserves-attributes");
    length = 1; RtlFillMemory(data, sizeof(data), 0xa5);
    status = query(&name, &global_vendor, data, &length, &attrs);
    check(status == STATUS_BUFFER_TOO_SMALL && length == 2 && attrs == 0xcccccccc && filled(data,sizeof(data),0xa5), "short-buffer-preserved");
    RtlInitUnicodeString(&name, L"BootOrder"); length = sizeof(data);
    status = query(&name, &global_vendor, data, &length, &attrs);
    check(status == STATUS_SUCCESS && length == 2 && attrs == 7 && !data[0] && !data[1], "order-refers-to-boot0000");
    RtlInitUnicodeString(&name, L"Boot0000"); length = 0;
    status = query(&name, &global_vendor, NULL, &length, NULL); needed = length;
    check(status == STATUS_BUFFER_TOO_SMALL && needed > 48 && needed <= sizeof(data), "entry-size-probe");
    length = sizeof(data); attrs = 0;
    status = query(&name, &global_vendor, data, &length, &attrs);
    check(status == STATUS_SUCCESS && length == needed && attrs == 7 && boot_entry(data,length), "packed-active-gpt-windows-path-entry");
    RtlCopyMemory(saved, data, sizeof(data)); length = sizeof(data);
    status = query(&name, &global_vendor, data, &length, NULL);
    check(status == STATUS_SUCCESS && length == needed && RtlCompareMemory(data,saved,needed) == needed, "repeat-optional-attributes");
    RtlInitUnicodeString(&name, L"bootcurrent"); length = sizeof(data); attrs = 0xcccccccc;
    status = query(&name, &global_vendor, data, &length, &attrs);
    check(status == (NTSTATUS)0xc0000100 && length == sizeof(data) && attrs == 0xcccccccc, "case-sensitive-missing");
    RtlInitUnicodeString(&name, L"MissingFirmwareVariable");
    check(query(&name,&global_vendor,data,&length,&attrs) == (NTSTATUS)0xc0000100, "missing-variable");
    RtlInitUnicodeString(&name, L"BootCurrent"); vendor = global_vendor; vendor.Data1 ^= 1;
    check(query(&name,&vendor,data,&length,&attrs) == (NTSTATUS)0xc0000100, "vendor-namespace");
    RtlFillMemory(data,sizeof(data),0xa5);
    check(query(NULL,&global_vendor,data,&length,&attrs) == STATUS_INVALID_PARAMETER, "null-name");
    check(query(&name,NULL,data,&length,&attrs) == STATUS_INVALID_PARAMETER, "null-vendor");
    check(query(&name,&global_vendor,data,NULL,&attrs) == STATUS_INVALID_PARAMETER, "null-length");
    check(query(&name,&global_vendor,NULL,&length,&attrs) == STATUS_INVALID_PARAMETER, "null-nonzero-value");
    bad = name; bad.Length |= 1;
    check(query(&bad,&global_vendor,data,&length,&attrs) == STATUS_INVALID_PARAMETER, "odd-name-length");
    bad = name; bad.MaximumLength = 2;
    check(query(&bad,&global_vendor,data,&length,&attrs) == STATUS_INVALID_PARAMETER, "length-exceeds-maximum");
    bad = name; bad.Length = bad.MaximumLength = 2050;
    check(query(&bad,&global_vendor,data,&length,&attrs) == STATUS_INVALID_PARAMETER, "bounded-name-length");
    bad.Buffer = embedded; bad.Length = bad.MaximumLength = sizeof(embedded);
    check(query(&bad,&global_vendor,data,&length,&attrs) == STATUS_INVALID_PARAMETER, "embedded-nul-name");
    bad = name; bad.Buffer = NULL;
    check(query(&bad,&global_vendor,data,&length,&attrs) == STATUS_INVALID_PARAMETER, "null-name-buffer");
    check(query((PUNICODE_STRING)1,&global_vendor,data,&length,&attrs) == STATUS_ACCESS_VIOLATION, "invalid-name-descriptor");
    check(query(&name,(LPGUID)1,data,&length,&attrs) == STATUS_ACCESS_VIOLATION, "invalid-guid");
    check(query(&name,&global_vendor,data,(PULONG)1,&attrs) == STATUS_ACCESS_VIOLATION, "invalid-length");
    check(query(&name,&global_vendor,data,&length,(PULONG)1) == STATUS_ACCESS_VIOLATION, "last-output-preflight");
    check(query(&name,&global_vendor,(PVOID)1,&length,&attrs) == STATUS_ACCESS_VIOLATION, "invalid-value");
    check(query(&name,&global_vendor,(PVOID)(ULONG_PTR)-1,&length,&attrs) == STATUS_ACCESS_VIOLATION, "overflow-value-range");
    check(query(&name,&global_vendor,data,&length,&length) == STATUS_INVALID_PARAMETER, "length-attribute-alias");
    check(query(&name,&global_vendor,&length,&length,&attrs) == STATUS_INVALID_PARAMETER, "length-value-alias");
    check(query(&name,&global_vendor,data,&length,(PULONG)data) == STATUS_INVALID_PARAMETER, "value-attribute-alias");
    check(length == sizeof(data) && attrs == 0xcccccccc && filled(data,sizeof(data),0xa5), "failure-outputs-unchanged");
    old = KfRaiseIrql(DISPATCH_LEVEL);
    status = query(&name,&global_vendor,data,&length,&attrs);
    KeLowerIrql(old);
    check(status == (NTSTATUS)0xc0000184 && length == sizeof(data) && attrs == 0xcccccccc && filled(data,sizeof(data),0xa5), "nonpassive-deterministic-failure");
    /* Guest ABI fixed by types_x64.hpp, ntkrnlmp.pdb
     * 8CB8E27C9BCA95EA7FD026E739740C9D1: KTHREAD.PreviousMode is 0x232.
     * Restore immediately, before any diagnostics or other kernel services. */
    previous = (volatile UCHAR *)PsGetCurrentThread() + 0x232;
    saved_mode = *previous;
    *previous = UserMode;
    status = query(&name,&global_vendor,data,&length,&attrs);
    *previous = saved_mode;
    check(status == STATUS_SUCCESS && length == 2 && attrs == 6 && !data[0] && !data[1],
        "ex-zw-kernel-entry-bypasses-previousmode");
    /* A counted name needs no terminator, and can overlap value input/output. */
    RtlCopyMemory(data, L"BootCurrent", 22);
    bad.Buffer = (PWCHAR)data; bad.Length = bad.MaximumLength = 22;
    length = 22;
    status = query(&bad,&global_vendor,data,&length,&attrs);
    check(status == STATUS_SUCCESS && length == 2 && !data[0] && !data[1] && data[2] == 'o',
        "input-captured-before-overlapping-output");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    UNICODE_STRING name;
    QUERY query;
    static const WCHAR *apis[] = {L"ExGetFirmwareEnvironmentVariable", L"ZwQuerySystemEnvironmentValueEx"};
    static const char *labels[] = {"Ex", "Zw"};
    ULONG i;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(registry);
    for (i=0; i<RTL_NUMBER_OF(apis); ++i) {
        RtlInitUnicodeString(&name, apis[i]);
        query = (QUERY)MmGetSystemRoutineAddress(&name);
        check(query != NULL, "firmware-api-resolved");
        if (query) exercise(query, labels[i]);
    }
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}


