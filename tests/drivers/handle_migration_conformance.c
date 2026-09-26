/* Guest-only regression checks for kernel handle migration behavior. */
#include <ntifs.h>

typedef NTSTATUS (NTAPI *FLUSH_KEY_FN)(HANDLE);
typedef NTSTATUS (NTAPI *ALPC_CREATE_PORT_FN)(PHANDLE, POBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS (NTAPI *ALPC_CONNECT_PORT_FN)(PHANDLE, PUNICODE_STRING,
    POBJECT_ATTRIBUTES, PVOID, ULONG, PSID, PVOID, PSIZE_T, PVOID, PVOID,
    PLARGE_INTEGER);

static volatile LONG failures;

static void check(BOOLEAN ok, const char *label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) InterlockedIncrement(&failures);
}

static NTSTATUS create_named_port(ALPC_CREATE_PORT_FN create_port, PCWSTR path,
    ULONG object_attributes, PHANDLE port)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&attributes, &name, object_attributes, NULL, NULL);
    return create_port(port, &attributes, NULL);
}

static NTSTATUS connect_named_port(ALPC_CONNECT_PORT_FN connect_port, PCWSTR path,
    PHANDLE port)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, path);
    return connect_port(port, &name, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
}

static void check_flush_previous_mode(FLUSH_KEY_FN zw_flush)
{
    static const WCHAR key_path[] = L"\\Registry\\Machine\\Software\\KernemulHandleMigration";
    UNICODE_STRING key_name;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key = NULL;
    NTSTATUS status, zw_status;
    volatile UCHAR *previous_mode = (volatile UCHAR *)PsGetCurrentThread() + 0x232;
    UCHAR saved_mode, mode_after_zw;

    RtlInitUnicodeString(&key_name, key_path);
    InitializeObjectAttributes(&attributes, &key_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateKey(&key, KEY_ALL_ACCESS, &attributes, 0, NULL,
        REG_OPTION_NON_VOLATILE, NULL);
    check(NT_SUCCESS(status) && key, "create-kernel-registry-handle");
    if (!NT_SUCCESS(status) || !key) return;

    /* KTHREAD.PreviousMode is 0x232 in the pinned x64 guest profile. */
    saved_mode = *previous_mode;
    *previous_mode = UserMode;
    zw_status = zw_flush(key);
    mode_after_zw = *previous_mode;
    *previous_mode = saved_mode;

    check(zw_status == STATUS_SUCCESS && mode_after_zw == UserMode,
        "zw-flush-kernel-handle-restores-user-previousmode");
    ZwClose(key);
}

static void check_alpc_publication(ALPC_CREATE_PORT_FN create_port,
    ALPC_CONNECT_PORT_FN connect_port)
{
    static const WCHAR output_path[] = L"\\KernemulHandleMigrationOutputRetry";
    static const WCHAR existing_path[] = L"\\KernemulHandleMigrationExisting";
    static const WCHAR zw_kernel_path[] = L"\\KernemulHandleMigrationZwKernel";
    volatile UCHAR *previous_mode = (volatile UCHAR *)PsGetCurrentThread() + 0x232;
    UCHAR saved_mode, mode_after_zw;
    HANDLE port = NULL, server = NULL, client = NULL;
    HANDLE collision = (HANDLE)(ULONG_PTR)0x5555;
    NTSTATUS status;

    /* Zw must temporarily use KernelMode even when the caller's mode is UserMode. */
    saved_mode = *previous_mode;
    *previous_mode = UserMode;
    status = create_named_port(create_port, zw_kernel_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, &port);
    mode_after_zw = *previous_mode;
    *previous_mode = saved_mode;
    check(NT_SUCCESS(status) && port && mode_after_zw == UserMode,
        "zw-alpc-kernel-handle-restores-user-previousmode");
    if (port) ZwClose(port);

    /* A bad output pointer must roll back publication so the same name can retry. */
    status = create_named_port(create_port, output_path, OBJ_CASE_INSENSITIVE, (PHANDLE)1);
    check(status == STATUS_ACCESS_VIOLATION, "named-port-output-write-fails");
    status = create_named_port(create_port, output_path, OBJ_CASE_INSENSITIVE, &port);
    check(NT_SUCCESS(status) && port, "retry-name-after-output-write-failure");
    if (port) ZwClose(port);

    /* A failed client output must leave the pre-existing server name resolvable. */
    status = create_named_port(create_port, existing_path, OBJ_CASE_INSENSITIVE, &server);
    check(NT_SUCCESS(status) && server, "create-server-before-failed-connect");
    if (!NT_SUCCESS(status) || !server) return;

    status = create_named_port(create_port, existing_path, OBJ_CASE_INSENSITIVE, &collision);
    check(status == STATUS_OBJECT_NAME_COLLISION
        && collision == (HANDLE)(ULONG_PTR)0x5555,
        "name-collision-preserves-original-server");

    status = connect_named_port(connect_port, existing_path, (PHANDLE)1);
    check(status == STATUS_ACCESS_VIOLATION, "connect-output-write-fails");
    status = connect_named_port(connect_port, existing_path, &client);
    check(NT_SUCCESS(status) && client, "prior-server-name-survives-failed-connect");

    if (client) ZwClose(client);
    ZwClose(server);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    UNICODE_STRING routine_name;
    FLUSH_KEY_FN zw_flush;
    ALPC_CREATE_PORT_FN create_port;
    ALPC_CONNECT_PORT_FN connect_port;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);

    RtlInitUnicodeString(&routine_name, L"ZwFlushKey");
    zw_flush = (FLUSH_KEY_FN)MmGetSystemRoutineAddress(&routine_name);
    RtlInitUnicodeString(&routine_name, L"ZwAlpcCreatePort");
    create_port = (ALPC_CREATE_PORT_FN)MmGetSystemRoutineAddress(&routine_name);
    RtlInitUnicodeString(&routine_name, L"ZwAlpcConnectPort");
    connect_port = (ALPC_CONNECT_PORT_FN)MmGetSystemRoutineAddress(&routine_name);

    check(zw_flush != NULL, "resolve-zw-flush-key");
    check(create_port != NULL, "resolve-zw-alpc-create-port");
    check(connect_port != NULL, "resolve-zw-alpc-connect-port");

    if (zw_flush) check_flush_previous_mode(zw_flush);
    if (create_port && connect_port) check_alpc_publication(create_port, connect_port);

    DbgPrint("CONFORMANCE SKIP NtFlushKey/NtAlpcCreatePort PreviousModeUser denial: Nt exports are unavailable through MmGetSystemRoutineAddress\n");

    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
