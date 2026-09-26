/* Guest input only; never load this fixture on the host. */
#include <ntifs.h>

#define PHYSICAL_MEMORY_VALUE_BYTES 60
#define RESOURCE_LIST_HEADER_BYTES 20
#define RANGE_LIMIT 16

C_ASSERT(sizeof(ULONG) + sizeof(INTERFACE_TYPE) + sizeof(ULONG) +
         sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG) == RESOURCE_LIST_HEADER_BYTES);
C_ASSERT(sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) == 20);
C_ASSERT(sizeof(CM_RESOURCE_LIST) == 40);
C_ASSERT(FIELD_OFFSET(CM_PARTIAL_RESOURCE_DESCRIPTOR, u.Memory.Start) == 4);
C_ASSERT(FIELD_OFFSET(CM_PARTIAL_RESOURCE_DESCRIPTOR, u.Memory.Length) == 12);

typedef struct _MEMORY_INTERVAL {
    ULONGLONG Start;
    ULONGLONG End;
} MEMORY_INTERVAL, *PMEMORY_INTERVAL;

static LONG failures;

static void check(BOOLEAN ok, const char *label)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++failures;
}

static void finish(void)
{
    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
}

static BOOLEAN tail_is(const UCHAR *buffer, ULONG start, ULONG length, UCHAR value)
{
    ULONG i;
    for (i = start; i < length; ++i)
        if (buffer[i] != value) return FALSE;
    return TRUE;
}

static void normalize_intervals(PMEMORY_INTERVAL ranges, PULONG count)
{
    ULONG i, j, used = 0;
    MEMORY_INTERVAL current;

    for (i = 1; i < *count; ++i) {
        current = ranges[i];
        j = i;
        while (j && ranges[j - 1].Start > current.Start) {
            ranges[j] = ranges[j - 1];
            --j;
        }
        ranges[j] = current;
    }

    for (i = 0; i < *count; ++i) {
        if (used && ranges[i].Start <= ranges[used - 1].End) {
            if (ranges[i].End > ranges[used - 1].End)
                ranges[used - 1].End = ranges[i].End;
        } else {
            ranges[used++] = ranges[i];
        }
    }
    *count = used;
}

static BOOLEAN capture_physical_ranges(
    PMEMORY_INTERVAL output,
    ULONG capacity,
    PULONG output_count,
    PPHYSICAL_MEMORY_RANGE *allocation)
{
    ULONG i;
    *output_count = 0;
    *allocation = MmGetPhysicalMemoryRanges();
    if (!*allocation) return FALSE;

    for (i = 0; i < 64; ++i) {
        ULONGLONG start, length;
        LONGLONG signed_length = (*allocation)[i].NumberOfBytes.QuadPart;
        if (!signed_length) {
            if (!*output_count) return FALSE;
            normalize_intervals(output, output_count);
            return TRUE;
        }
        if (signed_length < 0 || *output_count >= capacity) return FALSE;
        start = (ULONGLONG)(*allocation)[i].BaseAddress.QuadPart;
        length = (ULONGLONG)signed_length;
        if (start > ~(ULONGLONG)0 - length) return FALSE;
        output[*output_count].Start = start;
        output[*output_count].End = start + length;
        ++*output_count;
    }
    return FALSE;
}

static BOOLEAN intervals_equal(
    const MEMORY_INTERVAL *left,
    ULONG left_count,
    const MEMORY_INTERVAL *right,
    ULONG right_count)
{
    ULONG i;
    if (left_count != right_count) return FALSE;
    for (i = 0; i < left_count; ++i) {
        if (left[i].Start != right[i].Start || left[i].End != right[i].End)
            return FALSE;
    }
    return TRUE;
}

static BOOLEAN parse_resource_list(
    const UCHAR *data,
    ULONG length,
    PMEMORY_INTERVAL decoded,
    PULONG decoded_count)
{
    CM_RESOURCE_LIST header;
    CM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
    ULONG i;

    *decoded_count = 0;
    if (length != PHYSICAL_MEMORY_VALUE_BYTES) return FALSE;

    /* The value data can be unaligned; copy each WDK structure before reading it. */
    RtlCopyMemory(&header, data, RESOURCE_LIST_HEADER_BYTES);
    if (header.Count != 1 ||
        header.List[0].InterfaceType != (INTERFACE_TYPE)0 ||
        header.List[0].BusNumber != 0 ||
        header.List[0].PartialResourceList.Version != 1 ||
        header.List[0].PartialResourceList.Revision != 1 ||
        header.List[0].PartialResourceList.Count != 2)
        return FALSE;

    for (i = 0; i < 2; ++i) {
        ULONGLONG start, extent;
        RtlCopyMemory(&descriptor,
            data + RESOURCE_LIST_HEADER_BYTES + i * sizeof(descriptor),
            sizeof(descriptor));
        if (descriptor.Type != CmResourceTypeMemory ||
            descriptor.ShareDisposition != CmResourceShareDeviceExclusive ||
            descriptor.Flags != 0 || descriptor.u.Memory.Length == 0)
            return FALSE;
        start = (ULONGLONG)descriptor.u.Memory.Start.QuadPart;
        extent = descriptor.u.Memory.Length;
        if (start > ~(ULONGLONG)0 - extent) return FALSE;
        decoded[i].Start = start;
        decoded[i].End = start + extent;
    }

    if (decoded[0].End != decoded[1].Start ||
        decoded[0].End - decoded[0].Start != 0xfffff000UL)
        return FALSE;
    *decoded_count = 2;
    normalize_intervals(decoded, decoded_count);
    return TRUE;
}

static BOOLEAN full_information_data(
    const UCHAR *buffer,
    ULONG result_length,
    const UNICODE_STRING *expected_name,
    const UCHAR **data,
    PULONG data_length)
{
    KEY_VALUE_FULL_INFORMATION header;
    ULONG name_offset = FIELD_OFFSET(KEY_VALUE_FULL_INFORMATION, Name);

    if (result_length < name_offset) return FALSE;
    RtlCopyMemory(&header, buffer, name_offset);
    if (header.Type != REG_RESOURCE_LIST ||
        header.NameLength != expected_name->Length ||
        header.DataOffset < name_offset + header.NameLength ||
        header.DataOffset > result_length ||
        header.DataLength > result_length - header.DataOffset ||
        header.DataOffset + header.DataLength != result_length ||
        RtlCompareMemory(buffer + name_offset, expected_name->Buffer,
                         expected_name->Length) != expected_name->Length)
        return FALSE;

    *data = buffer + header.DataOffset;
    *data_length = header.DataLength;
    return TRUE;
}

static BOOLEAN check_value_blob(
    const UCHAR *data,
    ULONG length,
    const MEMORY_INTERVAL *physical,
    ULONG physical_count)
{
    MEMORY_INTERVAL decoded[RANGE_LIMIT];
    ULONG decoded_count;
    if (!parse_resource_list(data, length, decoded, &decoded_count)) return FALSE;
    return intervals_equal(decoded, decoded_count, physical, physical_count);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    UNICODE_STRING parent_name, child_name, direct_name, value_name;
    OBJECT_ATTRIBUTES attributes;
    HANDLE parent = NULL, key = NULL, direct = NULL;
    NTSTATUS status;
    ULONG required = 0, result_length = 0, short_length;
    UCHAR full_buffer[512], enum_buffer[512], partial_buffer[256];
    UCHAR *partial_data;
    const UCHAR *value_data;
    ULONG value_length;
    BOOLEAN found_enumerated_value = FALSE;
    MEMORY_INTERVAL physical[RANGE_LIMIT], repeated[RANGE_LIMIT];
    ULONG physical_count = 0, repeated_count = 0;
    PPHYSICAL_MEMORY_RANGE physical_allocation = NULL, repeated_allocation = NULL;
    PVOID pool_allocation = NULL;
    ULONG i;

    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry_path);

    RtlInitUnicodeString(&parent_name,
        L"\\Registry\\Machine\\hardware\\resourcemap\\system resources");
    InitializeObjectAttributes(&attributes, &parent_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&parent, KEY_READ, &attributes);
    check(NT_SUCCESS(status) && parent != NULL, "physical-memory-parent-present-case-insensitive");
    if (!NT_SUCCESS(status) || !parent) goto cleanup;

    RtlInitUnicodeString(&child_name, L"PHYSICAL MEMORY");
    InitializeObjectAttributes(&attributes, &child_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parent, NULL);
    status = ZwOpenKey(&key, KEY_READ, &attributes);
    check(NT_SUCCESS(status) && key != NULL, "physical-memory-relative-open-case-insensitive");
    if (!NT_SUCCESS(status) || !key) goto cleanup;

    RtlInitUnicodeString(&direct_name,
        L"\\registry\\machine\\HARDWARE\\RESOURCEMAP\\System Resources\\physical memory");
    InitializeObjectAttributes(&attributes, &direct_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&direct, KEY_READ, &attributes);
    check(NT_SUCCESS(status) && direct != NULL, "physical-memory-full-path-case-insensitive");

    RtlInitUnicodeString(&value_name, L".Translated");
    if (!capture_physical_ranges(physical, RANGE_LIMIT, &physical_count,
                                 &physical_allocation)) {
        check(FALSE, "MmGetPhysicalMemoryRanges-baseline");
        goto cleanup;
    }
    check(TRUE, "MmGetPhysicalMemoryRanges-baseline");

    status = ZwQueryValueKey(key, &value_name, KeyValueFullInformation,
                             NULL, 0, &required);
    check(status == STATUS_BUFFER_TOO_SMALL && required > 0,
          "full-information-zero-size-reports-exact-required-length");
    if (status != STATUS_BUFFER_TOO_SMALL || !required || required > sizeof(full_buffer))
        goto cleanup;

    short_length = required - 1;
    RtlFillMemory(full_buffer, sizeof(full_buffer), 0xa5);
    result_length = 0;
    status = ZwQueryValueKey(key, &value_name, KeyValueFullInformation,
                             full_buffer, short_length, &result_length);
    check(status == STATUS_BUFFER_OVERFLOW && result_length == required &&
          tail_is(full_buffer, short_length, sizeof(full_buffer), 0xa5),
          "full-information-short-buffer-overflow-bounded");

    RtlFillMemory(full_buffer, sizeof(full_buffer), 0xa5);
    result_length = 0;
    status = ZwQueryValueKey(key, &value_name, KeyValueFullInformation,
                             full_buffer, required, &result_length);
    check(status == STATUS_SUCCESS && result_length == required &&
          full_information_data(full_buffer, result_length, &value_name,
                                &value_data, &value_length) &&
          check_value_blob(value_data, value_length, physical, physical_count),
          "full-information-exact-dataoffset-and-resource-list");

    for (i = 0; i < 64; ++i) {
        ULONG enum_length = 0;
        status = ZwEnumerateValueKey(key, i, KeyValueFullInformation,
                                     enum_buffer, sizeof(enum_buffer), &enum_length);
        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(status)) {
            check(FALSE, "value-enumeration-succeeds");
            break;
        }
        if (full_information_data(enum_buffer, enum_length, &value_name,
                                  &value_data, &value_length)) {
            found_enumerated_value = TRUE;
            check(check_value_blob(value_data, value_length, physical, physical_count),
                  "enumerated-translated-resource-list-dataoffset");
            break;
        }
    }
    check(found_enumerated_value, "translated-value-found-by-enumeration");

    required = 0;
    status = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
                             NULL, 0, &required);
    check(status == STATUS_BUFFER_TOO_SMALL &&
          required == FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
                      PHYSICAL_MEMORY_VALUE_BYTES,
          "partial-information-zero-size-reports-exact-required-length");
    if (status != STATUS_BUFFER_TOO_SMALL || required > sizeof(partial_buffer))
        goto cleanup;

    short_length = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 16;
    RtlFillMemory(partial_buffer, sizeof(partial_buffer), 0xa5);
    result_length = 0;
    status = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
                             partial_buffer, short_length, &result_length);
    check(status == STATUS_BUFFER_OVERFLOW && result_length == required,
          "partial-information-short-buffer-overflow");
    check(tail_is(partial_buffer, short_length, sizeof(partial_buffer), 0xa5),
          "partial-information-short-buffer-bounded-canary");

    RtlFillMemory(partial_buffer, sizeof(partial_buffer), 0xa5);
    result_length = 0;
    status = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
                             partial_buffer, required, &result_length);
    check(status == STATUS_SUCCESS && result_length == required,
          "partial-information-exact-query");
    if (NT_SUCCESS(status) && result_length >=
        (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)) {
        KEY_VALUE_PARTIAL_INFORMATION partial_header;
        RtlCopyMemory(&partial_header, partial_buffer,
                      FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data));
        partial_data = partial_buffer + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
        check(partial_header.Type == REG_RESOURCE_LIST &&
              partial_header.DataLength == PHYSICAL_MEMORY_VALUE_BYTES &&
              check_value_blob(partial_data, partial_header.DataLength,
                               physical, physical_count),
              "partial-information-metadata-and-resource-list");
    }

    RtlFillMemory(partial_buffer, sizeof(partial_buffer), 0xa5);
    result_length = 0;
    status = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
                             partial_buffer, sizeof(partial_buffer), &result_length);
    check(status == STATUS_SUCCESS && result_length == required &&
          tail_is(partial_buffer, required, sizeof(partial_buffer), 0xa5),
          "partial-information-oversized-query-preserves-tail");

    pool_allocation = ExAllocatePoolWithTag(NonPagedPool, 4096, 'rPmK');
    check(pool_allocation != NULL, "pool-allocation-for-range-stability");
    if (pool_allocation) {
        if (capture_physical_ranges(repeated, RANGE_LIMIT, &repeated_count,
                                    &repeated_allocation)) {
            check(intervals_equal(physical, physical_count, repeated, repeated_count),
                  "physical-memory-ranges-stable-after-pool-allocation");
        } else {
            check(FALSE, "physical-memory-ranges-repeat-after-pool-allocation");
        }
    }

cleanup:
    if (repeated_allocation) ExFreePool(repeated_allocation);
    if (physical_allocation) ExFreePool(physical_allocation);
    if (pool_allocation) ExFreePool(pool_allocation);
    if (direct) ZwClose(direct);
    if (key) ZwClose(key);
    if (parent) ZwClose(parent);
    finish();
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
