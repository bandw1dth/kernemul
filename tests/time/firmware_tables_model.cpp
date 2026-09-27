#include "kernel/win/firmware_tables.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <set>

using namespace win::firmware_tables;

static std::uint32_t u32(const std::vector<std::uint8_t>& b, std::size_t p)
{
    assert(p + 4 <= b.size());
    return b[p] | (std::uint32_t(b[p+1]) << 8) | (std::uint32_t(b[p+2]) << 16)
        | (std::uint32_t(b[p+3]) << 24);
}

int main()
{
    const store fixture, another;
    const auto& raw = fixture.raw_smbios();
    assert(raw == another.raw_smbios());
    assert(raw.size() >= 14 && raw.size() < 4080);
    assert(raw[0] == 0 && raw[1] == 2 && raw[2] == 8);
    assert(u32(raw, 4) == raw.size() - 8);
    const store legacy(false);
    assert((raw[8 + 19] & 8) != 0);
    assert((legacy.raw_smbios()[8 + 19] & 8) == 0);
    auto legacy_expected = raw;
    legacy_expected[8 + 19] &= ~std::uint8_t{8};
    assert(legacy.raw_smbios() == legacy_expected);
    std::set<unsigned> handles;
    std::vector<unsigned> types;
    std::size_t p = 8;
    while (p < raw.size())
    {
        assert(p + 4 <= raw.size());
        const unsigned type = raw[p], length = raw[p+1];
        assert(length >= 4 && p + length + 2 <= raw.size());
        assert(handles.insert(raw[p+2] | (unsigned(raw[p+3]) << 8)).second);
        types.push_back(type);
        std::size_t end = p + length;
        while (end + 1 < raw.size() && (raw[end] || raw[end+1])) ++end;
        assert(end + 1 < raw.size());
        unsigned strings = 0;
        for (std::size_t at = p + length; at < end; ++at)
            if (at == p + length || raw[at-1] == 0) ++strings;
        const auto check_index = [&](unsigned offset) { assert(raw[p+offset] <= strings); };
        if (type == 0)
        {
            assert(length == 24);
            check_index(4); check_index(5); check_index(8);
        }
        else if (type == 1)
        {
            assert(length == 27);
            for (unsigned offset : {4, 5, 6, 7, 25, 26}) check_index(offset);
            assert(std::equal(synthetic_system_uuid.begin(), synthetic_system_uuid.end(), raw.begin() + p + 8));
            assert(std::any_of(raw.begin() + p + 8, raw.begin() + p + 24, [](auto v) { return v != 0; }));
        }
        else
        {
            assert(type == 127 && length == 4 && strings == 0 && end + 2 == raw.size());
        }
        p = end + 2;
    }
    assert((types == std::vector<unsigned>{0, 1, 127}));
    const auto needed = static_cast<std::uint32_t>(16 + raw.size());
    for (std::uint32_t size = 0; size <= needed + 1; ++size)
    {
        const auto result = fixture.query(provider_rsmb, 1, 0, size);
        if (size < 16)
            assert(result.status == 0xC0000004u && result.required == 16 && !result.write_length && result.payload.empty());
        else if (size < needed)
            assert(result.status == 0xC0000023u && result.required == needed && result.write_length == 16
                && result.table_buffer_length == raw.size() && result.payload.empty());
        else
            assert(result.status == 0 && result.required == needed && result.write_length == needed && result.payload == raw);
    }
    for (std::uint32_t id : {0u, 1u, 0xffffffffu})
    {
        auto result = fixture.query(provider_rsmb, 1, id, 0xffffffffu);
        assert(result.status == 0 && result.payload == raw);
        result.payload[0] ^= 0xff;
        assert(fixture.raw_smbios() == another.raw_smbios());
        auto enumerated = fixture.query(provider_rsmb, 0, id, 20);
        assert(enumerated.status == 0 && enumerated.required == 20 && enumerated.table_buffer_length == 4
            && enumerated.payload == std::vector<std::uint8_t>(4, 0));
    }
    for (auto size : {16u, 19u})
    {
        auto result = fixture.query(provider_rsmb, 0, 0, size);
        assert(result.status == 0xC0000023u && result.required == 20 && result.table_buffer_length == 4 && result.payload.empty());
    }
    for (auto provider : {0u, 0x41435049u, 0x4649524du})
    {
        const auto result = fixture.query(provider, 2, 0, 4096);
        assert(result.status == 0xC0000002u && !result.required && !result.write_length && result.payload.empty());
    }
    const auto invalid = fixture.query(provider_rsmb, 2, 0, 4096);
    assert(invalid.status == 0xC00000EFu && invalid.required == 4096 && !invalid.write_length && invalid.payload.empty());
    std::cout << "firmware_tables_model: PASS (wire structure, bounds, aliases, immutability)\n";
}
