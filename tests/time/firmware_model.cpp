#include "kernel/win/firmware.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace win::firmware;

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
	assert(offset + 2 <= bytes.size());
	return static_cast<std::uint16_t>(bytes[offset])
		| static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1]) << 8);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
	assert(offset + 4 <= bytes.size());
	std::uint32_t value = 0;
	for (unsigned int i = 0; i < 4; ++i)
		value |= static_cast<std::uint32_t>(bytes[offset + i]) << (i * 8);
	return value;
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
	assert(offset + 8 <= bytes.size());
	std::uint64_t value = 0;
	for (unsigned int i = 0; i < 8; ++i)
		value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
	return value;
}

std::u16string read_u16_string(const std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::size_t code_units)
{
	assert(offset + code_units * 2 <= bytes.size());
	std::u16string value;
	value.reserve(code_units);
	for (std::size_t i = 0; i < code_units; ++i)
		value.push_back(static_cast<char16_t>(read_u16(bytes, offset + i * 2)));
	return value;
}

variable make_variable(std::u16string name, std::vector<std::uint8_t> value = {},
	const guid vendor = {})
{
	return { vendor, std::move(name), 0xFEDCBA98, std::move(value) };
}

template <typename Function>
void expect_invalid_argument(Function&& action)
{
	bool threw = false;
	try
	{
		action();
	}
	catch (const std::invalid_argument&)
	{
		threw = true;
	}
	assert(threw);
}

void test_synthetic_wire_data()
{
	constexpr guid expected_global_guid{
		0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
		0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C,
	};
	assert(global_variable_guid == expected_global_guid);
	constexpr guid expected_disk_guid{
		0x12, 0x8D, 0x91, 0xF3, 0x4A, 0x7C, 0x9D, 0x4F,
		0x8E, 0x61, 0x22, 0x50, 0xAA, 0x19, 0xB0, 0xC1,
	};
	assert(synthetic_boot_disk_guid == expected_disk_guid);
	constexpr guid expected_partition_guid{
		0x91, 0x33, 0x5E, 0xB7, 0x07, 0xC2, 0x6F, 0x4A,
		0xA2, 0xC9, 0x43, 0x6B, 0x11, 0xDD, 0x08, 0xE4,
	};
	assert(synthetic_boot_partition_guid == expected_partition_guid);
	assert(synthetic_boot_partition_start_lba == 2048);
	assert(synthetic_boot_partition_size_lba == 524288);
	assert(synthetic_sector_size_bytes == 512);
	assert(!synthetic_provenance.empty());

	const auto firmware = synthetic_uefi();
	assert(firmware.type() == mode::uefi);
	const auto* boot_current = firmware.find(global_variable_guid, u"BootCurrent");
	const auto* boot_order = firmware.find(global_variable_guid, u"BootOrder");
	const auto* boot_option = firmware.find(global_variable_guid, u"Boot0000");
	assert(boot_current && boot_current->attributes == 6);
	assert(boot_current->value == std::vector<std::uint8_t>({ 0x00, 0x00 }));
	assert(boot_order && boot_order->attributes == 7);
	assert(boot_order->value == std::vector<std::uint8_t>({ 0x00, 0x00 }));
	assert(boot_option && boot_option->attributes == 7);

	const auto& bytes = boot_option->value;
	assert(read_u32(bytes, 0) == 1); // Active load option.
	const auto file_path_list_length = read_u16(bytes, 4);
	constexpr std::u16string_view expected_description = u"Windows Boot Manager (kernemul)";
	constexpr std::size_t description_offset = 6;
	const auto description_bytes = (expected_description.size() + 1) * 2;
	assert(read_u16_string(bytes, description_offset, expected_description.size()) == expected_description);
	assert(read_u16(bytes, description_offset + expected_description.size() * 2) == 0);
	const auto device_path_offset = description_offset + description_bytes;
	assert(file_path_list_length == bytes.size() - device_path_offset);

	// Decode the EFI hard-drive node by its specified field offsets.
	assert(bytes[device_path_offset] == 0x04 && bytes[device_path_offset + 1] == 0x01);
	assert(read_u16(bytes, device_path_offset + 2) == 42);
	assert(read_u32(bytes, device_path_offset + 4) == 1);
	assert(read_u64(bytes, device_path_offset + 8) == 2048);
	assert(read_u64(bytes, device_path_offset + 16) == 524288);
	for (std::size_t i = 0; i < expected_partition_guid.size(); ++i)
		assert(bytes[device_path_offset + 24 + i] == expected_partition_guid[i]);
	assert(bytes[device_path_offset + 40] == 0x02); // GPT partition.
	assert(bytes[device_path_offset + 41] == 0x02); // GUID signature.

	constexpr std::u16string_view expected_path = u"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
	const auto file_path_node_offset = device_path_offset + 42;
	const auto file_path_node_length = static_cast<std::uint16_t>(4 + (expected_path.size() + 1) * 2);
	assert(bytes[file_path_node_offset] == 0x04 && bytes[file_path_node_offset + 1] == 0x04);
	assert(read_u16(bytes, file_path_node_offset + 2) == file_path_node_length);
	assert(read_u16_string(bytes, file_path_node_offset + 4, expected_path.size()) == expected_path);
	assert(read_u16(bytes, file_path_node_offset + 4 + expected_path.size() * 2) == 0);
	const auto end_offset = file_path_node_offset + file_path_node_length;
	assert(bytes[end_offset] == 0x7F && bytes[end_offset + 1] == 0xFF);
	assert(read_u16(bytes, end_offset + 2) == 4);
	assert(end_offset + 4 == device_path_offset + file_path_list_length);
	assert(end_offset + 4 == bytes.size()); // Optional data is empty.
}

void test_lookup_and_instance_ownership()
{
	const auto first = synthetic_uefi();
	const auto second = synthetic_uefi();
	assert(first.find(global_variable_guid, u"Boot0000") != second.find(global_variable_guid, u"Boot0000"));
	assert(first.find(global_variable_guid, u"boot0000") == nullptr);
	assert(first.find(guid{}, u"Boot0000") == nullptr);
	assert(first.find(global_variable_guid, u"Boot0001") == nullptr);

	const auto lower = make_variable(u"BootCurrent");
	const auto namespaced = make_variable(u"BootCurrent", {}, guid{ 1 });
	const auto differently_cased = make_variable(u"bootcurrent");
	store names(mode::uefi, { lower, namespaced, differently_cased });
	assert(names.find(guid{}, u"BootCurrent") != nullptr);
	assert(names.find(guid{ 1 }, u"BootCurrent") != nullptr);
	assert(names.find(guid{}, u"bootcurrent") != nullptr);
	assert(names.find(guid{ 1 }, u"bootcurrent") == nullptr);

	store bios(mode::legacy_bios, {});
	assert(bios.type() == mode::legacy_bios);
	assert(bios.find(global_variable_guid, u"BootCurrent") == nullptr);
}

void test_validation()
{
	expect_invalid_argument([] { store invalid(mode::uefi, { make_variable(u"") }); });
	expect_invalid_argument([] { store invalid(mode::uefi, { make_variable(std::u16string{ u'x', 0, u'y' }) }); });
	expect_invalid_argument([] { store invalid(mode::uefi, { make_variable(u"duplicate"), make_variable(u"duplicate") }); });
	expect_invalid_argument([] {
		store invalid(mode::legacy_bios, { make_variable(u"present") });
	});

	std::vector<variable> maximum_count;
	maximum_count.reserve(128);
	for (std::size_t i = 0; i < 128; ++i)
		maximum_count.push_back(make_variable(u"v" + std::u16string(1, static_cast<char16_t>(i + 1))));
	store accepted_count(mode::uefi, maximum_count);
	maximum_count.push_back(make_variable(u"overflow"));
	expect_invalid_argument([&] { store invalid(mode::uefi, maximum_count); });

	store accepted_name(mode::uefi, { make_variable(std::u16string(1024, u'n')) });
	assert(accepted_name.find(guid{}, std::u16string(1024, u'n')) != nullptr);
	expect_invalid_argument([] { store invalid(mode::uefi, { make_variable(std::u16string(1025, u'n')) }); });

	store accepted_value(mode::uefi, { make_variable(u"max-value", std::vector<std::uint8_t>(64 * 1024)) });
	assert(accepted_value.find(guid{}, u"max-value")->value.size() == 64 * 1024);
	expect_invalid_argument([] {
		store invalid(mode::uefi, { make_variable(u"large-value", std::vector<std::uint8_t>(64 * 1024 + 1)) });
	});

	std::vector<variable> maximum_total;
	maximum_total.reserve(16);
	for (unsigned int i = 0; i < 16; ++i)
		maximum_total.push_back(make_variable(u"total" + std::u16string(1, static_cast<char16_t>(u'a' + i)),
			std::vector<std::uint8_t>(64 * 1024)));
	store accepted_total(mode::uefi, maximum_total);
	maximum_total.push_back(make_variable(u"total-overflow", { 0x01 }));
	expect_invalid_argument([&] { store invalid(mode::uefi, maximum_total); });

	const auto unknown_attributes = make_variable(u"future-attributes");
	store preserved(mode::uefi, { unknown_attributes });
	assert(preserved.find(guid{}, u"future-attributes")->attributes == 0xFEDCBA98);
}

} // namespace

int main()
{
	test_synthetic_wire_data();
	test_lookup_and_instance_ownership();
	test_validation();
	std::cout << "firmware_model: PASS\n";
}
