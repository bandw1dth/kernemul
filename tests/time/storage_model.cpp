#include "kernel/win/storage.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using namespace win::storage;

void write_u16(std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::uint16_t value)
{
	bytes[offset] = static_cast<std::uint8_t>(value);
	bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void write_u32(std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::uint32_t value)
{
	for (unsigned int i = 0; i < 4; ++i)
		bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

void write_u64(std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::uint64_t value)
{
	for (unsigned int i = 0; i < 8; ++i)
		bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

std::uint16_t read_u16(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
	assert(offset + 2 <= bytes.size());
	return static_cast<std::uint16_t>(bytes[offset])
		| static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1]) << 8);
}

std::uint32_t read_u32(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
	assert(offset + 4 <= bytes.size());
	std::uint32_t value = 0;
	for (unsigned int i = 0; i < 4; ++i)
		value |= static_cast<std::uint32_t>(bytes[offset + i]) << (i * 8);
	return value;
}

std::vector<std::uint8_t> make_property_query(const std::uint32_t property = 0,
	const std::uint32_t query_type = 0)
{
	std::vector<std::uint8_t> bytes(12, 0);
	write_u32(bytes, 0, property);
	write_u32(bytes, 4, query_type);
	return bytes;
}

std::vector<std::uint8_t> make_identify_request(const std::uint64_t data_offset = 48,
	const std::uint8_t command = 0xEC)
{
	std::vector<std::uint8_t> bytes(48, 0);
	write_u16(bytes, 0, 48);
	write_u16(bytes, 2, 3); // DRDY_REQUIRED | DATA_IN.
	bytes[4] = 0x11;
	bytes[5] = 0x22;
	bytes[6] = 0x33;
	write_u32(bytes, 8, 512);
	write_u32(bytes, 12, 5);
	write_u64(bytes, 24, data_offset);
	for (std::size_t i = 32; i < 40; ++i)
		bytes[i] = static_cast<std::uint8_t>(0xA0 + i - 32);
	bytes[40] = 0x5A; // Features input; overwritten by the completion error register.
	bytes[41] = 0x61;
	bytes[42] = 0x62;
	bytes[43] = 0x63;
	bytes[44] = 0x64;
	bytes[45] = 0x65;
	bytes[46] = command;
	return bytes;
}

std::string decode_ata_string(const std::span<const std::uint8_t> bytes,
	const std::size_t first_word, const std::size_t word_count)
{
	std::string value;
	value.reserve(word_count * 2);
	for (std::size_t i = 0; i < word_count * 2; i += 2)
	{
		value.push_back(static_cast<char>(bytes[(first_word * 2) + i + 1]));
		value.push_back(static_cast<char>(bytes[(first_word * 2) + i]));
	}
	while (!value.empty() && value.back() == ' ')
		value.pop_back();
	return value;
}

std::string read_ascii_string(const std::span<const std::uint8_t> bytes,
	const std::uint32_t offset)
{
	assert(offset >= 40 && offset < bytes.size());
	std::string value;
	for (std::size_t i = offset; i < bytes.size() && bytes[i] != 0; ++i)
		value.push_back(static_cast<char>(bytes[i]));
	assert(offset + value.size() < bytes.size());
	assert(bytes[offset + value.size()] == 0);
	return value;
}

void test_storage_property()
{
	const disk device;
	const auto query = make_property_query();
	const auto probe = device.control(query_property, query, 8);
	assert(probe.status == status_success && probe.information == 8 && probe.output.size() == 8);
	assert(read_u32(probe.output, 0) == 40);
	const auto descriptor_size = read_u32(probe.output, 4);
	assert(descriptor_size > 40 && descriptor_size < max_request_bytes);
	assert(device.control(query_property, query, 8).output == probe.output);

	const auto empty_probe = device.control(query_property, query, 0);
	assert(empty_probe.status == status_success && empty_probe.information == 0
		&& empty_probe.output.empty());
	const auto too_short_header = device.control(query_property, query, 7);
	assert(too_short_header.status == status_buffer_too_small
		&& too_short_header.information == 0 && too_short_header.output.empty());
	const auto too_short_descriptor = device.control(query_property, query, descriptor_size - 1);
	assert(too_short_descriptor.status == status_buffer_too_small
		&& too_short_descriptor.information == 0 && too_short_descriptor.output.empty());

	const auto full = device.control(query_property, query, descriptor_size);
	assert(full.status == status_success && full.information == descriptor_size
		&& full.output.size() == descriptor_size);
	const std::span<const std::uint8_t> bytes(full.output);
	assert(read_u32(bytes, 0) == 40 && read_u32(bytes, 4) == descriptor_size);
	assert(bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0);
	assert(read_u32(bytes, 12) == 40);
	assert(read_u32(bytes, 16) == 49);
	assert(read_u32(bytes, 20) == 73);
	assert(read_u32(bytes, 24) == 77);
	assert(read_u32(bytes, 28) == 3); // BusTypeAta.
	assert(read_u32(bytes, 32) == 0);
	assert(bytes[36] == 0 && bytes[37] == 0 && bytes[38] == 0 && bytes[39] == 0);
	assert(read_ascii_string(bytes, read_u32(bytes, 12)) == "KERNEMUL");
	assert(read_ascii_string(bytes, read_u32(bytes, 16)) == std::string(model));
	assert(read_ascii_string(bytes, read_u32(bytes, 20)) == std::string(revision));
	assert(read_ascii_string(bytes, read_u32(bytes, 24)) == std::string(serial));
	assert(device.control(query_property, query, max_request_bytes).output == full.output);

	const auto exists_query = make_property_query(0, 1);
	const auto exists = device.control(query_property, exists_query, 0);
	assert(exists.status == status_success && exists.information == 0 && exists.output.empty());
	const auto unsupported_exists_query = make_property_query(1, 1);
	const auto unsupported_standard_query = make_property_query(1);
	const auto invalid_type_query = make_property_query(0, 2);
	const auto unsupported_exists = device.control(query_property, unsupported_exists_query, 0);
	assert(unsupported_exists.status == status_not_supported && unsupported_exists.output.empty());
	assert(device.control(query_property, unsupported_standard_query, 0).status == status_not_supported);
	assert(device.control(query_property, invalid_type_query, 8).status
		== status_invalid_parameter);
	assert(device.control(query_property, std::span<const std::uint8_t>(query).first(11), 8).status
		== status_invalid_parameter);
	std::vector<std::uint8_t> oversized_query(max_request_bytes + 1, 0);
	assert(device.control(query_property, oversized_query, 8).status == status_invalid_parameter);
	assert(device.control(0xFFFFFFFF, query, 8).status == status_invalid_device_request);
}

void test_identify()
{
	const disk device;
	auto request = make_identify_request();
	const auto result = device.control(ata_pass_through, request, 560);
	assert(result.status == status_success && result.information == 560 && result.output.size() == 560);
	for (std::size_t i = 0; i < request.size(); ++i)
	{
		const auto expected = i == 40 ? 0 : i == 46 ? 0x50 : request[i];
		assert(result.output[i] == expected);
	}
	const auto repeated = device.control(ata_pass_through, request, 560);
	assert(repeated.status == result.status && repeated.information == result.information
		&& repeated.output == result.output);

	const std::span<const std::uint8_t> identify(result.output.data() + 48, 512);
	assert(decode_ata_string(identify, 10, 10) == serial);
	assert(decode_ata_string(identify, 23, 4) == revision);
	assert(decode_ata_string(identify, 27, 20) == model);
	const auto identify_sectors = static_cast<std::uint32_t>(read_u16(identify, 60 * 2))
		| (static_cast<std::uint32_t>(read_u16(identify, 61 * 2)) << 16);
	assert(identify_sectors == capacity_sectors);
	assert(static_cast<std::uint64_t>(identify_sectors) * sector_size_bytes == capacity_bytes);
	assert(capacity_bytes == 8ull * 1024 * 1024 * 1024);
	assert(capacity_sectors > win::firmware::synthetic_boot_partition_start_lba
		+ win::firmware::synthetic_boot_partition_size_lba);
	assert(boot_disk_guid == win::firmware::synthetic_boot_disk_guid);
	assert(boot_partition_guid == win::firmware::synthetic_boot_partition_guid);
	assert((read_u16(identify, 49 * 2) & (1u << 9)) != 0); // 28-bit LBA.
	assert((read_u16(identify, 49 * 2) & (1u << 8)) == 0); // No DMA.
	assert((read_u16(identify, 83 * 2) & (1u << 10)) == 0); // No 48-bit LBA.
	assert((read_u16(identify, 76 * 2) & (1u << 8)) == 0); // No NCQ.
	std::uint8_t checksum = 0;
	for (const auto value : identify)
		checksum = static_cast<std::uint8_t>(checksum + value);
	assert(identify[510] == 0xA5 && checksum == 0);
}

void test_identify_buffer_rules()
{
	const disk device;
	auto request = make_identify_request(56);
	request.resize(60, 0xCC); // Trailing caller bytes must not become an output gap.
	const auto result = device.control(ata_pass_through, request, 568);
	assert(result.status == status_success && result.information == 568 && result.output.size() == 568);
	for (std::size_t i = 48; i < 56; ++i)
		assert(result.output[i] == 0);
	for (std::size_t i = 0; i < 48; ++i)
	{
		const auto expected = i == 40 ? 0 : i == 46 ? 0x50 : request[i];
		assert(result.output[i] == expected);
	}

	const auto limit_request = make_identify_request(65024);
	const auto exact_limit = device.control(ata_pass_through, limit_request,
		static_cast<std::uint32_t>(max_request_bytes));
	assert(exact_limit.status == status_success && exact_limit.information == max_request_bytes
		&& exact_limit.output.size() == max_request_bytes);
	const auto short_request = make_identify_request();
	const auto short_output = device.control(ata_pass_through, short_request, 559);
	assert(short_output.status == status_buffer_too_small && short_output.information == 0
		&& short_output.output.empty());
	const auto over_limit_request = make_identify_request();
	const auto over_limit = device.control(ata_pass_through, over_limit_request,
		static_cast<std::uint32_t>(max_request_bytes + 1));
	assert(over_limit.status == status_invalid_parameter);
}

void test_ata_rejections()
{
	const disk device;
	const auto valid = make_identify_request();
	assert(device.control(ata_pass_through, std::span<const std::uint8_t>(valid).first(47), 560).status
		== status_invalid_parameter);

	auto malformed = valid;
	write_u16(malformed, 0, 47);
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_parameter);
	malformed = valid;
	write_u16(malformed, 2, 7); // DATA_OUT is not supported.
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_parameter);
	malformed = valid;
	write_u16(malformed, 2, 0x0A); // DATA_IN plus 48-bit command.
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_parameter);
	malformed = valid;
	write_u16(malformed, 2, 0x12); // DATA_IN plus DMA.
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_parameter);
	malformed = valid;
	write_u16(malformed, 2, 0x8002); // Unknown flag.
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_parameter);
	malformed = valid;
	write_u16(malformed, 2, 1); // No DATA_IN direction.
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_parameter);
	malformed = valid;
	write_u32(malformed, 8, 511);
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_parameter);
	malformed = make_identify_request(46);
	assert(device.control(ata_pass_through, malformed, 558).status == status_invalid_parameter);
	malformed = make_identify_request(49);
	assert(device.control(ata_pass_through, malformed, 561).status == status_invalid_parameter);
	malformed = make_identify_request(UINT64_MAX - 511);
	assert(device.control(ata_pass_through, malformed,
		static_cast<std::uint32_t>(max_request_bytes)).status == status_invalid_parameter);
	malformed = make_identify_request(48, 0x25); // READ DMA EXT is never forwarded.
	assert(device.control(ata_pass_through, malformed, 560).status == status_invalid_device_request);

	// Regression: features[0] is EC, but CurrentTaskFile[6] (command) is zero.
	const std::array<std::uint8_t, 48> malformed_probe{
		0x30, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xEC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	assert(malformed_probe[40] == 0xEC && malformed_probe[46] == 0);
	const auto rejected_probe = device.control(ata_pass_through, malformed_probe, 512);
	assert(rejected_probe.status == status_buffer_too_small && rejected_probe.information == 0
		&& rejected_probe.output.empty()); // Bounds are checked before the command byte.
}

} // namespace

int main()
{
	test_storage_property();
	test_identify();
	test_identify_buffer_rules();
	test_ata_rejections();
	std::cout << "storage_model: PASS\n";
}
