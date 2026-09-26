#pragma once

#include "firmware.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace win::storage
{

inline constexpr std::uint32_t query_property = 0x2d1400;
inline constexpr std::uint32_t ata_pass_through = 0x4d02c;
inline constexpr std::size_t max_request_bytes = 65536;

inline constexpr std::uint32_t status_success = 0x00000000;
inline constexpr std::uint32_t status_invalid_parameter = 0xC000000D;
inline constexpr std::uint32_t status_invalid_device_request = 0xC0000010;
inline constexpr std::uint32_t status_buffer_too_small = 0xC0000023;
inline constexpr std::uint32_t status_not_supported = 0xC00000BB;

inline constexpr std::string_view serial = "KERNEMUL00000001";
inline constexpr std::string_view model = "Kernemul Synthetic Disk";
inline constexpr std::string_view revision = "1.0";
inline constexpr std::uint32_t sector_size_bytes = firmware::synthetic_sector_size_bytes;
inline constexpr std::uint64_t capacity_bytes = 8ull * 1024 * 1024 * 1024;
inline constexpr std::uint64_t capacity_sectors = capacity_bytes / sector_size_bytes;
inline constexpr auto boot_disk_guid = firmware::synthetic_boot_disk_guid;
inline constexpr auto boot_partition_guid = firmware::synthetic_boot_partition_guid;
// Capacity describes metadata only; this model does not implement sector I/O.

static_assert(capacity_bytes % sector_size_bytes == 0);
static_assert(capacity_sectors > firmware::synthetic_boot_partition_start_lba
	+ firmware::synthetic_boot_partition_size_lba);

struct reply
{
	std::uint32_t status;
	std::uint64_t information;
	std::vector<std::uint8_t> output;
};

namespace detail
{

inline constexpr std::size_t descriptor_fixed_size = 40;
inline constexpr std::size_t ata_header_size = 48;
inline constexpr std::size_t identify_size = 512;
inline constexpr std::uint16_t ata_flag_drdy_required = 0x0001;
inline constexpr std::uint16_t ata_flag_data_in = 0x0002;
inline constexpr std::uint8_t ata_identify_device = 0xEC;

inline std::uint16_t read_u16(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
	return static_cast<std::uint16_t>(bytes[offset])
		| static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1]) << 8);
}

inline std::uint32_t read_u32(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
	std::uint32_t value = 0;
	for (unsigned int i = 0; i < 4; ++i)
		value |= static_cast<std::uint32_t>(bytes[offset + i]) << (i * 8);
	return value;
}

inline std::uint64_t read_u64(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
	std::uint64_t value = 0;
	for (unsigned int i = 0; i < 8; ++i)
		value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
	return value;
}

inline void write_u32(std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::uint32_t value)
{
	for (unsigned int i = 0; i < 4; ++i)
		bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

inline void append_ascii(std::vector<std::uint8_t>& bytes, const std::string_view value)
{
	for (const char character : value)
		bytes.push_back(static_cast<std::uint8_t>(character));
	bytes.push_back(0);
}

inline std::vector<std::uint8_t> make_device_descriptor()
{
	std::vector<std::uint8_t> bytes(descriptor_fixed_size, 0);
	const auto vendor_offset = static_cast<std::uint32_t>(bytes.size());
	append_ascii(bytes, "KERNEMUL");
	const auto model_offset = static_cast<std::uint32_t>(bytes.size());
	append_ascii(bytes, model);
	const auto revision_offset = static_cast<std::uint32_t>(bytes.size());
	append_ascii(bytes, revision);
	const auto serial_offset = static_cast<std::uint32_t>(bytes.size());
	append_ascii(bytes, serial);

	write_u32(bytes, 0, static_cast<std::uint32_t>(descriptor_fixed_size));
	write_u32(bytes, 4, static_cast<std::uint32_t>(bytes.size()));
	bytes[8] = 0; // Direct-access device.
	bytes[9] = 0;
	bytes[10] = 0; // RemovableMedia = FALSE.
	bytes[11] = 0; // CommandQueueing = FALSE.
	write_u32(bytes, 12, vendor_offset);
	write_u32(bytes, 16, model_offset);
	write_u32(bytes, 20, revision_offset);
	write_u32(bytes, 24, serial_offset);
	write_u32(bytes, 28, 3); // BusTypeAta.
	write_u32(bytes, 32, 0); // No bus-specific raw properties.
	return bytes;
}

inline void set_word(std::array<std::uint8_t, identify_size>& bytes, const std::size_t word,
	const std::uint16_t value)
{
	bytes[word * 2] = static_cast<std::uint8_t>(value);
	bytes[word * 2 + 1] = static_cast<std::uint8_t>(value >> 8);
}

inline void set_ata_string(std::array<std::uint8_t, identify_size>& bytes,
	const std::size_t first_word, const std::size_t word_count, const std::string_view value)
{
	for (std::size_t i = 0; i < word_count * 2; i += 2)
	{
		const auto first = i < value.size() ? static_cast<std::uint8_t>(value[i]) : std::uint8_t{' '};
		const auto second = i + 1 < value.size()
			? static_cast<std::uint8_t>(value[i + 1]) : std::uint8_t{' '};
		const auto byte_offset = first_word * 2 + i;
		// ATA strings store the first character in the high byte of each word.
		bytes[byte_offset] = second;
		bytes[byte_offset + 1] = first;
	}
}

inline std::array<std::uint8_t, identify_size> make_identify_data()
{
	std::array<std::uint8_t, identify_size> bytes{};
	set_word(bytes, 0, 0x0040); // Fixed disk; no removable-media claim.
	set_ata_string(bytes, 10, 10, serial);
	set_ata_string(bytes, 23, 4, revision);
	set_ata_string(bytes, 27, 20, model);
	set_word(bytes, 49, 1u << 9); // 28-bit LBA only; no DMA claim.
	set_word(bytes, 60, static_cast<std::uint16_t>(capacity_sectors));
	set_word(bytes, 61, static_cast<std::uint16_t>(capacity_sectors >> 16));

	// Word 255 carries the optional ATA checksum signature and checksum byte.
	bytes[510] = 0xA5;
	std::uint8_t sum = 0;
	for (std::size_t i = 0; i < 511; ++i)
		sum = static_cast<std::uint8_t>(sum + bytes[i]);
	bytes[511] = static_cast<std::uint8_t>(0u - sum);
	return bytes;
}

inline reply failure(const std::uint32_t status)
{
	return { status, 0, {} };
}

inline reply query_storage_property(const std::span<const std::uint8_t> input,
	const std::uint32_t output_length)
{
	if (input.size() < 12 || input.size() > max_request_bytes || output_length > max_request_bytes)
		return failure(status_invalid_parameter);

	const auto property_id = read_u32(input, 0);
	const auto query_type = read_u32(input, 4);
	if (query_type > 1)
		return failure(status_invalid_parameter);
	if (property_id != 0) // StorageDeviceProperty is the only modeled property.
		return failure(status_not_supported);
	if (query_type == 1) // PropertyExistsQuery.
		return { status_success, 0, {} };

	// A zero-length standard query is the documented existence probe.
	if (output_length == 0)
		return { status_success, 0, {} };
	if (output_length < 8)
		return failure(status_buffer_too_small);

	auto descriptor = make_device_descriptor();
	if (output_length == 8)
	{
		descriptor.resize(8);
		return { status_success, 8, std::move(descriptor) };
	}
	// A short descriptor request returns no partial data and reports no information.
	if (output_length < descriptor.size())
		return failure(status_buffer_too_small);
	const auto information = static_cast<std::uint64_t>(descriptor.size());
	return { status_success, information, std::move(descriptor) };
}

inline reply identify_ata(const std::span<const std::uint8_t> input,
	const std::uint32_t output_length)
{
	if (input.size() < ata_header_size || input.size() > max_request_bytes)
		return failure(status_invalid_parameter);
	if (output_length > max_request_bytes)
		return failure(status_invalid_parameter);

	if (read_u16(input, 0) != ata_header_size)
		return failure(status_invalid_parameter);
	const auto flags = read_u16(input, 2);
	if ((flags & ~(ata_flag_drdy_required | ata_flag_data_in)) != 0
		|| (flags & ata_flag_data_in) == 0)
		return failure(status_invalid_parameter);
	if (input[7] != 0 || read_u32(input, 16) != 0 || input[47] != 0)
		return failure(status_invalid_parameter);
	if (read_u32(input, 8) != identify_size)
		return failure(status_invalid_parameter);

	const auto data_offset = read_u64(input, 24);
	if (data_offset < ata_header_size || (data_offset & 1u) != 0)
		return failure(status_invalid_parameter);
	if (data_offset > std::numeric_limits<std::uint64_t>::max() - identify_size)
		return failure(status_invalid_parameter);
	const auto end_offset = data_offset + identify_size;
	// Bounds are checked before the command byte. Short output returns no partial wrapper.
	if (end_offset > output_length)
		return failure(status_buffer_too_small);

	// CurrentTaskFile[6] is the command register; [0] at byte 40 is features.
	if (input[46] != ata_identify_device)
		return failure(status_invalid_device_request);

	std::vector<std::uint8_t> output(static_cast<std::size_t>(end_offset), 0);
	std::copy_n(input.begin(), ata_header_size, output.begin());
	const auto identify = make_identify_data();
	std::copy(identify.begin(), identify.end(), output.begin() + static_cast<std::ptrdiff_t>(data_offset));
	output[40] = 0; // Completion error register.
	output[46] = 0x50; // Completion status: DRDY | DSC.
	return { status_success, end_offset, std::move(output) };
}

} // namespace detail

class disk
{
public:
	reply control(const std::uint32_t code, const std::span<const std::uint8_t> input,
		const std::uint32_t output_length) const
	{
		if (code == query_property)
			return detail::query_storage_property(input, output_length);
		if (code == ata_pass_through)
			return detail::identify_ata(input, output_length);
		return detail::failure(status_invalid_device_request);
	}
};

} // namespace win::storage
