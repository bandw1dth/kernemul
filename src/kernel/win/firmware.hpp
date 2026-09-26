#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace win::firmware
{

using guid = std::array<std::uint8_t, 16>;

// EFI global-variable GUID 8BE4DF61-93CA-11D2-AA0D-00E098032B8C in Windows GUID memory order.
inline constexpr guid global_variable_guid{
	0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
	0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C,
};

// These identities describe a synthetic guest disk. No host firmware or storage is queried.
inline constexpr guid synthetic_boot_disk_guid{
	0x12, 0x8D, 0x91, 0xF3, 0x4A, 0x7C, 0x9D, 0x4F,
	0x8E, 0x61, 0x22, 0x50, 0xAA, 0x19, 0xB0, 0xC1,
};
inline constexpr guid synthetic_boot_partition_guid{
	0x91, 0x33, 0x5E, 0xB7, 0x07, 0xC2, 0x6F, 0x4A,
	0xA2, 0xC9, 0x43, 0x6B, 0x11, 0xDD, 0x08, 0xE4,
};
inline constexpr std::uint64_t synthetic_boot_partition_start_lba = 2048;
inline constexpr std::uint64_t synthetic_boot_partition_size_lba = 524288;
inline constexpr std::uint32_t synthetic_sector_size_bytes = 512;
inline constexpr std::string_view synthetic_provenance =
	"synthetic guest firmware fixture; no host firmware access";

struct variable
{
	guid vendor;
	std::u16string name;
	std::uint32_t attributes;
	std::vector<std::uint8_t> value;
};

enum class mode
{
	legacy_bios,
	uefi,
};

class store
{
public:
	store(mode type, std::vector<variable> variables)
		: type_(type), variables_(validate(type, std::move(variables)))
	{
	}

	mode type() const
	{
		return type_;
	}

	const variable* find(const guid& vendor, const std::u16string_view name) const
	{
		for (const auto& candidate : variables_)
			if (candidate.vendor == vendor && candidate.name == name)
				return &candidate;
		return nullptr;
	}

private:
	static std::vector<variable> validate(const mode type, std::vector<variable> variables)
	{
		constexpr std::size_t max_variables = 128;
		constexpr std::size_t max_name_code_units = 1024;
		constexpr std::size_t max_value_bytes = 64 * 1024;
		constexpr std::size_t max_total_value_bytes = 1024 * 1024;

		if (type != mode::legacy_bios && type != mode::uefi)
			throw std::invalid_argument("invalid firmware mode");
		if (type == mode::legacy_bios && !variables.empty())
			throw std::invalid_argument("legacy BIOS firmware cannot contain variables");
		if (variables.size() > max_variables)
			throw std::invalid_argument("too many firmware variables");

		std::size_t total_value_bytes = 0;
		for (std::size_t i = 0; i < variables.size(); ++i)
		{
			const auto& current = variables[i];
			if (current.name.empty())
				throw std::invalid_argument("firmware variable name cannot be empty");
			if (current.name.size() > max_name_code_units)
				throw std::invalid_argument("firmware variable name is too long");
			if (current.name.find(u'\0') != std::u16string::npos)
				throw std::invalid_argument("firmware variable name contains NUL");
			if (current.value.size() > max_value_bytes)
				throw std::invalid_argument("firmware variable value is too large");
			if (current.value.size() > max_total_value_bytes - total_value_bytes)
				throw std::invalid_argument("firmware variable values exceed total size limit");
			total_value_bytes += current.value.size();

			for (std::size_t j = 0; j < i; ++j)
				if (variables[j].vendor == current.vendor && variables[j].name == current.name)
					throw std::invalid_argument("duplicate firmware variable");
		}
		return variables;
	}

	const mode type_;
	const std::vector<variable> variables_;
};

namespace detail
{

inline void append_u16(std::vector<std::uint8_t>& bytes, const std::uint16_t value)
{
	bytes.push_back(static_cast<std::uint8_t>(value));
	bytes.push_back(static_cast<std::uint8_t>(value >> 8));
}

inline void append_u32(std::vector<std::uint8_t>& bytes, const std::uint32_t value)
{
	for (unsigned int shift = 0; shift < 32; shift += 8)
		bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

inline void append_u64(std::vector<std::uint8_t>& bytes, const std::uint64_t value)
{
	for (unsigned int shift = 0; shift < 64; shift += 8)
		bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

inline std::vector<std::uint8_t> make_boot_option()
{
	constexpr std::u16string_view description = u"Windows Boot Manager (kernemul)";
	constexpr std::u16string_view path = u"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";

	std::vector<std::uint8_t> device_path;
	device_path.reserve(42 + 4 + (path.size() + 1) * 2 + 4);
	// EFI_HARD_DRIVE_DEVICE_PATH: GPT partition 1, followed by its EFI GUID signature.
	device_path.insert(device_path.end(), { 0x04, 0x01, 0x2A, 0x00 });
	append_u32(device_path, 1);
	append_u64(device_path, synthetic_boot_partition_start_lba);
	append_u64(device_path, synthetic_boot_partition_size_lba);
	device_path.insert(device_path.end(), synthetic_boot_partition_guid.begin(), synthetic_boot_partition_guid.end());
	device_path.push_back(0x02); // GPT partition format.
	device_path.push_back(0x02); // GUID signature format.

	const auto file_path_node_length = static_cast<std::uint16_t>(4 + (path.size() + 1) * 2);
	device_path.insert(device_path.end(), { 0x04, 0x04 });
	append_u16(device_path, file_path_node_length);
	for (const auto character : path)
		append_u16(device_path, static_cast<std::uint16_t>(character));
	append_u16(device_path, 0);
	device_path.insert(device_path.end(), { 0x7F, 0xFF, 0x04, 0x00 }); // End Entire.

	std::vector<std::uint8_t> load_option;
	load_option.reserve(6 + (description.size() + 1) * 2 + device_path.size());
	append_u32(load_option, 1); // EFI_LOAD_OPTION_ACTIVE.
	append_u16(load_option, static_cast<std::uint16_t>(device_path.size()));
	for (const auto character : description)
		append_u16(load_option, static_cast<std::uint16_t>(character));
	append_u16(load_option, 0);
	load_option.insert(load_option.end(), device_path.begin(), device_path.end());
	return load_option;
}

} // namespace detail

inline store synthetic_uefi()
{
	std::vector<variable> variables;
	variables.reserve(3);
	variables.push_back({ global_variable_guid, u"BootCurrent", 6, { 0x00, 0x00 } });
	variables.push_back({ global_variable_guid, u"BootOrder", 7, { 0x00, 0x00 } });
	variables.push_back({ global_variable_guid, u"Boot0000", 7, detail::make_boot_option() });
	return store(mode::uefi, std::move(variables));
}

} // namespace win::firmware
