#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace win::firmware_tables
{
inline constexpr std::uint32_t header_size = 16;
inline constexpr std::uint32_t provider_rsmb = 0x52534D42;
inline constexpr std::string_view synthetic_provenance =
	"synthetic minimal SMBIOS 2.8 fixture; partial inventory; no host firmware";

// Windows/SMBIOS 2.6+ UUID byte order. This identity belongs to the deterministic
// guest fixture, is stable across boots, and is unrelated to any host identity.
inline constexpr std::array<std::uint8_t, 16> synthetic_system_uuid{
	0x73, 0xA9, 0x2C, 0x61, 0xD4, 0x18, 0x81, 0x4E,
	0xA2, 0x67, 0x59, 0xB0, 0x33, 0xC8, 0xF1, 0x02,
};

struct query_response
{
	std::uint32_t status = 0;
	std::uint32_t required = 0; // ReturnLength, including the outer header.
	// Extent of output touched: zero on rejected headers, 16 on a short provider buffer,
	// required on success. Only the length field and payload are ever changed.
	std::uint32_t write_length = 0;
	std::uint32_t table_buffer_length = 0;
	std::vector<std::uint8_t> payload; // Owned copy; empty unless successful.
};

class store
{
public:
	explicit store(bool uefi = true) : raw_smbios_(make_raw_smbios(uefi)) {}

	const std::vector<std::uint8_t>& raw_smbios() const noexcept { return raw_smbios_; }

	query_response query(std::uint32_t provider, std::uint32_t action,
		[[maybe_unused]] std::uint32_t table, std::uint32_t outer_length) const
	{
		if (outer_length < header_size) return {0xC0000004u, header_size, 0, 0, {}};
		if (provider != provider_rsmb) return {0xC0000002u, 0, 0, 0, {}};
		if (action > 1) return {0xC00000EFu, outer_length, 0, 0, {}};
		// RSMB accepts every table ID as an alias of zero. The input capacity is
		// deliberately absent: native Windows uses only the outer buffer length.
		const auto size = action == 0 ? 4u : static_cast<std::uint32_t>(raw_smbios_.size());
		const auto required = header_size + size;
		if (outer_length < required) return {0xC0000023u, required, header_size, size, {}};
		return {0, required, required, size,
			action == 0 ? std::vector<std::uint8_t>(4, 0) : raw_smbios_};
	}

private:
	static std::vector<std::uint8_t> make_raw_smbios(bool uefi)
	{
		// RawSMBIOSData: calling method, version 2.8, DMI revision, table length.
		std::vector<std::uint8_t> bytes{0, 2, 8, 0, 0, 0, 0, 0};
		const auto strings = [&bytes](std::initializer_list<std::string_view> values)
		{
			for (const auto value : values)
			{
				bytes.insert(bytes.end(), value.begin(), value.end());
				bytes.push_back(0);
			}
			bytes.push_back(0);
		};
		// Type 0, handle 0: base characteristics unsupported; BIOS/EC revisions
		// are unknown. Not a full DMTF inventory.
		std::array<std::uint8_t, 24> bios{
			0, 24, 0, 0, 1, 2, 0, 0, 3, 0, 8, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF,
		};
		// Extension byte 2's UEFI flag follows the machine firmware profile,
		// never host firmware capabilities.
		bios[19] = uefi ? 0x08 : 0;
		bytes.insert(bytes.end(), bios.begin(), bios.end());
		strings({"kernemul", "Synthetic minimal fixture", "01/01/2024"});
		// Type 1, handle 1; string indexes manufacturer/product/version/serial,
		// UUID, unknown wake-up type, SKU/family. No CPU or RAM inventory.
		std::array<std::uint8_t, 27> system{1, 27, 1, 0, 1, 2, 3, 4};
		for (std::size_t i = 0; i < synthetic_system_uuid.size(); ++i)
			system[8 + i] = synthetic_system_uuid[i];
		system[24] = 2;
		system[25] = 5;
		system[26] = 6;
		bytes.insert(bytes.end(), system.begin(), system.end());
		strings({"kernemul", "Synthetic guest (partial inventory)", "1",
			"KERNEMUL-GUEST-0001", "Minimal fixture", "Synthetic guest"});
		// Type 127, unique handle 0x7F00, empty string set (double NUL).
		bytes.insert(bytes.end(), {127, 4, 0, 127, 0, 0});
		if (bytes.size() > std::numeric_limits<std::uint32_t>::max() - header_size)
			throw std::length_error("synthetic SMBIOS wire size overflow");
		const auto table_length = static_cast<std::uint32_t>(bytes.size() - 8);
		for (unsigned i = 0; i < 4; ++i)
			bytes[4 + i] = static_cast<std::uint8_t>(table_length >> (8 * i));
		return bytes;
	}

	const std::vector<std::uint8_t> raw_smbios_;
};
} // namespace win::firmware_tables
