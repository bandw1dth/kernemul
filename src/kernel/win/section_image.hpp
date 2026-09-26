#pragma once
#include <image.hpp>
#include <cstring>
#include <span>

namespace win
{
// Validate before the generic PE materializer dereferences raw header offsets.
inline bool valid_section_image(std::span<const std::uint8_t> raw)
{
	if (raw.size() < sizeof(pe::dos_header)) return false;
	pe::dos_header dos{};
	std::memcpy(&dos, raw.data(), sizeof(dos));
	if (!dos.ok() || dos.lfanew < static_cast<std::int32_t>(sizeof(dos))) return false;
	const auto offset = static_cast<std::size_t>(dos.lfanew);
	if (offset > raw.size() || sizeof(pe::nt_headers) > raw.size() - offset) return false;
	pe::nt_headers nt{};
	std::memcpy(&nt, raw.data() + offset, sizeof(nt));
	if (nt.signature != pe::nt_headers::nt_signature || !nt.optional_hdr.ok()
		|| nt.file_hdr.size_of_optional_header < sizeof(pe::optional_header64)) return false;
	const auto table = offset + offsetof(pe::nt_headers, optional_hdr) + nt.file_hdr.size_of_optional_header;
	if (table > raw.size() || nt.file_hdr.number_of_sections > (raw.size() - table) / sizeof(pe::section_header))
		return false;
	const auto headers = nt.optional_hdr.size_of_headers;
	const auto image = nt.optional_hdr.size_of_image;
	if (!image || headers > raw.size() || headers > image
		|| headers < table + nt.file_hdr.number_of_sections * sizeof(pe::section_header)) return false;
	for (std::size_t i = 0; i < nt.file_hdr.number_of_sections; ++i)
	{
		pe::section_header section{};
		std::memcpy(&section, raw.data() + table + i * sizeof(section), sizeof(section));
		if (section.virtual_address > image || section.virtual_size > image - section.virtual_address)
			return false;
		if (!section.size_of_raw_data) continue;
		// Materialization must not overwrite the validated headers that its callers read.
		if (section.virtual_address < headers) return false;
		if (section.pointer_to_raw_data > raw.size()
			|| section.size_of_raw_data > raw.size() - section.pointer_to_raw_data
			|| section.size_of_raw_data > image - section.virtual_address) return false;
	}
	return true;
}
}
