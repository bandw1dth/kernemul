#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace win::physical_memory_resources
{

inline constexpr std::uint64_t page_bytes = 0x1000;
inline constexpr std::uint64_t max_partial_length = 0xFFFFF000;
inline constexpr std::size_t max_descriptors = 4096;
inline constexpr std::size_t envelope_bytes = 20;
inline constexpr std::size_t descriptor_bytes = 20;

struct range
{
	std::uint64_t base;
	std::uint64_t length;
};

struct encoded_resource_list
{
	std::vector<std::uint8_t> bytes;
	std::uint32_t descriptor_count;
};

namespace detail
{

inline void write_u16(std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::uint16_t value)
{
	for (unsigned int i = 0; i < 2; ++i)
		bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

inline void write_u32(std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::uint32_t value)
{
	for (unsigned int i = 0; i < 4; ++i)
		bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

inline void write_u64(std::vector<std::uint8_t>& bytes, const std::size_t offset,
	const std::uint64_t value)
{
	for (unsigned int i = 0; i < 8; ++i)
		bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

} // namespace detail

// Throws invalid_argument for malformed ranges and length_error when the 4096-descriptor
// bound would be exceeded. Validation completes before the output vector is allocated.
[[nodiscard]] inline encoded_resource_list encode(const std::span<const range> ranges)
{
	if (ranges.empty())
		throw std::invalid_argument("physical resource list cannot be empty");
	if (ranges.size() > max_descriptors)
		throw std::length_error("physical resource descriptor limit exceeded");

	std::size_t descriptor_count = 0;
	std::uint64_t previous_base = 0;
	std::uint64_t previous_end = 0;
	bool have_previous = false;

	for (const auto& item : ranges)
	{
		if (item.length == 0)
			throw std::invalid_argument("physical resource range has zero length");
		if ((item.base % page_bytes) != 0 || (item.length % page_bytes) != 0)
			throw std::invalid_argument("physical resource range is not page aligned");
		if (item.length > std::numeric_limits<std::uint64_t>::max() - item.base)
			throw std::invalid_argument("physical resource range overflows");
		if (have_previous && (item.base < previous_base || item.base < previous_end))
			throw std::invalid_argument("physical resource ranges are unsorted or overlap");

		const auto pieces = item.length / max_partial_length
			+ static_cast<std::uint64_t>((item.length % max_partial_length) != 0);
		if (pieces > max_descriptors - descriptor_count)
			throw std::length_error("physical resource descriptor limit exceeded");

		descriptor_count += static_cast<std::size_t>(pieces);
		previous_base = item.base;
		previous_end = item.base + item.length;
		have_previous = true;
	}

	encoded_resource_list result{
		std::vector<std::uint8_t>(envelope_bytes + descriptor_count * descriptor_bytes, 0),
		static_cast<std::uint32_t>(descriptor_count),
	};
	auto& bytes = result.bytes;

	// CM_RESOURCE_LIST with one FULL_RESOURCE_DESCRIPTOR and its partial list.
	detail::write_u32(bytes, 0, 1); // Full resource descriptor count.
	detail::write_u32(bytes, 4, 0); // InterfaceTypeInternal.
	detail::write_u32(bytes, 8, 0); // Bus number.
	detail::write_u16(bytes, 12, 1); // Partial resource list version.
	detail::write_u16(bytes, 14, 1); // Partial resource list revision.
	detail::write_u32(bytes, 16, result.descriptor_count);

	std::size_t descriptor_index = 0;
	for (const auto& item : ranges)
	{
		auto base = item.base;
		auto remaining = item.length;
		while (remaining != 0)
		{
			const auto length = remaining < max_partial_length ? remaining : max_partial_length;
			const auto offset = envelope_bytes + descriptor_index * descriptor_bytes;
			bytes[offset] = 3; // CmResourceTypeMemory.
			bytes[offset + 1] = 1; // CmResourceShareDeviceExclusive.
			// Flags and descriptor tail padding are zero from vector initialization.
			detail::write_u64(bytes, offset + 4, base);
			detail::write_u32(bytes, offset + 12, static_cast<std::uint32_t>(length));

			base += length;
			remaining -= length;
			++descriptor_index;
		}
	}

	return result;
}

} // namespace win::physical_memory_resources
