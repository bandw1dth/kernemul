#include "kernel/win/physical_memory_resources.hpp"
#include "kernel/win/registry.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace
{

using win::physical_memory_resources::encoded_resource_list;
using win::physical_memory_resources::range;

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

std::uint64_t read_u64(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
	assert(offset + 8 <= bytes.size());
	std::uint64_t value = 0;
	for (unsigned int i = 0; i < 8; ++i)
		value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
	return value;
}

std::vector<range> decode(const encoded_resource_list& encoded)
{
	const std::span<const std::uint8_t> bytes(encoded.bytes);
	assert(bytes.size() >= 20);
	assert(read_u32(bytes, 0) == 1);
	assert(read_u32(bytes, 4) == 0);
	assert(read_u32(bytes, 8) == 0);
	assert(read_u16(bytes, 12) == 1);
	assert(read_u16(bytes, 14) == 1);
	const auto count = read_u32(bytes, 16);
	assert(count == encoded.descriptor_count);
	assert(bytes.size() == 20 + static_cast<std::size_t>(count) * 20);

	std::vector<range> result;
	result.reserve(count);
	for (std::size_t i = 0; i < count; ++i)
	{
		const auto offset = 20 + i * 20;
		assert(bytes[offset] == 3);
		assert(bytes[offset + 1] == 1);
		assert(read_u16(bytes, offset + 2) == 0);
		assert(read_u32(bytes, offset + 12) != 0);
		assert(read_u32(bytes, offset + 12) <= 0xFFFFF000);
		assert(read_u32(bytes, offset + 16) == 0); // Reserved descriptor tail.
		result.push_back({ read_u64(bytes, offset + 4), read_u32(bytes, offset + 12) });
	}
	return result;
}

template <typename Exception, typename Function>
void expect_exception(Function&& action)
{
	bool threw = false;
	try
	{
		action();
	}
	catch (const Exception&)
	{
		threw = true;
	}
	assert(threw);
}

void test_known_wire_bytes()
{
	static_assert(static_cast<std::uint32_t>(registry_type::resource_list) == 8);
	const std::array ranges{ range{ 0x12345000, 0x2000 } };
	const auto encoded = win::physical_memory_resources::encode(ranges);
	const std::vector<std::uint8_t> expected{
		0x01, 0x00, 0x00, 0x00, // One full resource descriptor.
		0x00, 0x00, 0x00, 0x00, // Internal interface type.
		0x00, 0x00, 0x00, 0x00, // Bus zero.
		0x01, 0x00, 0x01, 0x00, // Partial-list version and revision.
		0x01, 0x00, 0x00, 0x00, // One partial descriptor.
		0x03, 0x01, 0x00, 0x00, // Memory, device-exclusive, read/write flags.
		0x00, 0x50, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, // 64-bit start.
		0x00, 0x20, 0x00, 0x00, // 32-bit length.
		0x00, 0x00, 0x00, 0x00, // Trailing descriptor padding.
	};
	assert(encoded.bytes == expected);
	assert(encoded.descriptor_count == 1);
	const auto decoded = decode(encoded);
	assert(decoded.size() == 1 && decoded[0].base == 0x12345000
		&& decoded[0].length == 0x2000);
}

void test_four_gibibyte_range_splits()
{
	const std::array ranges{ range{ 0x100000000, 0x100000000 } };
	const auto encoded = win::physical_memory_resources::encode(ranges);
	assert(encoded.bytes.size() == 60);
	assert(encoded.descriptor_count == 2);
	const auto decoded = decode(encoded);
	assert(decoded.size() == 2);
	assert(decoded[0].base == 0x100000000 && decoded[0].length == 0xFFFFF000);
	assert(decoded[1].base == 0x1FFFFF000 && decoded[1].length == 0x1000);
}

void test_holes_and_high_addresses()
{
	const std::array ranges{
		range{ 0x100000000, 0x2000 },
		range{ 0x100100000, 0x1000 },
		range{ 0x10000000000, 0x3000 },
	};
	const auto encoded = win::physical_memory_resources::encode(ranges);
	const auto decoded = decode(encoded);
	assert(decoded.size() == ranges.size());
	for (std::size_t i = 0; i < ranges.size(); ++i)
		assert(decoded[i].base == ranges[i].base && decoded[i].length == ranges[i].length);
}

void test_invalid_ranges()
{
	expect_exception<std::invalid_argument>([] {
		static_cast<void>(win::physical_memory_resources::encode(std::span<const range>{}));
	});
	expect_exception<std::invalid_argument>([] {
		const std::array ranges{ range{ 0x1000, 0 } };
		static_cast<void>(win::physical_memory_resources::encode(ranges));
	});
	expect_exception<std::invalid_argument>([] {
		const std::array ranges{ range{ 0x1001, 0x1000 } };
		static_cast<void>(win::physical_memory_resources::encode(ranges));
	});
	expect_exception<std::invalid_argument>([] {
		const std::array ranges{ range{ 0x1000, 0x1001 } };
		static_cast<void>(win::physical_memory_resources::encode(ranges));
	});
	expect_exception<std::invalid_argument>([] {
		const std::array ranges{ range{ 0xFFFFFFFFFFFFF000, 0x2000 } };
		static_cast<void>(win::physical_memory_resources::encode(ranges));
	});
	expect_exception<std::invalid_argument>([] {
		const std::array ranges{ range{ 0x4000, 0x1000 }, range{ 0x2000, 0x1000 } };
		static_cast<void>(win::physical_memory_resources::encode(ranges));
	});
	expect_exception<std::invalid_argument>([] {
		const std::array ranges{ range{ 0x1000, 0x3000 }, range{ 0x3000, 0x1000 } };
		static_cast<void>(win::physical_memory_resources::encode(ranges));
	});
}

void test_descriptor_limit()
{
	using namespace win::physical_memory_resources;
	const auto max_range_bytes = max_partial_length * max_descriptors;
	const std::array at_limit{ range{ 0x100000000, max_range_bytes } };
	const auto encoded = encode(at_limit);
	assert(encoded.descriptor_count == max_descriptors);
	assert(encoded.bytes.size() == envelope_bytes + max_descriptors * descriptor_bytes);

	const std::array above_limit{ range{ 0x100000000, max_range_bytes + page_bytes } };
	expect_exception<std::length_error>([&] { static_cast<void>(encode(above_limit)); });

	std::vector<range> too_many_ranges(max_descriptors + 1);
	for (std::size_t i = 0; i < too_many_ranges.size(); ++i)
		too_many_ranges[i] = { 0x100000000 + i * 0x2000, 0x1000 };
	expect_exception<std::length_error>([&] { static_cast<void>(encode(too_many_ranges)); });
}

} // namespace

int main()
{
	test_known_wire_bytes();
	test_four_gibibyte_range_splits();
	test_holes_and_high_addresses();
	test_invalid_ranges();
	test_descriptor_limit();
	std::cout << "physical_memory_resource_model: PASS\n";
}
