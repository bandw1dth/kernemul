#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

enum class registry_type : std::uint32_t
{
	none      = 0,
	sz        = 1,
	expand_sz = 2,
	binary    = 3,
	dword     = 4,
	dword_be  = 5,
	link      = 6,
	multi_sz  = 7,
	resource_list = 8,
	qword     = 11,
};

struct registry_value
{
	registry_type type = registry_type::none;
	std::vector<std::uint8_t> data;
};

class win_registry_key
{
public:
	void set_value(std::string_view name, registry_type type, const void* data, std::size_t size);
	void set_value(std::string_view name, registry_type type, std::span<const std::uint8_t> data);
	[[nodiscard]] const registry_value* query_value(std::string_view name) const;
	[[nodiscard]] std::optional<registry_value> copy_value(std::string_view name) const;
	bool delete_value(std::string_view name);

	void set_dword(std::string_view name, std::uint32_t value);
	void set_qword(std::string_view name, std::uint64_t value);
	void set_string(std::string_view name, std::u16string_view value);
	void set_string(std::string_view name, std::string_view value);
	void set_binary(std::string_view name, const void* data, std::size_t size);
	void set_binary(std::string_view name, std::span<const std::uint8_t> data);

	[[nodiscard]] std::vector<std::string> enumerate_values() const;

private:
	mutable std::mutex mutex_;
	std::unordered_map<std::string, registry_value> values_;
};

class win_registry
{
public:
	[[nodiscard]] std::shared_ptr<win_registry_key> open_key(std::string_view path) const;
	std::shared_ptr<win_registry_key> create_key(std::string_view path);
	bool delete_key(std::string_view path);
	[[nodiscard]] bool key_exists(std::string_view path) const;
	[[nodiscard]] std::vector<std::string> enumerate_subkeys(std::string_view parent_path) const;

	[[nodiscard]] static std::string normalize_path(std::u16string_view guest_path);

private:
	mutable std::mutex mutex_;
	std::unordered_map<std::string, std::shared_ptr<win_registry_key>> keys_;
};
