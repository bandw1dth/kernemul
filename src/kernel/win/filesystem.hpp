#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

class win_file
{
public:
	win_file() = default;
	explicit win_file(std::vector<std::uint8_t> data) : data_(std::move(data)) {}

	[[nodiscard]] std::span<const std::uint8_t> data() const { return data_; }
	[[nodiscard]] std::span<std::uint8_t> data() { return data_; }
	[[nodiscard]] std::size_t size() const noexcept { return data_.size(); }

	void write(std::span<const std::uint8_t> buf);
	void write(const void* buf, std::size_t size);

private:
	std::vector<std::uint8_t> data_;
};

class win_filesystem
{
public:
	struct dir_entry
	{
		std::string name;
		bool is_directory = false;
		std::uint64_t size = 0;
	};

	[[nodiscard]] std::shared_ptr<win_file> open(std::string_view path) const;
	std::shared_ptr<win_file> create(std::string_view path);
	bool remove(std::string_view path);
	[[nodiscard]] bool exists(std::string_view path) const;
	[[nodiscard]] bool dir_exists(std::string_view path) const;

	// A directory holding no files is otherwise unrepresentable: a directory is normally
	// inferred from the files under it, and an empty one has none to infer it from.
	void create_directory(std::string_view path);

	// The same file under a second name, sharing its bytes rather than copying them.
	bool link(std::string_view from, std::string_view to);

	[[nodiscard]] std::vector<dir_entry> list_dir(std::string_view path) const;

	struct file_enumeration
	{
		std::vector<std::string> paths;
		std::size_t examined = 0;
		bool limit_exceeded = false;
	};
	// One bounded pass over files_, including nonmatches in examined. Does not visit
	// empty directories. Paths and suffix matching are normalized, paths are unsorted.
	// Limits are checked before inspecting another entry or copying another match.
	// A limit_exceeded result is incomplete; callers must not treat it as exhaustive.
	[[nodiscard]] file_enumeration enumerate_files_under(std::string_view directory,
		std::string_view suffix, std::size_t max_examined, std::size_t max_results) const;

	bool load_file(const std::filesystem::path& host_path, std::string_view virtual_path);
	bool load_dir(const std::filesystem::path& host_dir, std::string_view virtual_path);

	[[nodiscard]] static std::string normalize(std::string_view path);

private:
	std::unordered_map<std::string, std::shared_ptr<win_file>> files_;

	// Only the ones nothing else implies. A directory with files under it is still inferred,
	// so this does not have to be kept in step with every create().
	std::set<std::string> dirs_;
};
