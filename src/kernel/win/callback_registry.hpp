#pragma once

#include "../../emu/defs.hpp"
#include <atomic>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace win::callbacks
{

struct ob_operation
{
	addr_t object_type{};
	addr_t type{};
	std::uint32_t operations{};
	addr_t pre_operation{};
	addr_t post_operation{};
};

struct ob_registration
{
	std::uint16_t version{};
	addr_t context{};
	std::u16string altitude;
	std::vector<ob_operation> operations;
};

struct cm_registration
{
	addr_t function{};
	addr_t context{};
	std::u16string altitude;
	addr_t driver{};
};

enum class insert_status
{
	success,
	altitude_collision,
	output_write_failed,
	identifier_exhausted,
};

template <typename Id, typename Entry>
class registry
{
public:
	struct registration
	{
		Id id;
		Entry value;
		std::atomic_bool active{true};

		registration(const Id id_, Entry value_)
			: id(id_), value(std::move(value_))
		{
		}
	};

	struct insert_result
	{
		insert_status status;
		Id id{};
	};

	explicit registry(const Id first_id) noexcept
		: next_id_(first_id)
	{
	}

	template <typename WriteOutput>
	insert_result insert(Entry value, WriteOutput&& write_output)
	{
		std::lock_guard lock(mutex_);

		for (const auto& item : registrations_)
		{
			const auto& existing = item.second;
			if (existing->active.load() && existing->value.altitude == value.altitude)
				return { insert_status::altitude_collision, {} };
		}

		if (exhausted_)
			return { insert_status::identifier_exhausted, {} };

		const auto id = next_id_;
		if (next_id_ == std::numeric_limits<Id>::max())
			exhausted_ = true;
		else
			++next_id_;

		auto record = std::make_shared<registration>(id, std::move(value));
		const auto [entry, inserted] = registrations_.emplace(id, record);
		if (!inserted)
			return { insert_status::identifier_exhausted, {} };

		try
		{
			std::forward<WriteOutput>(write_output)(id);
		}
		catch (...)
		{
			record->active.store(false);
			registrations_.erase(entry);
			return { insert_status::output_write_failed, {} };
		}

		return { insert_status::success, id };
	}

	bool unregister(const Id id)
	{
		std::lock_guard lock(mutex_);
		const auto entry = registrations_.find(id);
		if (entry == registrations_.end())
			return false;

		entry->second->active.store(false);
		registrations_.erase(entry);
		return true;
	}

	[[nodiscard]] std::shared_ptr<registration> find(const Id id) const
	{
		std::lock_guard lock(mutex_);
		const auto entry = registrations_.find(id);
		return entry == registrations_.end() ? nullptr : entry->second;
	}

	[[nodiscard]] std::vector<std::shared_ptr<registration>> snapshot() const
	{
		std::lock_guard lock(mutex_);
		std::vector<std::shared_ptr<registration>> out;
		out.reserve(registrations_.size());
		for (const auto& item : registrations_)
			out.push_back(item.second);
		return out;
	}

private:
	mutable std::mutex mutex_;
	std::map<Id, std::shared_ptr<registration>> registrations_;
	Id next_id_;
	bool exhausted_{};
};

}
