// Exercise the production allocator with a deterministic MMU. Physical frames
// have unique identities so stale guard/noaccess backing is observable on reuse.
#include "kernel/win/win_user_mem.hpp"
#include "kernel/win/section_views.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>

// WDK 10.0.28000 shared/ntstatus.h: STATUS_UNABLE_TO_FREE_VM.
static_assert(STATUS_UNABLE_TO_FREE_VM == 0xC000001A);

namespace
{
struct test_space final : addr_space
{
	addr_t alloc(std::size_t, mem_prot) override { throw std::logic_error("unexpected alloc"); }
	addr_t map_phys(addr_t, std::size_t, mem_prot) override { throw std::logic_error("unexpected map_phys"); }
};

struct test_mmu final : mmu
{
	std::map<addr_t, addr_t> pages;
	unsigned protection_changes = 0;
	addr_t next_frame = 0x1000;
	bool fail_mapping = false;
	bool fail_unmapping = false;

	std::size_t page_size() const override { return 0x1000; }
	void map_virt(addr_space&, addr_t va, std::size_t size, mem_prot) override
	{
		for (std::size_t off = 0; off < size; off += page_size())
		{
			assert(!pages.contains(va + off));
			pages[va + off] = next_frame;
			next_frame += page_size();
			if (fail_mapping) throw std::bad_alloc(); // Fail after a partial map.
		}
	}
	void map_virt_phys(addr_space&, addr_t va, addr_t pa, std::size_t size, mem_prot) override
	{
		for (std::size_t off = 0; off < size; off += page_size()) pages[va + off] = pa + off;
	}
	void unmap_virt(addr_space&, addr_t va, std::size_t size) override
	{
		if (fail_unmapping) throw std::runtime_error("injected unmap failure");
		for (std::size_t off = 0; off < size; off += page_size()) pages.erase(va + off);
	}
	void read_virt(const addr_space&, addr_t, void*, std::size_t) override { assert(false); }
	void write_virt(const addr_space&, addr_t, const void*, std::size_t) override { assert(false); }
	void prot_virt(addr_space&, addr_t, std::size_t, mem_prot) override { ++protection_changes; }
	std::optional<addr_t> virt_to_phys(const addr_space&, addr_t va) override
	{
		const auto it = pages.find(va);
		return it == pages.end() ? std::nullopt : std::optional{it->second};
	}
	std::optional<addr_t> phys_to_virt(const addr_space&, addr_t) override { return std::nullopt; }
	std::shared_ptr<addr_space> create_addr_space() override { throw std::logic_error("unexpected create"); }
	void destroy_addr_space(std::shared_ptr<addr_space>) override { assert(false); }
	std::shared_ptr<addr_space> curr_addr_space(vcpu&) override { throw std::logic_error("unexpected current"); }
	void init_vcpu(vcpu&) override { assert(false); }
	void switch_to(vcpu&, std::shared_ptr<addr_space>) override { assert(false); }
};
}

int main()
{
	using namespace win;
	test_mmu mmu;
	auto space = std::make_shared<test_space>();
	space->mmu_ = &mmu;
	win_user_mem mem(space);
	const addr_t base = user_alloc_base;
	constexpr std::size_t size = 0x3000;
	auto allocate = [&] {
		auto at = base;
		auto region = size;
		assert(mem.allocate(at, region, mem_reserve | mem_commit, page_readwrite) == STATUS_SUCCESS);
		assert(at == base && region == size);
	};
	auto expect_free = [&] {
		memory_basic_info info{};
		assert(mem.query(base, info) == STATUS_SUCCESS && info.state == mem_free);
		assert(mmu.pages.empty());
		assert(!mem.handle_fault(base));
	};

	// Mapping can fail before allocate returns its address to NtMapViewOfSection.
	mmu.fail_mapping = true;
	try { allocate(); assert(false); } catch (const std::bad_alloc&) {}
	mmu.fail_mapping = false;
	expect_free();

	// Private pre-registration rollback, mapped sections, and image sections all
	// use the host teardown; the guest MEM_RELEASE path must still reject images.
	for (const auto type : {mem_private, mem_mapped, mem_image})
	{
		allocate();
		const auto old_frames = mmu.pages;
		if (type != mem_private)
			mem.register_section_view(base, size, type == mem_image, page_readwrite);
		memory_basic_info info{};
		assert(mem.query(base, info) == STATUS_SUCCESS && info.type == type);
		if (type != mem_private)
		{
			auto at = base;
			std::size_t region = 0;
			assert(mem.free(at, region, mem_release) == STATUS_UNABLE_TO_FREE_VM);
			assert(at == base && region == 0 && mmu.pages == old_frames);
		}
		for (unsigned i = 0; i < 2; ++i)
		{
			auto at = base + i * 0x1000;
			std::size_t region = 0x1000;
			std::uint32_t old_prot;
			assert(mem.protect(at, region, i ? page_noaccess : page_readwrite | page_guard,
				old_prot) == STATUS_SUCCESS);
		}
		assert(mmu.pages.size() == 1);
		assert(mem.release_view(base + 0x1000) == STATUS_UNABLE_TO_FREE_VM);
		section_views views;
		assert(views.insert(4, base, size));
		auto teardown = [&](auto) { return mem.release_view(base) == STATUS_SUCCESS; };
		assert(!views.remove(8, base, teardown));
		assert(views.remove(4, base, teardown));
		assert(!views.remove(4, base, teardown));
		assert(mem.release_view(base) == STATUS_UNABLE_TO_FREE_VM);
		expect_free();
		allocate();
		for (const auto& [va, pa] : mmu.pages) assert(pa != old_frames.at(va));
		assert(mem.release_view(base) == STATUS_SUCCESS);
		expect_free();
	}

	// The exact classifier used before NtMapViewOfSection publishes outputs must
	// prevent free/reuse from leaving a stale view owning a private replacement.
	{
		allocate();
		mem.register_section_view(base, size, false, page_readwrite);
		section_views data_views;
		assert(data_views.insert(4, base, size));
		memory_basic_info info{};
		assert(mem.query(base, info) == STATUS_SUCCESS && info.type == mem_mapped);
		const auto mapped_frames = mmu.pages;
		auto at = base + 1;
		std::size_t region = 0;
		assert(mem.free(at, region, mem_release) == STATUS_UNABLE_TO_FREE_VM);
		assert(at == base + 1 && region == 0 && mmu.pages == mapped_frames);
		at = base;
		region = size * 2;
		assert(mem.allocate(at, region, mem_reserve | mem_commit, page_readwrite)
			== STATUS_CONFLICTING_ADDRESSES);
		assert(at == base && region == size * 2 && mmu.pages == mapped_frames);
		auto unmap = [&](auto) { return mem.release_view(base) == STATUS_SUCCESS; };
		assert(data_views.remove(4, base, unmap));
		expect_free();
		assert(mem.allocate(at, region, mem_reserve | mem_commit, page_readwrite) == STATUS_SUCCESS);
		const auto replacement_frames = mmu.pages;
		assert(!data_views.remove(4, base, unmap));
		assert(mmu.pages == replacement_frames && mmu.pages.size() == size * 2 / mmu.page_size());
		assert(mem.query(base, info) == STATUS_SUCCESS && info.type == mem_private && info.region_size == size * 2);
		region = 0;
		assert(mem.free(at, region, mem_release) == STATUS_SUCCESS);
		expect_free();
	}

	// An unsuccessful host teardown retains reservation and ownership for retry.
	allocate();
	mem.register_image(base, size);
	const auto guarded_frame = mmu.pages.at(base);
	auto guarded_at = base;
	std::size_t guarded_size = 0x1000;
	std::uint32_t guarded_previous;
	assert(mem.protect(guarded_at, guarded_size, page_readwrite | page_guard,
		guarded_previous) == STATUS_SUCCESS);
	section_views views;
	assert(views.insert(4, base, size));
	auto teardown = [&](auto) { return mem.release_view(base) == STATUS_SUCCESS; };
	mmu.fail_unmapping = true;
	try { views.remove(4, base, teardown); assert(false); } catch (const std::runtime_error&) {}
	memory_basic_info info{};
	assert(mem.query(base, info) == STATUS_SUCCESS && info.type == mem_image);
	mmu.fail_unmapping = false;
	assert(mem.handle_fault(base));
	assert(mmu.pages.at(base) == guarded_frame); // Failed teardown retained hidden backing.
	assert(views.remove(4, base, teardown));
	expect_free();

	allocate();
	mem.register_image(base, size, page_readonly, true);
	for (const auto prot : {page_execute, page_execute_read, page_execute_readwrite,
		page_execute_writecopy, page_execute_read | page_guard})
	{
		for (const auto start : {base - 0x1000, base, base + 0x1001})
		{
			auto at = start;
			std::size_t region = 0x4000;
			std::uint32_t previous = 0xDEADBEEF;
			const auto changes = mmu.protection_changes;
			assert(mem.protect(at, region, prot, previous) == STATUS_SECTION_PROTECTION);
			assert(at == start && region == 0x4000 && previous == 0xDEADBEEF);
			assert(mmu.protection_changes == changes);
		}
	}
	for (const auto prot : {page_readwrite, page_readonly})
	{
		auto at = base + 1;
		std::size_t region = 1;
		std::uint32_t previous;
		assert(mem.protect(at, region, prot, previous) == STATUS_SUCCESS);
		assert(at == base && region == 0x1000);
	}
	// Recommit is another exposed path that changes an existing reservation's protection.
	auto at = base;
	std::size_t region = size;
	assert(mem.allocate(at, region, mem_commit, page_execute_readwrite) == STATUS_SECTION_PROTECTION);
	assert(mem.query(base, info) == STATUS_SUCCESS && info.protect == page_readonly);
	for (const auto start : {base + 1, ~addr_t{0} - 0x1000})
	{
		at = start;
		region = ~std::size_t{0};
		std::uint32_t previous = 0xDEADBEEF;
		assert(mem.protect(at, region, page_execute_read, previous) == STATUS_INVALID_PARAMETER);
		assert(at == start && region == ~std::size_t{0} && previous == 0xDEADBEEF);
		assert(mem.allocate(at, region, mem_commit, page_execute_read) == STATUS_INVALID_PARAMETER);
	}
	at = ~addr_t{0} - 0x1000;
	region = 0x2000; // Size rounding fits, but the rounded range end overflows.
	std::uint32_t previous = 0xDEADBEEF;
	assert(mem.protect(at, region, page_execute_read, previous) == STATUS_INVALID_PARAMETER);
	assert(at == ~addr_t{0} - 0x1000 && region == 0x2000 && previous == 0xDEADBEEF);
	assert(mem.release_view(base) == STATUS_SUCCESS);
	allocate();
	mem.register_image(base, size); // Ordinary images remain executable/reprotectable.
	at = base;
	region = size;
	previous = 0;
	assert(mem.protect(at, region, page_execute_readwrite, previous) == STATUS_SUCCESS);
	assert(mem.release_view(base) == STATUS_SUCCESS);
	expect_free();
	std::cout << "win_user_mem_model: PASS\n";
}
