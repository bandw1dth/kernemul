#include "emu/emu.hpp"
#include "emu/x86/mmu.hpp"
#include <algorithm>
#include <array>
#include <barrier>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>

namespace {
constexpr std::size_t page = 0x1000;
void require(bool ok, const char* message)
{
	if (!ok) throw std::runtime_error(message);
}

// Only physical storage is substituted; allocation, page tables, translations and
// virtual reads/writes all use the production MMU. No executing vCPUs are needed.
class memory_backend final : public emu {
public:
	explicit memory_backend(std::shared_ptr<::mmu> mem) : emu({}, std::move(mem)) {}
	bool fail_mapping = false;
	void map_phys_mem(addr_t pa, std::size_t size) override
	{
		std::lock_guard lock(mutex_);
		if (std::exchange(fail_mapping, false)) throw std::runtime_error("injected mapping failure");
		for (std::size_t off = 0; off < size; off += page) pages_.try_emplace(pa + off);
	}
	void read_phys_mem(addr_t pa, void* buf, std::size_t size) override { copy(pa, buf, size, false); }
	void write_phys_mem(addr_t pa, const void* buf, std::size_t size) override
	{ copy(pa, const_cast<void*>(buf), size, true); }
	void unmap_phys_mem(addr_t, std::size_t, mem_prot) override { throw std::runtime_error("unexpected unmap"); }
	hook_handle hook_mem(addr_t, addr_t, mem_prot, mem_hk_cb, ::addr_space*) override { return nullptr; }
	hook_handle hook_insn(addr_t, addr_t, hook_insn_t, insn_hk_cb) override { return nullptr; }
	hook_handle hook_code(addr_t, addr_t, code_hk_cb) override { return nullptr; }
	hook_handle hook_basic_block(addr_t, addr_t, code_hk_cb) override { return nullptr; }
	hook_handle hook_invalid_mem(mem_prot, invalid_mem_hk_cb) override { return nullptr; }
	hook_handle hook_exception(exception_hk_cb) override { return nullptr; }
	void remove_hook(hook_handle) override {}
protected:
	std::shared_ptr<vcpu> create_vcpu(std::size_t) override { throw std::runtime_error("unexpected vCPU"); }
private:
	std::mutex mutex_;
	std::map<addr_t, std::array<std::byte, page>> pages_;
	void copy(addr_t pa, void* buf, std::size_t size, bool write)
	{
		std::lock_guard lock(mutex_);
		auto* bytes = static_cast<std::byte*>(buf);
		while (size) {
			const auto off = static_cast<std::size_t>(pa % page);
			const auto count = std::min(size, page - off);
			auto* physical = pages_.at(pa - off).data() + off;
			if (write) std::memcpy(physical, bytes, count);
			else std::memcpy(bytes, physical, count);
			pa += count; bytes += count; size -= count;
		}
	}
};

// Pause at the virtual mapping boundary, after the allocator reserved its range.
// A second allocator must not enter mapping until the first one has completed.
class gated_mmu final : public x86::mmu {
public:
	std::mutex gate_mutex;
	std::condition_variable gate_cv;
	unsigned entered = 0;
	bool release = false;
	void map_virt(::addr_space& s, addr_t va, std::size_t size, mem_prot prot) override
	{ gate(); x86::mmu::map_virt(s, va, size, prot); }
	void map_virt_phys(::addr_space& s, addr_t va, addr_t pa, std::size_t size, mem_prot prot) override
	{ gate(); x86::mmu::map_virt_phys(s, va, pa, size, prot); }
private:
	void gate()
	{
		std::unique_lock lock(gate_mutex);
		++entered;
		gate_cv.notify_all();
		gate_cv.wait(lock, [&] { return release; });
	}
};

void mapping_serialization(bool physical_first, mem_prot prot)
{
	auto mem = std::make_shared<gated_mmu>();
	memory_backend backend(mem);
	auto space = mem->create_addr_space();
	const auto pa = mem->alloc_phys(page, prot_rw);
	auto allocate = [&](bool physical) {
		return physical ? space->map_phys(pa, page, prot) : space->alloc(page, prot);
	};
	auto first = std::async(std::launch::async, allocate, physical_first);
	{
		std::unique_lock lock(mem->gate_mutex);
		mem->gate_cv.wait(lock, [&] { return mem->entered == 1; });
	}
	std::promise<void> started;
	auto second = std::async(std::launch::async, [&] {
		started.set_value();
		return allocate(!physical_first);
	});
	started.get_future().wait();
	bool overlap;
	{
		std::unique_lock lock(mem->gate_mutex);
		overlap = mem->gate_cv.wait_for(lock, std::chrono::milliseconds(150), [&] { return mem->entered > 1; });
		mem->release = true;
	}
	mem->gate_cv.notify_all();
	const auto a = first.get(), b = second.get();
	require(!overlap, "second allocation entered mapping before first completed");
	require(b == a + page, "serialized allocations must be adjacent");
}

void concurrent_pages(mem_prot prot)
{
	auto mem = std::make_shared<x86::mmu>();
	memory_backend backend(mem);
	auto space = mem->create_addr_space();
	constexpr unsigned workers = 8, iterations = 128;
	struct allocation { addr_t va, pa; std::size_t size; std::uint64_t tag; };
	std::array<std::vector<allocation>, workers> results;
	std::array<std::exception_ptr, workers> errors{};
	std::barrier start(workers);
	std::vector<std::jthread> threads;
	for (unsigned worker = 0; worker < workers; ++worker) threads.emplace_back([&, worker] {
		start.arrive_and_wait();
		try {
			for (unsigned i = 0; i < iterations; ++i) {
				const auto size = (i % 3 + 1) * page;
				const auto pa = i % 2 ? mem->alloc_phys(size, prot_rw) : 0;
				// Exercise rounding in alloc, and the page-aligned map_phys contract.
				const auto va = pa ? space->map_phys(pa, size, prot) : space->alloc(size - 17, prot);
				const auto tag = std::uint64_t(worker * iterations + i + 1);
				for (std::size_t off = 0; off < size; off += page) {
					space->write_mem(va + off, tag);
					space->write_mem(va + off + page - sizeof(tag), tag);
				}
				results[worker].push_back({va, pa, size, tag});
			}
		} catch (...) { errors[worker] = std::current_exception(); }
	});
	threads.clear();
	for (auto error : errors) if (error) std::rethrow_exception(error);
	std::vector<allocation> all;
	for (const auto& batch : results) all.insert(all.end(), batch.begin(), batch.end());
	std::sort(all.begin(), all.end(), [](auto a, auto b) { return a.va < b.va; });
	addr_t next = prot & prot_supervisor ? 0xFFFFF80000000000 : 0x10000;
	for (const auto& a : all) {
		require(a.va == next, "allocation pages overlap or cursor lost a reservation");
		next += a.size;
		for (std::size_t off = 0; off < a.size; off += page) {
			const auto translated = mem->virt_to_phys(*space, a.va + off);
			require(translated.has_value(), "missing page mapping");
			if (a.pa) require(*translated == a.pa + off, "physical mapping changed");
			require(space->read_mem<std::uint64_t>(a.va + off) == a.tag, "page data overwritten");
			require(space->read_mem<std::uint64_t>(a.va + off + page - sizeof(a.tag)) == a.tag, "page end overwritten");
		}
	}
}

void failed_mapping()
{
	auto mem = std::make_shared<x86::mmu>();
	memory_backend backend(mem);
	auto space = mem->create_addr_space();
	backend.fail_mapping = true;
	bool failed = false;
	try { space->alloc(page, prot_rw); } catch (const std::runtime_error&) { failed = true; }
	require(failed, "failure injection did not run");
	const auto va = space->alloc(page, prot_rw);
	require(va == 0x11000, "failed reservation must remain consumed");
	space->write_mem<std::uint64_t>(va, 42);
	require(space->read_mem<std::uint64_t>(va) == 42, "allocation did not recover after failure");
}
}

int main()
{
	try {
		for (const auto prot : {prot_rw, prot_rw | prot_supervisor}) {
			mapping_serialization(false, prot);
			mapping_serialization(true, prot);
			concurrent_pages(prot);
		}
		failed_mapping();
		std::cout << "PASS: serialized mapping, 2048 concurrent allocations, translations/data, failure recovery\n";
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "FAIL: " << e.what() << '\n';
		return 1;
	}
}
