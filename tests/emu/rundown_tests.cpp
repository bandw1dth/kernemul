#include "emu/emu.hpp"
#include "emu/x86/mmu.hpp"
#include "kernel/win/rundown.hpp"
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

void rundown_tests()
{
	auto mem = std::make_shared<x86::mmu>();
	memory_backend backend(mem);
	auto space = mem->create_addr_space();
	win::rundown_ref ref(*space, space->alloc(page, prot_rw));
	win::rundown_service service;
	auto count = ref.field(&_EX_RUNDOWN_REF::Count);
	service.initialize(ref);
	constexpr unsigned workers = 8, iterations = 2000;
	auto concurrently = [&](auto operation) {
		std::barrier start(workers);
		std::array<std::exception_ptr, workers> errors{};
		std::vector<std::jthread> threads;
		for (unsigned w = 0; w < workers; ++w) threads.emplace_back([&, w] {
			start.arrive_and_wait();
			try {
				// Independent views model hooks receiving the same guest address.
				const win::rundown_ref alias(*space, ref.address());
				for (unsigned i = 0; i < iterations; ++i) operation(alias);
			} catch (...) { errors[w] = std::current_exception(); }
		});
		threads.clear();
		for (auto error : errors) if (error) std::rethrow_exception(error);
	};
	concurrently([&](const auto& r) { require(service.acquire(r), "acquire refused"); });
	require(count.read() == workers * iterations * 2, "concurrent held refs lost increments");
	require(service.references(ref) == workers * iterations, "wrong held count");
	concurrently([&](const auto& r) { require(service.release(r), "release refused"); });
	require(count.read() == 0, "concurrent releases did not balance");
	require(!service.release(ref) && count.read() == 0, "zero underflow changed count");
	concurrently([&](const auto& r) { require(service.acquire(r), "second acquire refused"); });
	require(service.begin(ref) == workers * iterations, "begin lost held refs");
	require(count.read() == workers * iterations * 2 + 1, "begin discarded count");
	concurrently([&](const auto& r) { require(!service.acquire(r), "active acquire succeeded"); });
	concurrently([&](const auto& r) { require(service.release(r), "active release refused"); });
	require(count.read() == 1 && service.references(ref) == 0, "active drain lost state");
	require(!service.release(ref) && count.read() == 1, "active underflow changed state");
	require(service.begin(ref) == 0 && count.read() == 1, "begin not idempotent");
	// Direct guest changes must be observed, with no shadow host count.
	count.write(42);
	require(service.references(ref) == 21 && service.acquire(ref) && count.read() == 44,
		"guest count is not authoritative");
	const auto maximum = std::numeric_limits<std::uint64_t>::max() - 1;
	count.write(maximum);
	require(!service.acquire(ref) && count.read() == maximum, "acquire overflow changed count");
	service.initialize(ref);
	require(count.read() == 0 && service.acquire(ref) && service.release(ref), "reinitialize failed");
	const win::rundown_ref null;
	require(!service.acquire(null) && !service.release(null) && service.references(null) == 0 &&
		service.begin(null) == 0, "null guard failed");
	service.initialize(null);
}
}

int main()
{
	try {
		rundown_tests();
		std::cout << "PASS: exact concurrent held counts and balanced releases; active drain/refusal, underflow, overflow, guest authority, initialize, null\n";
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "FAIL: " << e.what() << '\n';
		return 1;
	}
}