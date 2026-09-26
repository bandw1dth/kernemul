#include "process.hpp"
#include "thread.hpp"
#include "win_kernel.hpp"
#include "../thread_scheduler.hpp"
#include "../../util/log.hpp"

NTSTATUS win_kernel_state::call_registry_notify(vcpu& cpu,
	const win::registry_notify_service::record& registration,
	const std::uint32_t notification, const addr_t information)
{
	const auto caller = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	auto* const emu = emulator();
	const auto scheduler = sys_proc->scheduler();
	auto fail = [&](const char* reason) -> void {
		THREAD_LOG_ERR("registry notify: {}", reason);
		if (scheduler) scheduler->stop();
		cpu.stop();
		throw std::runtime_error(reason);
	};
	if (!caller || !caller->ethread() || !emu || cpu.in_dpc || emu->irql(cpu) != passive_level)
		fail("callback requires a thread at PASSIVE_LEVEL");
	const auto irql = emu->irql(cpu);
	const auto kernel = caller->kernel_apc_disable().read();
	const auto special = caller->special_apc_disable().read();
	const auto sleep = caller->sleep_until();
	auto restore = [&] {
		emu->set_irql(cpu, irql);
		caller->kernel_apc_disable().write(kernel);
		caller->special_apc_disable().write(special);
	};
	const std::uint64_t args[] = {registration.value.context, notification, information};
	++win::registry_callback_depth;
	try
	{
		const auto result = static_cast<NTSTATUS>(calls.call(cpu, registration.value.function, args, 0, [&] {
			if (caller->suspend_count() || caller->is_waiting() || caller->sleep_until() != sleep)
				fail("callback cannot block or suspend");
			return cpu.dpc_failed || cpu.execution_failed() || caller->is_finished()
				|| (scheduler && scheduler->stopped());
		}));
		if (emu->irql(cpu) != irql || caller->kernel_apc_disable().read() != kernel
			|| caller->special_apc_disable().read() != special)
			fail("callback returned with unbalanced IRQL/APC context");
		restore();
		--win::registry_callback_depth;
		return result;
	}
	catch (...)
	{
		--win::registry_callback_depth;
		if (scheduler) scheduler->stop();
		cpu.stop();
		restore();
		THREAD_LOG_ERR("registry notify: callback failed before returning; stopped");
		THREAD_LOG_INFO("registry notify: restored irql={}, kernel_apc_disable={}, special_apc_disable={}",
			emu->irql(cpu), caller->kernel_apc_disable().read(), caller->special_apc_disable().read());
		throw;
	}
}

[[noreturn]] void win_kernel_state::fail_thread_notify(vcpu& cpu, const char* reason)
{
	THREAD_LOG_ERR("thread notify: {}", reason);
	if (const auto scheduler = sys_proc->scheduler()) scheduler->stop();
	cpu.stop();
	throw std::runtime_error(reason);
}

void win_kernel_state::notify_thread(vcpu& cpu, const win_thread& target, const bool create)
{
	const auto snapshot = thread_notify.snapshot();
	if (snapshot.empty()) return;
	const auto* pcpu = per_cpu(cpu.id());
	if (cpu.in_dpc || (pcpu && pcpu->irql() > apc_level))
		fail_thread_notify(cpu, "classic callback requires PASSIVE_LEVEL or APC_LEVEL");
	const auto caller = cpu.thread();
	const auto win_caller = std::dynamic_pointer_cast<win_thread>(caller);
	const auto sleep_before = caller ? caller->sleep_until() : thread::time_point{};
	const auto scheduler = sys_proc->scheduler();
	const auto irql_before = pcpu ? pcpu->irql() : passive_level;
	const auto kernel_apc_before = win_caller ? win_caller->kernel_apc_disable().read() : 0;
	const auto special_apc_before = win_caller ? win_caller->special_apc_disable().read() : 0;
	const auto cid = target.client_id().read();
	const std::uint64_t args[] = { guest_va(cid.UniqueProcess), guest_va(cid.UniqueThread), create ? 1u : 0u };
	for (const auto& registration : snapshot)
	{
		if (!thread_notify.acquire(registration, cpu.id())) continue;
		try
		{
			calls.call(cpu, registration->routine, args, 0, [&]
			{
				if (win_caller && win_caller->suspend_count())
					fail_thread_notify(cpu, "suspended lifecycle callbacks are unsupported");
				if ((win_caller && win_caller->is_waiting())
					|| (caller && caller->sleep_until() != sleep_before))
					fail_thread_notify(cpu, "blocking guest callbacks are unsupported");
				return cpu.dpc_failed || cpu.execution_failed() || (scheduler && scheduler->stopped())
					|| (caller && caller->is_finished());
			});
			if ((pcpu && pcpu->irql() != irql_before)
				|| (win_caller && (win_caller->kernel_apc_disable().read() != kernel_apc_before
					|| win_caller->special_apc_disable().read() != special_apc_before)))
				fail_thread_notify(cpu, "callback returned with an unbalanced IRQL/APC context");
		}
		catch (...)
		{
			thread_notify.release(registration, cpu.id());
			if (scheduler) scheduler->stop();
			cpu.stop();
			throw;
		}
		thread_notify.release(registration, cpu.id());
	}
}

void win_kernel_state::notify_image(vcpu& cpu, const std::string_view path,
	const addr_t base, const std::uint64_t size)
{
	const auto snapshot = image_notify.snapshot();
	if (snapshot.empty()) return;
	const auto caller = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	auto* const emu = emulator();
	if (!caller || !caller->ethread() || !emu || cpu.in_dpc || emu->irql(cpu) != passive_level)
		fail_thread_notify(cpu, "image callback requires a thread at PASSIVE_LEVEL");
	// IMAGE_INFO, with no extended information, trust claims or driver-load flags.
	struct image_info
	{
		std::uint32_t properties = 0, padding = 0;
		std::uint64_t base = 0;
		std::uint32_t selector = 0, padding2 = 0;
		std::uint64_t size = 0;
		std::uint32_t section = 0, padding3 = 0;
	};
	static_assert(sizeof(image_info) == 40);
	// The pool reuses scratch after delivery, including exceptional exits. The
	// UNICODE_STRING length is bounded by its 16-bit byte count.
	const auto name = widen_string(path.substr(0, 32766));
	const pool_block scratch(pool, sizeof(image_info) + sizeof(_UNICODE_STRING)
		+ (name.size() + 1) * sizeof(char16_t), pool_tag("ImNt"));
	if (!scratch.addr()) fail_thread_notify(cpu, "image notification scratch allocation failed");
	auto& space = *cpu.curr_addr_space();
	const auto info_address = scratch.addr();
	const auto name_address = info_address + sizeof(image_info);
	const auto buffer = name_address + sizeof(_UNICODE_STRING);
	_UNICODE_STRING us{};
	us.Length = static_cast<unsigned short>(name.size() * sizeof(char16_t));
	us.MaximumLength = us.Length + sizeof(char16_t);
	us.Buffer = guest_ptr<char16_t>(buffer);
	space.write_mem(info_address, image_info{.base = base, .size = size});
	space.write_mem(name_address, us);
	space.write_mem(buffer, name.c_str(), us.MaximumLength);
	const std::uint64_t args[] = {name_address, caller->proc()->id(), info_address};
	const auto irql_before = emu->irql(cpu);
	const auto kernel_before = caller->kernel_apc_disable().read();
	const auto special_before = caller->special_apc_disable().read();
	const auto sleep_before = caller->sleep_until();
	const auto scheduler = sys_proc->scheduler();
	if (kernel_before == std::numeric_limits<std::int16_t>::min())
		fail_thread_notify(cpu, "image callback critical-region counter overflow");
	const auto disabled = static_cast<std::int16_t>(kernel_before - 1);
	auto restore = [&] {
		emu->set_irql(cpu, irql_before);
		caller->kernel_apc_disable().write(kernel_before);
		caller->special_apc_disable().write(special_before);
	};
	for (const auto& registration : snapshot)
	{
		if (!image_notify.acquire(registration, cpu.id())) continue;
		++win::image_callback_depth;
		try
		{
			caller->kernel_apc_disable().write(disabled);
			calls.call(cpu, registration->routine, args, 0, [&] {
				if (caller->suspend_count() || caller->is_waiting() || caller->sleep_until() != sleep_before)
					fail_thread_notify(cpu, "image callback cannot block or suspend");
				return cpu.dpc_failed || cpu.execution_failed() || caller->is_finished()
					|| (scheduler && scheduler->stopped());
			});
			if (emu->irql(cpu) != passive_level || caller->kernel_apc_disable().read() != disabled
				|| caller->special_apc_disable().read() != special_before)
				fail_thread_notify(cpu, "image callback returned with unbalanced IRQL/APC context");
			restore();
		}
		catch (...)
		{
			--win::image_callback_depth;
			image_notify.release(registration, cpu.id());
			if (scheduler) scheduler->stop();
			cpu.stop();
			restore();
			THREAD_LOG_INFO("image notify: restored irql={}, kernel_apc_disable={}, special_apc_disable={}",
				emu->irql(cpu), caller->kernel_apc_disable().read(), caller->special_apc_disable().read());
			throw;
		}
		--win::image_callback_depth;
		image_notify.release(registration, cpu.id());
	}
}

void win_kernel_state::finish_thread(vcpu& cpu, const NTSTATUS status)
{
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	if (!t) return;
	if (in_lifecycle_callback(cpu.id()))
		fail_thread_notify(cpu, "a thread cannot terminate inside a lifecycle callback");
	if (t->is_finished() || t->exit_notification_started) return;
	t->set_exit_status(status);
	t->exit_notification_started = true;
	try { notify_thread(cpu, *t, false); }
	catch (...) { fail_thread_notify(cpu, "exit callback failed before thread completion"); }
	t->finish();
}

win_kernel_proc::win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space)
	:	windows_process(id, std::move(space), kernel.objs, kernel.fs), kernel_(kernel) {}

addr_t windows_process::find_symbol(const std::string_view mod_name,
	const std::string_view sym) const
{
	if (const auto mod = find_module(mod_name))
	{
		if (const auto addr = mod->find_symbol(sym))
			return *addr;
	}

	LOG_ERR("{}!{} not found", mod_name, sym);
	return 0;
}

std::shared_ptr<thread> windows_process::create_suspended_thread(vcpu& cpu,
	const addr_t start_addr, const std::span<const std::uint64_t> args,
	const std::size_t stack_size)
{
	const auto id = static_cast<thread_id_type>(objs_.allocate_id());
	const auto size = thread_stack_size(stack_size);

	const addr_t stack_base = addr_space_->alloc(size, prot_rw | prot_supervisor);
	if (!stack_base) return {};
	auto self = std::static_pointer_cast<windows_process>(shared_from_this());
	auto t = std::make_shared<win_kernel_thread>(
		id, std::move(self), start_addr, stack_base, size, cpu);

	t->set_emulator(emulator_);
	setup_ethread(t, start_addr);

	try
	{
		{
			std::unique_lock lock(thread_mtx_);
			threads_[t->id()] = t;
		}
		// On the queue, but no cpu takes it until it is started.
		scheduler_->enqueue(cpu, t, args);
	}
	catch (...)
	{
		destroy_ethread(*t);
		process::terminate_thread(t->id());
		throw;
	}
	return t;
}

std::shared_ptr<thread> win_user_proc::create_suspended_thread(vcpu& cpu,
	const addr_t start_addr, const std::span<const std::uint64_t> args,
	const std::size_t stack_size)
{
	const auto id = static_cast<thread_id_type>(objs_.allocate_id());
	const auto size = thread_stack_size(stack_size);

	const addr_t stack_base = mem_.alloc(size, prot_rw);
	auto self = std::static_pointer_cast<windows_process>(shared_from_this());
	auto t = std::make_shared<win_user_thread>(
		id, std::move(self), mem_, start_addr, stack_base, size, cpu);

	t->set_emulator(emulator_);
	setup_ethread(t, start_addr);

	emulator_->init_thread_teb(*t, cpu, t->teb().address());

	{
		std::unique_lock lock(thread_mtx_);
		threads_[t->id()] = t;
	}

	scheduler_->enqueue(cpu, t, args);
	return t;
}

void windows_process::setup_ethread(const std::shared_ptr<win_thread>& t, const addr_t start_addr)
{
	if (!emulator_)
		return;

	auto& space = *emulator_->emu().default_addr_space();

	ethread_params p{};
	p.eprocess = eprocess_.address();
	p.start_addr = start_addr;
	p.teb = t->teb().address();
	p.stack_limit = t->stack_limit();
	p.stack_base = t->stack_base();
	p.process_id = id_;
	p.thread_id = t->id();
	p.system_thread = t->is_system_thread();

	const auto et = make_default_ethread(p);

	auto obj = emu_object<_ETHREAD>(space,
		objs_.create_object(0, &et, sizeof(et), std::make_shared<thread_object>(t),
			prot_rw | prot_supervisor));

	t->set_ethread(obj);
	if (!obj) return;

	if (!eprocess_)
		return;

	auto& espace = *eprocess_.space();

	std::scoped_lock lock(emulator_->kernel().list_mtx_);

	kprocess_thread_list(espace, eprocess_.address()).push_back(obj);
	eprocess_thread_list(espace, eprocess_.address()).push_back(obj);

	auto active = eprocess_.field(&_EPROCESS::ActiveThreads);
	active.write(active.read() + 1);
}

void windows_process::destroy_ethread(const win_thread& t)
{
	const auto& et = t.ethread();

	if (!et || !emulator_)
		return;

	set_thread_state(et, Terminated, false);
	set_thread_exit_time(et, win_system_time());
	set_thread_exit_status(et, t.exit_status());

	win::set_state_at(*et.space(), et.address(), 1);
	wake_waiters(*et.space(), et.address());

	if (!eprocess_)
		return;

	auto& espace = *eprocess_.space();

	std::scoped_lock lock(emulator_->kernel().list_mtx_);

	kprocess_thread_list(espace, eprocess_.address()).remove(et.address());
	eprocess_thread_list(espace, eprocess_.address()).remove(et.address());

	auto active = eprocess_.field(&_EPROCESS::ActiveThreads);

	if (const auto count = active.read(); count > 0)
		active.write(count - 1);
}

void windows_process::terminate_thread(const thread_id_type id)
{
	// Nothing frees the ETHREAD, so it is only unlinked.
	if (const auto t = std::dynamic_pointer_cast<win_thread>(find_thread(id)))
		destroy_ethread(*t);

	process::terminate_thread(id);
}

std::shared_ptr<win_file> windows_process::open_system_image(const std::string_view name) const
{
	if (auto file = fs_.open(std::string(system32_dir_narrow) + std::string(name)))
		return file;

	return fs_.open(std::string(system32_dir_narrow) + "drivers/" + std::string(name));
}

// There is no loader in the guest behind a driver, so the imports are resolved here.
std::shared_ptr<proc_module> win_kernel_proc::load_module(const std::string_view name,
	const bool supervisor)
{
	const auto file = open_system_image(name);

	if (!file)
		return nullptr;

	return krnl::map_img(*this, name, file->data(), supervisor);
}

// A user image resolves its own; doing it here too would map every module a second time.
std::shared_ptr<proc_module> win_user_proc::load_module(const std::string_view name,
	const bool supervisor)
{
	auto file = fs_.open(current_dir_ + std::string(name));

	if (!file)
		file = open_system_image(name);

	// Last, so nothing in the root can stand in front of a real system module. A process is
	// created from a bare name, which leaves it no directory of its own to look in, and the
	// guest filesystem is loaded from a host directory whose root is where an image dropped in
	// to be run actually lands -- so without this the only place a user image can be started
	// from is System32, and a copy left in the root is loaded and then reported missing.
	if (!file)
		file = fs_.open(std::string(root_dir_narrow) + std::string(name));

	if (!file)
		return nullptr;

	return krnl::map_img(*this, name, file->data(), supervisor, true);
}

void win_user_proc::module_add_cb(proc_module& mod)
{
	mem_.register_image(mod.addr, mod.size);

	const bool image = is_process_image(mod);

	ldr_.add_module(mem_, mod.addr, mod.entry_point, mod.size, mod.name,
		!image, image ? ldr_module_list::image_flags : ldr_module_list::dll_flags);
}

void win_kernel_proc::module_add_cb(proc_module& mod)
{
	if (!kernel_.loaded_module_list.address())
		return;

	auto& space = *addr_space_;

	_KLDR_DATA_TABLE_ENTRY entry{};
	entry.DllBase = reinterpret_cast<void*>(mod.addr);
	entry.EntryPoint = reinterpret_cast<void*>(mod.entry_point);
	entry.SizeOfImage = mod.size;

	// A nameless entry is most of the way to useless: code that walks this list is looking for
	// a module by name, so without one it can only ever match on an address it already had.
	const auto wide_name = widen_string(mod.name);

	entry.BaseDllName = win::init_unicode_string(space, wide_name, prot_rw | prot_supervisor);

	// What the kernel reports, which is never a drive letter: a driver goes under drivers\,
	// everything else sits in system32 itself.
	const std::u16string dir = mod.lookup_name.ends_with(".sys")
		? u"\\SystemRoot\\System32\\drivers\\"
		: u"\\SystemRoot\\System32\\";

	entry.FullDllName = win::init_unicode_string(space, dir + wide_name, prot_rw | prot_supervisor);

	std::scoped_lock lock(kernel_.list_mtx_);
	const auto obj = kernel_.loaded_module_list.push_back(entry);

	kernel_.set_ldr_entry(mod.addr, obj.address());
}

std::shared_ptr<win_thread> windows_process::find_ethread(
	const emu_object<_ETHREAD>& ethread) const
{
	std::shared_lock lock(thread_mtx_);

	for (const auto& [id, t] : threads_)
	{
		const auto win_t = std::dynamic_pointer_cast<win_thread>(t);

		if (win_t && win_t->ethread().address() == ethread.address())
			return win_t;
	}

	return {};
}

void windows_process::for_each_thread(const std::function<void(win_thread&)>& fn) const
{
	std::shared_lock lock(thread_mtx_);

	for (const auto& [id, t] : threads_)
	{
		if (const auto win_t = std::dynamic_pointer_cast<win_thread>(t))
			fn(*win_t);
	}
}

void windows_process::wake_waiters(struct addr_space& space, const addr_t object) const
{
	bool released = false;

	for_each_thread([&](win_thread& t)
	{
		if (t.waiting_on(object) && t.try_satisfy(space))
		{
			THREAD_LOG_INFO("wait on 0x{:X} satisfied for tid={}", object, t.id());
			released = true;
		}
	});

	// Satisfying the wait is only half of releasing the thread: it is runnable again without
	// having been queued, and a cpu parked on an empty answer does not look a second time on
	// its own. An untimed wait leaves nothing for next_wake() to arm either, so that cpu waits
	// on a notify that never comes. start() and resume() are the other two ways a thread turns
	// runnable out of band, and both say so exactly here.
	if (released)
	{
		if (const auto s = scheduler())
			s->wake();
	}
}
