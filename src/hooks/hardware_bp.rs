use crate::hooks::common::*;
use std::sync::{
    atomic::{AtomicPtr, Ordering},
    Mutex,
};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, GetThreadContext, RemoveVectoredExceptionHandler,
    SetThreadContext, CONTEXT, CONTEXT_FLAGS, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
    THREAD_ALL_ACCESS,
};

// STATUS_SINGLE_STEP is the exception code raised when a hardware breakpoint fires
const STATUS_SINGLE_STEP: i32 = 0x80000004u32 as i32;
// Resume Flag in EFlags: when set, ignores instruction breakpoints for the next instruction
const EFLAGS_RF: u32 = 0x00010000;

// x64 context flags — MUST include the CONTEXT_AMD64 (0x00100000) architecture prefix
// without it, Get/SetThreadContext silently ignores the debug register fields
const CONTEXT_AMD64: u32 = 0x00100000;
const CTX_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;
const CTX_CONTROL: u32 = CONTEXT_AMD64 | 0x00000001;
const CTX_FULL_DEBUG: u32 = CTX_DEBUG_REGISTERS | CTX_CONTROL;

// hardware breakpoint (dr0-dr3) based hooking
// uses the cpu debug registers to intercept execution without modifying code bytes

pub struct HardwareBreakpointHook {
    pub target_address: *const u8,
    // the handler to call when the breakpoint fires — receives the full cpu context
    pub callback: Option<unsafe fn(&mut CONTEXT)>,
    pub dr_index: u32,
}

unsafe impl Send for HardwareBreakpointHook {}
unsafe impl Sync for HardwareBreakpointHook {}

static ACTIVE_BREAKPOINTS: Mutex<Vec<HardwareBreakpointHook>> = Mutex::new(Vec::new());

// holds the opaque handle returned by AddVectoredExceptionHandler
static VEH_HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

// the vectored exception handler that fires on every STATUS_SINGLE_STEP exception.
// we check if the faulting address matches one of our HWBP targets and invoke the callback.
unsafe extern "system" fn hwbp_veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exc = &*exception_info;
    if exc.ExceptionRecord.is_null() || exc.ContextRecord.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = &*exc.ExceptionRecord;
    let ctx = &mut *exc.ContextRecord;

    // only handle single-step / hardware-breakpoint exceptions
    if record.ExceptionCode.0 != STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let fault_addr = record.ExceptionAddress as *const u8;
    log_debug(&format!(
        "HWBP VEH single-step at {:p}. DR0: 0x{:X}, DR1: 0x{:X}, DR2: 0x{:X}, DR3: 0x{:X}, DR6: 0x{:X}, DR7: 0x{:X}",
        fault_addr, ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7
    ));

    // if we are already inside a hook, just set RF and continue to avoid infinite loop
    if IN_HOOK.with(|h| h.get()) {
        ctx.EFlags |= EFLAGS_RF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // look up the matching breakpoint and invoke the callback
    // We check if the fault address is target_address or if DR6 indicates a match for that index.
    let callback = {
        let bps = match ACTIVE_BREAKPOINTS.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        bps.iter()
            .find(|bp| bp.target_address == fault_addr || (ctx.Dr6 & (1u64 << bp.dr_index)) != 0)
            .and_then(|bp| bp.callback)
    };

    if let Some(cb) = callback {
        // set RF so the resumed instruction executes once without re-triggering the breakpoint
        ctx.EFlags |= EFLAGS_RF;
        cb(ctx);
        // Clear DR6 status bits to acknowledge the breakpoint
        ctx.Dr6 &= !0x00000000_0000000F_u64;
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        // not our breakpoint — let other handlers process it
        EXCEPTION_CONTINUE_SEARCH
    }
}

// register the VEH handler if it is not already installed
pub unsafe fn ensure_veh_registered() {
    if VEH_HANDLE.load(Ordering::Acquire).is_null() {
        // first = 1 means our handler is called before any existing handlers
        let handle = AddVectoredExceptionHandler(1, Some(hwbp_veh_handler));
        VEH_HANDLE.store(handle, Ordering::Release);
        log_debug("HWBP VEH handler registered");
    }
}

// apply the current breakpoint list to a specific thread handle
pub unsafe fn apply_breakpoints_to_thread(h_thread: HANDLE) {
    let bps = match ACTIVE_BREAKPOINTS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };

    if bps.is_empty() {
        return;
    }

    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FLAGS(CTX_FULL_DEBUG);

    let suspend_count = SuspendThread(h_thread);
    let suspended = suspend_count != u32::MAX;

    if suspended {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    if GetThreadContext(h_thread, &mut ctx).is_err() {
        if suspended {
            let _ = ResumeThread(h_thread);
        }
        return;
    }

    // clear all breakpoints first, then re-apply from our list
    ctx.Dr7 = 0;
    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;

    for bp in bps.iter() {
        let addr = bp.target_address as u64;
        let idx = bp.dr_index;

        match idx {
            0 => ctx.Dr0 = addr,
            1 => ctx.Dr1 = addr,
            2 => ctx.Dr2 = addr,
            3 => ctx.Dr3 = addr,
            _ => continue,
        }

        // local enable bit for drN
        ctx.Dr7 |= 1u64 << (2 * idx);
        // condition = execute (00), length = 1-byte (00) — clear the 4 bits for this slot
        let mode_shift = 16 + (4 * idx);
        ctx.Dr7 &= !(0b1111u64 << mode_shift);
    }

    log_debug(&format!(
        "Writing debug regs to thread {:?}: DR0=0x{:X}, DR1=0x{:X}, DR2=0x{:X}, DR3=0x{:X}, DR7=0x{:X}",
        h_thread, ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr7
    ));

    if SetThreadContext(h_thread, &ctx).is_err() {
        log_debug("apply_breakpoints_to_thread: SetThreadContext failed");
    }

    if suspended {
        let _ = ResumeThread(h_thread);
    }
}

// walk all threads belonging to this process and apply the current breakpoints to each
pub unsafe fn apply_breakpoints_to_all_threads() {
    let current_pid = GetCurrentProcessId();

    let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
        Ok(h) => h,
        Err(_) => {
            log_debug("apply_breakpoints_to_all_threads: snapshot failed");
            return;
        }
    };

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    if let Err(e) = Thread32First(snap, &mut entry) {
        log_debug(&format!(
            "apply_breakpoints_to_all_threads: Thread32First failed: {:?}",
            e
        ));
        return;
    }

    let current_tid = GetCurrentThreadId();
    let mut thread_count = 0;
    loop {
        if entry.th32OwnerProcessID == current_pid && entry.th32ThreadID != current_tid {
            thread_count += 1;
            if let Ok(h_thread) = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID) {
                apply_breakpoints_to_thread(h_thread);
                let _ = windows::Win32::Foundation::CloseHandle(h_thread);
            } else {
                log_debug(&format!(
                    "apply_breakpoints_to_all_threads: OpenThread failed for thread {}",
                    entry.th32ThreadID
                ));
            }
        }

        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32Next(snap, &mut entry).is_err() {
            break;
        }
    }

    let _ = windows::Win32::Foundation::CloseHandle(snap);
    log_debug(&format!(
        "apply_breakpoints_to_all_threads: done. Applied to {} threads",
        thread_count
    ));
}

// register a hardware breakpoint on target_addr using dr_index.
// the callback receives the full CONTEXT at the time of the breakpoint.
// also applies the new set to all current threads immediately.
pub unsafe fn set_hardware_breakpoint(
    target_addr: *const u8,
    dr_index: u32,
    callback: unsafe fn(&mut CONTEXT),
) -> Result<(), String> {
    if dr_index > 3 {
        return Err("Only 4 hardware breakpoints available (DR0-DR3)".to_string());
    }

    // make sure the VEH is registered before we write any debug registers
    ensure_veh_registered();

    {
        let mut bps = ACTIVE_BREAKPOINTS.lock().unwrap_or_else(|p| p.into_inner());
        // replace an existing entry for the same dr_index if one exists
        bps.retain(|bp| bp.dr_index != dr_index);
        bps.push(HardwareBreakpointHook {
            target_address: target_addr,
            callback: Some(callback),
            dr_index,
        });
        log_debug(&format!(
            "Hardware breakpoint registered at DR{}: {:p}",
            dr_index, target_addr
        ));
    }

    // propagate to every running thread so they all hit the breakpoint
    apply_breakpoints_to_all_threads();

    Ok(())
}

// remove a hardware breakpoint by dr_index and re-apply the remaining set to all threads
pub unsafe fn remove_hardware_breakpoint(dr_index: u32) -> Result<(), String> {
    if dr_index > 3 {
        return Err("Invalid debug register index".to_string());
    }

    {
        let mut bps = ACTIVE_BREAKPOINTS.lock().unwrap_or_else(|p| p.into_inner());
        bps.retain(|bp| bp.dr_index != dr_index);
    }

    apply_breakpoints_to_all_threads();
    log_debug(&format!("Hardware breakpoint removed from DR{}", dr_index));
    Ok(())
}

// get all active hardware breakpoints as (address, dr_index) pairs
pub fn get_active_breakpoints() -> Vec<(u64, u32)> {
    match ACTIVE_BREAKPOINTS.lock() {
        Ok(bps) => bps
            .iter()
            .map(|bp| (bp.target_address as u64, bp.dr_index))
            .collect(),
        Err(_) => Vec::new(),
    }
}

// remove all hardware breakpoints and unregister the VEH handler
pub unsafe fn clear_all_breakpoints() {
    {
        let mut bps = ACTIVE_BREAKPOINTS.lock().unwrap_or_else(|p| p.into_inner());
        bps.clear();
    }

    let current_pid = GetCurrentProcessId();
    let current_tid = GetCurrentThreadId();

    if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        if Thread32First(snap, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == current_pid && entry.th32ThreadID != current_tid {
                    if let Ok(h_thread) = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID) {
                        let mut ctx = CONTEXT::default();
                        ctx.ContextFlags = CONTEXT_FLAGS(CTX_FULL_DEBUG);

                        let suspend_count = SuspendThread(h_thread);
                        let suspended = suspend_count != u32::MAX;

                        if GetThreadContext(h_thread, &mut ctx).is_ok() {
                            ctx.Dr7 = 0;
                            ctx.Dr0 = 0;
                            ctx.Dr1 = 0;
                            ctx.Dr2 = 0;
                            ctx.Dr3 = 0;
                            let _ = SetThreadContext(h_thread, &ctx);
                        }

                        if suspended {
                            let _ = ResumeThread(h_thread);
                        }
                        let _ = windows::Win32::Foundation::CloseHandle(h_thread);
                    }
                }
                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }

    // unregister our VEH handler
    let handle = VEH_HANDLE.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !handle.is_null() {
        RemoveVectoredExceptionHandler(handle);
        log_debug("HWBP VEH handler unregistered");
    }

    log_debug("All hardware breakpoints cleared");
}
