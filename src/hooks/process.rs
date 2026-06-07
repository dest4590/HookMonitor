use crate::hooks::common::*;
use crate::hooks::hardware_bp::apply_breakpoints_to_thread;
use crate::{install_detour, remove_detour};
use windows::Win32::System::Diagnostics::Debug::CONTEXT;
use windows::Win32::System::Threading::THREAD_CREATION_FLAGS;

// the low bit 0x10 is the debug registers flag, works with or without CONTEXT_AMD64 prefix

// --- CreateProcessW ---
pub type FnCreateProcessW = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    PROCESS_CREATION_FLAGS,
    *const std::ffi::c_void,
    PCWSTR,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;
static HOOK_CP: Mutex<Option<GenericDetour<FnCreateProcessW>>> = Mutex::new(None);

// --- TerminateProcess ---
pub type FnTerminateProcess = unsafe extern "system" fn(HANDLE, u32) -> BOOL;
static HOOK_TP: Mutex<Option<GenericDetour<FnTerminateProcess>>> = Mutex::new(None);

// --- CreateThread ---
pub type FnCreateThread = unsafe extern "system" fn(
    *const std::ffi::c_void,
    usize,
    Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>,
    *const std::ffi::c_void,
    THREAD_CREATION_FLAGS,
    *mut u32,
) -> HANDLE;
static HOOK_CT: Mutex<Option<GenericDetour<FnCreateThread>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_create_process_w(
    lp_application_name: PCWSTR,
    lp_command_line: PWSTR,
    lp_process_attributes: *const SECURITY_ATTRIBUTES,
    lp_thread_attributes: *const SECURITY_ATTRIBUTES,
    b_inherit_handles: BOOL,
    dw_creation_flags: PROCESS_CREATION_FLAGS,
    lp_environment: *const std::ffi::c_void,
    lp_current_directory: PCWSTR,
    lp_startup_info: *const STARTUPINFOW,
    lp_process_information: *mut PROCESS_INFORMATION,
) -> BOOL {
    let app = lp_application_name.to_string().unwrap_or_default();
    let cmd = lp_command_line.to_string().unwrap_or_default();
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "CreateProcessW",
            &format!("-> Spawning: {} (args: {})", app.yellow(), cmd.blue()),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_CP.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || BOOL::default(),
            |detour| {
                detour.call(
                    lp_application_name,
                    lp_command_line,
                    lp_process_attributes,
                    lp_thread_attributes,
                    b_inherit_handles,
                    dw_creation_flags,
                    lp_environment,
                    lp_current_directory,
                    lp_startup_info,
                    lp_process_information,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("CreateProcessW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || BOOL::default(),
                |detour| {
                    detour.call(
                        lp_application_name,
                        lp_command_line,
                        lp_process_attributes,
                        lp_thread_attributes,
                        b_inherit_handles,
                        dw_creation_flags,
                        lp_environment,
                        lp_current_directory,
                        lp_startup_info,
                        lp_process_information,
                    )
                },
            )
        }
    }
}

pub unsafe extern "system" fn hooked_terminate_process(
    h_process: HANDLE,
    u_exit_code: u32,
) -> BOOL {
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "TerminateProcess",
            &format!("-> Terminating process (Handle: {:?}, Exit Code: {})", h_process, u_exit_code),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_TP.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || BOOL::default(),
            |detour| detour.call(h_process, u_exit_code),
        ),
        Err(poisoned) => {
            log_debug("TerminateProcess mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || BOOL::default(),
                |detour| detour.call(h_process, u_exit_code),
            )
        }
    }
}

pub unsafe extern "system" fn hooked_create_thread(
    lp_thread_attributes: *const std::ffi::c_void,
    dw_stack_size: usize,
    lp_start_address: Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>,
    lp_parameter: *const std::ffi::c_void,
    dw_creation_flags: THREAD_CREATION_FLAGS,
    lp_thread_id: *mut u32,
) -> HANDLE {
    let h_thread = match HOOK_CT.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || HANDLE::default(),
            |detour| {
                detour.call(
                    lp_thread_attributes,
                    dw_stack_size,
                    lp_start_address,
                    lp_parameter,
                    dw_creation_flags,
                    lp_thread_id,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("CreateThread mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || HANDLE::default(),
                |detour| {
                    detour.call(
                        lp_thread_attributes,
                        dw_stack_size,
                        lp_start_address,
                        lp_parameter,
                        dw_creation_flags,
                        lp_thread_id,
                    )
                },
            )
        }
    };

    // apply any active hardware breakpoints to the new thread immediately
    if !h_thread.is_invalid() {
        apply_breakpoints_to_thread(h_thread);
    }

    h_thread
}

// --- SetThreadContext ---
pub type FnSetThreadContext = unsafe extern "system" fn(HANDLE, *const CONTEXT) -> BOOL;
static HOOK_STC: Mutex<Option<GenericDetour<FnSetThreadContext>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_set_thread_context(
    h_thread: HANDLE,
    lp_context: *const CONTEXT,
) -> BOOL {
    let mut modified_ctx = *lp_context;

    // Check if the caller is requesting to set debug registers
    // use the full x64 flag (0x00100010) for checking
    if (modified_ctx.ContextFlags.0 & 0x10) != 0 {
        let active_bps = crate::hooks::hardware_bp::get_active_breakpoints();
        if !active_bps.is_empty() {
            log_debug(&format!(
                "SetThreadContext intercepted: caller tried to set DR0=0x{:X}, DR7=0x{:X} — restoring our breakpoints",
                modified_ctx.Dr0, modified_ctx.Dr7
            ));

            // Keep our active HWBP breakpoints set in the incoming context
            modified_ctx.Dr7 = 0;
            modified_ctx.Dr0 = 0;
            modified_ctx.Dr1 = 0;
            modified_ctx.Dr2 = 0;
            modified_ctx.Dr3 = 0;

            for &(addr, idx) in &active_bps {
                match idx {
                    0 => modified_ctx.Dr0 = addr,
                    1 => modified_ctx.Dr1 = addr,
                    2 => modified_ctx.Dr2 = addr,
                    3 => modified_ctx.Dr3 = addr,
                    _ => {}
                }
                modified_ctx.Dr7 |= 1u64 << (2 * idx);
                let mode_shift = 16 + (4 * idx);
                modified_ctx.Dr7 &= !(0b1111u64 << mode_shift);
            }
        }
    }

    match HOOK_STC.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || BOOL::default(),
            |detour| detour.call(h_thread, &modified_ctx),
        ),
        Err(poisoned) => {
            log_debug("SetThreadContext mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || BOOL::default(),
                |detour| detour.call(h_thread, &modified_ctx),
            )
        }
    }
}

// --- GetThreadContext ---
pub type FnGetThreadContext = unsafe extern "system" fn(HANDLE, *mut CONTEXT) -> BOOL;
static HOOK_GTC: Mutex<Option<GenericDetour<FnGetThreadContext>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_get_thread_context(
    h_thread: HANDLE,
    lp_context: *mut CONTEXT,
) -> BOOL {
    let res = match HOOK_GTC.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || BOOL::default(),
            |detour| detour.call(h_thread, lp_context),
        ),
        Err(poisoned) => {
            log_debug("GetThreadContext mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || BOOL::default(),
                |detour| detour.call(h_thread, lp_context),
            )
        }
    };

    if res.as_bool() && !lp_context.is_null() {
        let ctx = &mut *lp_context;
        // Hide our active debug registers if requested (check the low bits for debug reg flag)
        if (ctx.ContextFlags.0 & 0x10) != 0 {
            ctx.Dr0 = 0;
            ctx.Dr1 = 0;
            ctx.Dr2 = 0;
            ctx.Dr3 = 0;
            ctx.Dr6 = 0;
            ctx.Dr7 = 0;
        }
    }

    res
}

pub unsafe fn install(k32: HMODULE) -> Result<(), String> {
    install_detour!(
        k32,
        "CreateProcessW",
        FnCreateProcessW,
        hooked_create_process_w,
        &HOOK_CP
    );
    install_detour!(
        k32,
        "TerminateProcess",
        FnTerminateProcess,
        hooked_terminate_process,
        &HOOK_TP
    );
    install_detour!(
        k32,
        "CreateThread",
        FnCreateThread,
        hooked_create_thread,
        &HOOK_CT
    );
    install_detour!(
        k32,
        "SetThreadContext",
        FnSetThreadContext,
        hooked_set_thread_context,
        &HOOK_STC
    );
    install_detour!(
        k32,
        "GetThreadContext",
        FnGetThreadContext,
        hooked_get_thread_context,
        &HOOK_GTC
    );
    Ok(())
}

pub unsafe fn remove() {
    remove_detour!(&HOOK_CP);
    remove_detour!(&HOOK_TP);
    remove_detour!(&HOOK_CT);
    remove_detour!(&HOOK_STC);
    remove_detour!(&HOOK_GTC);
}
