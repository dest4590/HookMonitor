use crate::hooks::common::*;

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
            &format!("App: {} Cmd: {}", app.yellow(), cmd.blue()),
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
            &format!("Proc: {:?}, ExitCode: {}", h_process, u_exit_code),
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

pub unsafe fn install(k32: HMODULE) -> Result<(), String> {
    let mut cp_ok = false;
    let mut tp_ok = false;

    if let Some(proc) = GetProcAddress(k32, s!("CreateProcessW")) {
        let target: FnCreateProcessW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_create_process_w) {
            let _ = hook.enable();
            match HOOK_CP.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    cp_ok = true;
                }
                Err(poisoned) => {
                    log_debug("CreateProcessW mutex poisoned during install");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    cp_ok = true;
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(k32, s!("TerminateProcess")) {
        let target: FnTerminateProcess = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_terminate_process) {
            let _ = hook.enable();
            match HOOK_TP.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    tp_ok = true;
                }
                Err(poisoned) => {
                    log_debug("TerminateProcess mutex poisoned during install");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    tp_ok = true;
                }
            }
        }
    }

    if cp_ok || tp_ok {
        Ok(())
    } else {
        Err("Failed to install process hooks".to_string())
    }
}

pub unsafe fn remove() {
    HOOK_CP
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_TP
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
}
