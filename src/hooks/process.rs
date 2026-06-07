use crate::hooks::common::*;
use crate::{install_detour, remove_detour};

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
    install_detour!(k32, "CreateProcessW", FnCreateProcessW, hooked_create_process_w, &HOOK_CP);
    install_detour!(k32, "TerminateProcess", FnTerminateProcess, hooked_terminate_process, &HOOK_TP);
    Ok(())
}

pub unsafe fn remove() {
    remove_detour!(&HOOK_CP);
    remove_detour!(&HOOK_TP);
}
