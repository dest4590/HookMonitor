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
    log_hook(
        "CreateProcessW",
        &format!("App: {} Cmd: {}", app.yellow(), cmd.blue()),
    );

    let guard = HOOK_CP.lock().unwrap();
    guard.as_ref().unwrap().call(
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
}

pub unsafe extern "system" fn hooked_terminate_process(
    h_process: HANDLE,
    u_exit_code: u32,
) -> BOOL {
    log_hook(
        "TerminateProcess",
        &format!("Proc: {:?}, ExitCode: {}", h_process, u_exit_code),
    );
    let guard = HOOK_TP.lock().unwrap();
    guard.as_ref().unwrap().call(h_process, u_exit_code)
}

pub unsafe fn install(k32: HMODULE) {
    if let Some(proc) = GetProcAddress(k32, s!("CreateProcessW")) {
        let target: FnCreateProcessW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_create_process_w) {
            let _ = hook.enable();
            *HOOK_CP.lock().unwrap() = Some(hook);
        }
    }
    if let Some(proc) = GetProcAddress(k32, s!("TerminateProcess")) {
        let target: FnTerminateProcess = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_terminate_process) {
            let _ = hook.enable();
            *HOOK_TP.lock().unwrap() = Some(hook);
        }
    }
}

pub unsafe fn remove() {
    HOOK_CP.lock().unwrap().take().map(|h| h.disable());
    HOOK_TP.lock().unwrap().take().map(|h| h.disable());
}
