use crate::hooks::common::*;

pub type FnCreateFileW = unsafe extern "system" fn(
    PCWSTR,
    u32,
    FILE_SHARE_MODE,
    *const SECURITY_ATTRIBUTES,
    FILE_CREATION_DISPOSITION,
    FILE_FLAGS_AND_ATTRIBUTES,
    HANDLE,
) -> HANDLE;

static HOOK: Mutex<Option<GenericDetour<FnCreateFileW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked(
    lp_file_name: PCWSTR,
    dw_desired_access: u32,
    dw_share_mode: FILE_SHARE_MODE,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    dw_creation_disposition: FILE_CREATION_DISPOSITION,
    dw_flags: FILE_FLAGS_AND_ATTRIBUTES,
    h_template: HANDLE,
) -> HANDLE {
    let path = lp_file_name
        .to_string()
        .unwrap_or_else(|_| "INVALID_UTF16".into());
    log_hook("CreateFileW", &format!("Path: {}", path.yellow()));

    let guard = HOOK.lock().unwrap();
    guard.as_ref().unwrap().call(
        lp_file_name,
        dw_desired_access,
        dw_share_mode,
        lp_security_attributes,
        dw_creation_disposition,
        dw_flags,
        h_template,
    )
}

pub unsafe fn install(k32: HMODULE) {
    if let Some(proc) = GetProcAddress(k32, s!("CreateFileW")) {
        let target: FnCreateFileW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked) {
            let _ = hook.enable();
            *HOOK.lock().unwrap() = Some(hook);
        }
    }
}

pub unsafe fn remove() {
    HOOK.lock().unwrap().take().map(|h| h.disable());
}
