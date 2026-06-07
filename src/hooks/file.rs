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
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook("CreateFileW", &format!("Path: {}", path.yellow()));
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || {
                log_debug("CreateFileW hook not installed");
                HANDLE::default()
            },
            |detour| {
                detour.call(
                    lp_file_name,
                    dw_desired_access,
                    dw_share_mode,
                    lp_security_attributes,
                    dw_creation_disposition,
                    dw_flags,
                    h_template,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("CreateFileW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || {
                    log_debug("CreateFileW hook not installed");
                    HANDLE::default()
                },
                |detour| {
                    detour.call(
                        lp_file_name,
                        dw_desired_access,
                        dw_share_mode,
                        lp_security_attributes,
                        dw_creation_disposition,
                        dw_flags,
                        h_template,
                    )
                },
            )
        }
    }
}

pub unsafe fn install(k32: HMODULE) -> Result<(), String> {
    if let Some(proc) = GetProcAddress(k32, s!("CreateFileW")) {
        let target: FnCreateFileW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked) {
            let _ = hook.enable();
            match HOOK.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    Ok(())
                }
                Err(poisoned) => {
                    log_debug("CreateFileW hook mutex poisoned, recovering");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    Ok(())
                }
            }
        } else {
            Err("Failed to create GenericDetour for CreateFileW".to_string())
        }
    } else {
        Err("CreateFileW not found in kernel32.dll".to_string())
    }
}

pub unsafe fn remove() {
    HOOK.lock().unwrap().take().map(|h| h.disable());
}
