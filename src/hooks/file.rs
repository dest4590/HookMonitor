use crate::hooks::common::*;
use crate::{install_detour, remove_detour};

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

    let path_lower = path.to_lowercase();
    let should_log = !path_lower.contains("c:\\users\\public\\hook_monitor");

    if !IN_HOOK.with(|h| h.get()) && should_log {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "CreateFileW",
            &format!("-> Opening file: {}", path.yellow()),
        );
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
    install_detour!(k32, "CreateFileW", FnCreateFileW, hooked, &HOOK);
    Ok(())
}

pub unsafe fn remove() {
    remove_detour!(&HOOK);
}
