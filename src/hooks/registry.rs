use crate::hooks::common::*;

// --- RegOpenKeyExW ---
pub type FnRegOpenKeyExW =
    unsafe extern "system" fn(HKEY, PCWSTR, u32, REG_SAM_FLAGS, *mut HKEY) -> i32;
static HOOK_ROK: Mutex<Option<GenericDetour<FnRegOpenKeyExW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_reg_open_key_ex_w(
    h_key: HKEY,
    lp_sub_key: PCWSTR,
    ul_options: u32,
    sam_desired: REG_SAM_FLAGS,
    phk_result: *mut HKEY,
) -> i32 {
    let sub_key = lp_sub_key
        .to_string()
        .unwrap_or_else(|_| "INVALID_UTF16".into());
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "RegOpenKeyExW",
            &format!("Key: {:?}, SubKey: {}", h_key, sub_key.blue()),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_ROK.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || -1,
            |detour| detour.call(h_key, lp_sub_key, ul_options, sam_desired, phk_result),
        ),
        Err(poisoned) => {
            log_debug("RegOpenKeyExW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || -1,
                |detour| detour.call(h_key, lp_sub_key, ul_options, sam_desired, phk_result),
            )
        }
    }
}

pub unsafe fn install(_k32: HMODULE) -> Result<(), String> {
    if let Ok(advapi) = LoadLibraryW(windows::core::w!("advapi32.dll")) {
        if let Some(proc) = GetProcAddress(advapi, s!("RegOpenKeyExW")) {
            let target: FnRegOpenKeyExW = std::mem::transmute(proc);
            if let Ok(hook) = GenericDetour::new(target, hooked_reg_open_key_ex_w) {
                let _ = hook.enable();
                match HOOK_ROK.lock() {
                    Ok(mut guard) => {
                        *guard = Some(hook);
                        Ok(())
                    }
                    Err(poisoned) => {
                        log_debug("RegOpenKeyExW mutex poisoned during install");
                        let mut guard = poisoned.into_inner();
                        *guard = Some(hook);
                        Ok(())
                    }
                }
            } else {
                Err("Failed to create GenericDetour for RegOpenKeyExW".to_string())
            }
        } else {
            Err("RegOpenKeyExW not found in advapi32.dll".to_string())
        }
    } else {
        Err("Failed to load advapi32.dll".to_string())
    }
}

pub unsafe fn remove() {
    HOOK_ROK
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
}
