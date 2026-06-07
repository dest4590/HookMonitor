use crate::hooks::common::*;
use crate::{install_detour, remove_detour};

// regopenkeyexw
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
    let advapi = LoadLibraryW(windows::core::w!("advapi32.dll"))
        .map_err(|_| "Failed to load advapi32.dll")?;

    install_detour!(
        advapi,
        "RegOpenKeyExW",
        FnRegOpenKeyExW,
        hooked_reg_open_key_ex_w,
        &HOOK_ROK
    );
    Ok(())
}

pub unsafe fn remove() {
    remove_detour!(&HOOK_ROK);
}
