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
    log_hook(
        "RegOpenKeyExW",
        &format!("Key: {:?}, SubKey: {}", h_key, sub_key.blue()),
    );

    let guard = HOOK_ROK.lock().unwrap();
    guard
        .as_ref()
        .unwrap()
        .call(h_key, lp_sub_key, ul_options, sam_desired, phk_result)
}

pub unsafe fn install(_k32: HMODULE) {
    if let Some(advapi) = GetProcAddress(_k32, s!("advapi32")) {
        let advapi: HMODULE = std::mem::transmute(advapi);
        if let Some(proc) = GetProcAddress(advapi, s!("RegOpenKeyExW")) {
            let target: FnRegOpenKeyExW = std::mem::transmute(proc);
            if let Ok(hook) = GenericDetour::new(target, hooked_reg_open_key_ex_w) {
                let _ = hook.enable();
                *HOOK_ROK.lock().unwrap() = Some(hook);
            }
        }
    }
}

pub unsafe fn remove() {
    HOOK_ROK.lock().unwrap().take().map(|h| h.disable());
}
