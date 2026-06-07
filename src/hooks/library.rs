use crate::hooks::common::*;

// --- GetProcAddress ---
pub type FnGetProcAddress = unsafe extern "system" fn(HMODULE, PCSTR) -> *const std::ffi::c_void;
static HOOK_GPA: Mutex<Option<GenericDetour<FnGetProcAddress>>> = Mutex::new(None);

// --- LoadLibraryW ---
pub type FnLoadLibraryW = unsafe extern "system" fn(PCWSTR) -> HMODULE;
static HOOK_LL: Mutex<Option<GenericDetour<FnLoadLibraryW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_get_proc_address(
    h_module: HMODULE,
    lp_proc_name: PCSTR,
) -> *const std::ffi::c_void {
    let proc_addr = lp_proc_name.as_ptr() as usize;
    let proc_name = if proc_addr <= 0xFFFF {
        format!("#{}", proc_addr)
    } else {
        lp_proc_name
            .to_string()
            .unwrap_or_else(|_| "INVALID_UTF8".into())
    };

    log_hook("GetProcAddress", &format!("Symbol: {}", proc_name.cyan()));

    let guard = HOOK_GPA.lock().unwrap();
    guard.as_ref().unwrap().call(h_module, lp_proc_name)
}

pub unsafe extern "system" fn hooked_load_library_w(lp_lib_file_name: PCWSTR) -> HMODULE {
    let lib_name = lp_lib_file_name
        .to_string()
        .unwrap_or_else(|_| "INVALID_UTF16".into());
    log_hook("LoadLibraryW", &format!("Library: {}", lib_name.magenta()));

    let guard = HOOK_LL.lock().unwrap();
    guard.as_ref().unwrap().call(lp_lib_file_name)
}

pub unsafe fn install(k32: HMODULE) {
    if let Some(proc) = GetProcAddress(k32, s!("GetProcAddress")) {
        let target: FnGetProcAddress = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_get_proc_address) {
            let _ = hook.enable();
            *HOOK_GPA.lock().unwrap() = Some(hook);
        }
    }

    if let Some(proc) = GetProcAddress(k32, s!("LoadLibraryW")) {
        let target: FnLoadLibraryW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_load_library_w) {
            let _ = hook.enable();
            *HOOK_LL.lock().unwrap() = Some(hook);
        }
    }
}

pub unsafe fn remove() {
    HOOK_GPA.lock().unwrap().take().map(|h| h.disable());
    HOOK_LL.lock().unwrap().take().map(|h| h.disable());
}
