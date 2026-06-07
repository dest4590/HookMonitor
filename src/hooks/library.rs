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

    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook("GetProcAddress", &format!("Symbol: {}", proc_name.cyan()));
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_GPA.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || std::ptr::null(),
            |detour| detour.call(h_module, lp_proc_name),
        ),
        Err(poisoned) => {
            log_debug("GetProcAddress mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || std::ptr::null(),
                |detour| detour.call(h_module, lp_proc_name),
            )
        }
    }
}

pub unsafe extern "system" fn hooked_load_library_w(lp_lib_file_name: PCWSTR) -> HMODULE {
    let lib_name = lp_lib_file_name
        .to_string()
        .unwrap_or_else(|_| "INVALID_UTF16".into());
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook("LoadLibraryW", &format!("Library: {}", lib_name.magenta()));
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_LL.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || HMODULE::default(),
            |detour| detour.call(lp_lib_file_name),
        ),
        Err(poisoned) => {
            log_debug("LoadLibraryW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || HMODULE::default(),
                |detour| detour.call(lp_lib_file_name),
            )
        }
    }
}

pub unsafe fn install(k32: HMODULE) -> Result<(), String> {
    let mut gpa_ok = false;
    let mut ll_ok = false;

    if let Some(proc) = GetProcAddress(k32, s!("GetProcAddress")) {
        let target: FnGetProcAddress = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_get_proc_address) {
            let _ = hook.enable();
            match HOOK_GPA.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    gpa_ok = true;
                }
                Err(poisoned) => {
                    log_debug("GetProcAddress mutex poisoned during install");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    gpa_ok = true;
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(k32, s!("LoadLibraryW")) {
        let target: FnLoadLibraryW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_load_library_w) {
            let _ = hook.enable();
            match HOOK_LL.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    ll_ok = true;
                }
                Err(poisoned) => {
                    log_debug("LoadLibraryW mutex poisoned during install");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    ll_ok = true;
                }
            }
        }
    }

    if gpa_ok || ll_ok {
        Ok(())
    } else {
        Err("Failed to install library hooks".to_string())
    }
}

pub unsafe fn remove() {
    HOOK_GPA
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_LL
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
}
