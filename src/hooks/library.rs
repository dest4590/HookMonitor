use crate::hooks::common::*;
use crate::{install_detour, remove_detour};

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
    install_detour!(k32, "GetProcAddress", FnGetProcAddress, hooked_get_proc_address, &HOOK_GPA);
    install_detour!(k32, "LoadLibraryW", FnLoadLibraryW, hooked_load_library_w, &HOOK_LL);
    Ok(())
}

pub unsafe fn remove() {
    remove_detour!(&HOOK_GPA);
    remove_detour!(&HOOK_LL);
}
