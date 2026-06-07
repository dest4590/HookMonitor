use crate::hooks::common::*;

// --- VirtualAlloc ---
pub type FnVirtualAlloc = unsafe extern "system" fn(
    *const std::ffi::c_void,
    usize,
    VIRTUAL_ALLOCATION_TYPE,
    PAGE_PROTECTION_FLAGS,
) -> *mut std::ffi::c_void;
static HOOK_VA: Mutex<Option<GenericDetour<FnVirtualAlloc>>> = Mutex::new(None);

// --- VirtualAllocEx ---
pub type FnVirtualAllocEx = unsafe extern "system" fn(
    HANDLE,
    *const std::ffi::c_void,
    usize,
    VIRTUAL_ALLOCATION_TYPE,
    PAGE_PROTECTION_FLAGS,
) -> *mut std::ffi::c_void;
static HOOK_VAE: Mutex<Option<GenericDetour<FnVirtualAllocEx>>> = Mutex::new(None);

// --- WriteProcessMemory ---
pub type FnWriteProcessMemory = unsafe extern "system" fn(
    HANDLE,
    *const std::ffi::c_void,
    *const std::ffi::c_void,
    usize,
    *mut usize,
) -> BOOL;
static HOOK_WPM: Mutex<Option<GenericDetour<FnWriteProcessMemory>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_virtual_alloc(
    lp_address: *const std::ffi::c_void,
    dw_size: usize,
    fl_allocation_type: VIRTUAL_ALLOCATION_TYPE,
    fl_protect: PAGE_PROTECTION_FLAGS,
) -> *mut std::ffi::c_void {
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "VirtualAlloc",
            &format!(
                "Addr: {:?}, Size: {} bytes, Type: {:?}, Protect: {:?}",
                lp_address, dw_size, fl_allocation_type, fl_protect
            ),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_VA.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || std::ptr::null_mut(),
            |detour| detour.call(lp_address, dw_size, fl_allocation_type, fl_protect),
        ),
        Err(poisoned) => {
            log_debug("VirtualAlloc mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || std::ptr::null_mut(),
                |detour| detour.call(lp_address, dw_size, fl_allocation_type, fl_protect),
            )
        }
    }
}

pub unsafe extern "system" fn hooked_virtual_alloc_ex(
    h_process: HANDLE,
    lp_address: *const std::ffi::c_void,
    dw_size: usize,
    fl_allocation_type: VIRTUAL_ALLOCATION_TYPE,
    fl_protect: PAGE_PROTECTION_FLAGS,
) -> *mut std::ffi::c_void {
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "VirtualAllocEx",
            &format!(
                "Proc: {:?}, Addr: {:?}, Size: {}, Protect: {:?}",
                h_process, lp_address, dw_size, fl_protect
            ),
        );
        IN_HOOK.with(|h| h.set(false));
    }
    match HOOK_VAE.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || std::ptr::null_mut(),
            |detour| {
                detour.call(
                    h_process,
                    lp_address,
                    dw_size,
                    fl_allocation_type,
                    fl_protect,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("VirtualAllocEx mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || std::ptr::null_mut(),
                |detour| {
                    detour.call(
                        h_process,
                        lp_address,
                        dw_size,
                        fl_allocation_type,
                        fl_protect,
                    )
                },
            )
        }
    }
}

pub unsafe extern "system" fn hooked_write_process_memory(
    h_process: HANDLE,
    lp_base_address: *const std::ffi::c_void,
    lp_buffer: *const std::ffi::c_void,
    n_size: usize,
    lp_number_of_bytes_written: *mut usize,
) -> BOOL {
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "WriteProcessMemory",
            &format!(
                "Proc: {:?}, Addr: {:?}, Size: {}",
                h_process, lp_base_address, n_size
            ),
        );
        IN_HOOK.with(|h| h.set(false));
    }
    match HOOK_WPM.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || BOOL::default(),
            |detour| {
                detour.call(
                    h_process,
                    lp_base_address,
                    lp_buffer,
                    n_size,
                    lp_number_of_bytes_written,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("WriteProcessMemory mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || BOOL::default(),
                |detour| {
                    detour.call(
                        h_process,
                        lp_base_address,
                        lp_buffer,
                        n_size,
                        lp_number_of_bytes_written,
                    )
                },
            )
        }
    }
}

pub unsafe fn install(k32: HMODULE) -> Result<(), String> {
    let mut va_ok = false;
    let mut vae_ok = false;
    let mut wpm_ok = false;

    if let Some(proc) = GetProcAddress(k32, s!("VirtualAlloc")) {
        let target: FnVirtualAlloc = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_virtual_alloc) {
            let _ = hook.enable();
            match HOOK_VA.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    va_ok = true;
                }
                Err(poisoned) => {
                    log_debug("VirtualAlloc mutex poisoned during install");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    va_ok = true;
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(k32, s!("VirtualAllocEx")) {
        let target: FnVirtualAllocEx = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_virtual_alloc_ex) {
            let _ = hook.enable();
            match HOOK_VAE.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    vae_ok = true;
                }
                Err(poisoned) => {
                    log_debug("VirtualAllocEx mutex poisoned during install");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    vae_ok = true;
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(k32, s!("WriteProcessMemory")) {
        let target: FnWriteProcessMemory = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_write_process_memory) {
            let _ = hook.enable();
            match HOOK_WPM.lock() {
                Ok(mut guard) => {
                    *guard = Some(hook);
                    wpm_ok = true;
                }
                Err(poisoned) => {
                    log_debug("WriteProcessMemory mutex poisoned during install");
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                    wpm_ok = true;
                }
            }
        }
    }

    if va_ok || vae_ok || wpm_ok {
        Ok(())
    } else {
        Err("Failed to install memory hooks".to_string())
    }
}

pub unsafe fn remove() {
    HOOK_VA
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_VAE
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_WPM
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
}
