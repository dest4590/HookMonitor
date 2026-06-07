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
    log_hook(
        "VirtualAlloc",
        &format!(
            "Addr: {:?}, Size: {} bytes, Type: {:?}, Protect: {:?}",
            lp_address, dw_size, fl_allocation_type, fl_protect
        ),
    );
    let guard = HOOK_VA.lock().unwrap();
    guard
        .as_ref()
        .unwrap()
        .call(lp_address, dw_size, fl_allocation_type, fl_protect)
}

pub unsafe extern "system" fn hooked_virtual_alloc_ex(
    h_process: HANDLE,
    lp_address: *const std::ffi::c_void,
    dw_size: usize,
    fl_allocation_type: VIRTUAL_ALLOCATION_TYPE,
    fl_protect: PAGE_PROTECTION_FLAGS,
) -> *mut std::ffi::c_void {
    log_hook(
        "VirtualAllocEx",
        &format!(
            "Proc: {:?}, Addr: {:?}, Size: {}, Protect: {:?}",
            h_process, lp_address, dw_size, fl_protect
        ),
    );
    let guard = HOOK_VAE.lock().unwrap();
    guard.as_ref().unwrap().call(
        h_process,
        lp_address,
        dw_size,
        fl_allocation_type,
        fl_protect,
    )
}

pub unsafe extern "system" fn hooked_write_process_memory(
    h_process: HANDLE,
    lp_base_address: *const std::ffi::c_void,
    lp_buffer: *const std::ffi::c_void,
    n_size: usize,
    lp_number_of_bytes_written: *mut usize,
) -> BOOL {
    log_hook(
        "WriteProcessMemory",
        &format!(
            "Proc: {:?}, Addr: {:?}, Size: {} bytes",
            h_process, lp_base_address, n_size
        ),
    );
    let guard = HOOK_WPM.lock().unwrap();
    guard.as_ref().unwrap().call(
        h_process,
        lp_base_address,
        lp_buffer,
        n_size,
        lp_number_of_bytes_written,
    )
}

pub unsafe fn install(k32: HMODULE) {
    if let Some(proc) = GetProcAddress(k32, s!("VirtualAlloc")) {
        let target: FnVirtualAlloc = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_virtual_alloc) {
            let _ = hook.enable();
            *HOOK_VA.lock().unwrap() = Some(hook);
        }
    }
    if let Some(proc) = GetProcAddress(k32, s!("VirtualAllocEx")) {
        let target: FnVirtualAllocEx = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_virtual_alloc_ex) {
            let _ = hook.enable();
            *HOOK_VAE.lock().unwrap() = Some(hook);
        }
    }
    if let Some(proc) = GetProcAddress(k32, s!("WriteProcessMemory")) {
        let target: FnWriteProcessMemory = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_write_process_memory) {
            let _ = hook.enable();
            *HOOK_WPM.lock().unwrap() = Some(hook);
        }
    }
}

pub unsafe fn remove() {
    HOOK_VA.lock().unwrap().take().map(|h| h.disable());
    HOOK_VAE.lock().unwrap().take().map(|h| h.disable());
    HOOK_WPM.lock().unwrap().take().map(|h| h.disable());
}
