use crate::hooks::common::*;
use crate::{install_detour, remove_detour};

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
    let res = match HOOK_VA.lock() {
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
    };

    if !res.is_null() && !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        let addr_val = res as usize;
        // Suppress system/module region allocations (0x7ff...) to reduce VMProtect init noise
        if addr_val < 0x7FF0_0000_0000_usize {
            log_hook(
                "VirtualAlloc",
                &format!(
                    "Addr: {:?}, Size: {} bytes, Type: {:?}, Protect: {:?}",
                    lp_address, dw_size, fl_allocation_type, fl_protect
                ),
            );
        }
        IN_HOOK.with(|h| h.set(false));
    }

    res
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
    install_detour!(
        k32,
        "VirtualAlloc",
        FnVirtualAlloc,
        hooked_virtual_alloc,
        &HOOK_VA
    );
    install_detour!(
        k32,
        "VirtualAllocEx",
        FnVirtualAllocEx,
        hooked_virtual_alloc_ex,
        &HOOK_VAE
    );
    install_detour!(
        k32,
        "WriteProcessMemory",
        FnWriteProcessMemory,
        hooked_write_process_memory,
        &HOOK_WPM
    );
    Ok(())
}

pub unsafe fn remove() {
    remove_detour!(&HOOK_VA);
    remove_detour!(&HOOK_VAE);
    remove_detour!(&HOOK_WPM);
}
