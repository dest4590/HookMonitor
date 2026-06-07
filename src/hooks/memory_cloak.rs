use crate::hooks::common::*;
use crate::{install_detour, remove_detour};
use std::collections::HashMap;
use windows::core::BOOL;
use windows::Win32::Foundation::HANDLE;

// memory cloaking module
// intercepts virtualquery and readprocessmemory to spoof hooked memory regions
// protectors scan memory looking for modifications - we hide our hooks by returning original bytes

pub type FnVirtualQuery = unsafe extern "system" fn(
    *const std::ffi::c_void,
    *mut windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION,
    usize,
) -> usize;

pub type FnReadProcessMemory = unsafe extern "system" fn(
    HANDLE,
    *const std::ffi::c_void,
    *mut std::ffi::c_void,
    usize,
    *mut usize,
) -> BOOL;

static HOOK_VQ: Mutex<Option<GenericDetour<FnVirtualQuery>>> = Mutex::new(None);
static HOOK_RPM: Mutex<Option<GenericDetour<FnReadProcessMemory>>> = Mutex::new(None);

// store original bytes of hooked functions for spoofing
static ORIGINAL_BYTES: once_cell::sync::Lazy<Mutex<HashMap<usize, Vec<u8>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

// register original bytes of a hooked function
// this data is used when protectors read the hooked memory to spoof unmodified bytes
pub fn register_hooked_function(address: *const u8, original_bytes: Vec<u8>) {
    if let Ok(mut map) = ORIGINAL_BYTES.lock() {
        let len = original_bytes.len();
        map.insert(address as usize, original_bytes);
        log_debug(&format!(
            "Registered original bytes for function at {:?}, size: {}",
            address, len
        ));
    }
}

// check if an address is a hooked function
pub fn is_hooked_function(address: *const u8) -> bool {
    if let Ok(map) = ORIGINAL_BYTES.lock() {
        map.contains_key(&(address as usize))
    } else {
        false
    }
}

// hooked virtualquery - returns modified information to hide hooks
pub unsafe extern "system" fn hooked_virtual_query(
    lp_address: *const std::ffi::c_void,
    lp_buffer: *mut windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION,
    dw_length: usize,
) -> usize {
    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));

        // call the original virtualquery
        let result = match HOOK_VQ.lock() {
            Ok(guard) => guard.as_ref().map_or_else(
                || {
                    log_debug("VirtualQuery hook not installed");
                    0
                },
                |detour| detour.call(lp_address, lp_buffer, dw_length),
            ),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                guard.as_ref().map_or_else(
                    || {
                        log_debug("VirtualQuery hook not installed");
                        0
                    },
                    |detour| detour.call(lp_address, lp_buffer, dw_length),
                )
            }
        };

        // don't log virtualquery calls as they are very frequent
        IN_HOOK.with(|h| h.set(false));
        result
    } else {
        0
    }
}

// hooked readprocessmemory - spoofs hooked regions with original bytes
pub unsafe extern "system" fn hooked_read_process_memory(
    h_process: HANDLE,
    lp_base_address: *const std::ffi::c_void,
    lp_buffer: *mut std::ffi::c_void,
    n_size: usize,
    lp_number_of_bytes_read: *mut usize,
) -> BOOL {
    let result = match HOOK_RPM.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || BOOL::default(),
            |detour| {
                detour.call(
                    h_process,
                    lp_base_address,
                    lp_buffer,
                    n_size,
                    lp_number_of_bytes_read,
                )
            },
        ),
        Err(poisoned) => {
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || BOOL::default(),
                |detour| {
                    detour.call(
                        h_process,
                        lp_base_address,
                        lp_buffer,
                        n_size,
                        lp_number_of_bytes_read,
                    )
                },
            )
        }
    };

    if result.as_bool() {
        // check if the read region contains a hooked function
        if let Ok(original_map) = ORIGINAL_BYTES.lock() {
            for (hooked_addr, original_bytes_vec) in original_map.iter() {
                let read_start = lp_base_address as usize;
                let read_end = read_start + n_size;
                let hooked_start = *hooked_addr;
                let hooked_end = hooked_start + original_bytes_vec.len();

                // check for overlap
                if read_start <= hooked_start && hooked_end <= read_end {
                    let offset = hooked_start - read_start;
                    let buffer_ptr = (lp_buffer as usize + offset) as *mut u8;

                    // spoof the read buffer with original bytes
                    for (i, &byte) in original_bytes_vec.iter().enumerate() {
                        *(buffer_ptr.add(i)) = byte;
                    }

                    log_debug(&format!(
                        "ReadProcessMemory spoof at {:?}: replaced {} bytes with original",
                        hooked_addr,
                        original_bytes_vec.len()
                    ));
                }
            }
        }
    }

    result
}

// install memory cloaking hooks
pub unsafe fn install(k32: HMODULE) -> Result<(), String> {
    install_detour!(
        k32,
        "VirtualQuery",
        FnVirtualQuery,
        hooked_virtual_query,
        &HOOK_VQ
    );
    install_detour!(
        k32,
        "ReadProcessMemory",
        FnReadProcessMemory,
        hooked_read_process_memory,
        &HOOK_RPM
    );

    log_debug("Memory cloaking hooks installed");
    Ok(())
}

// remove memory cloaking hooks
pub unsafe fn remove() {
    remove_detour!(&HOOK_VQ);
    remove_detour!(&HOOK_RPM);
    log_debug("Memory cloaking hooks removed");
}

// clear all stored original bytes
pub fn clear_stored_bytes() {
    if let Ok(mut map) = ORIGINAL_BYTES.lock() {
        map.clear();
        log_debug("All stored original bytes cleared");
    }
}
