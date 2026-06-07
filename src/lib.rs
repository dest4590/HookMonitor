mod console;
pub mod hooks;

use std::ffi::c_void;
use windows::core::BOOL;
use windows::Win32::Foundation::{HMODULE, TRUE};
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]
pub extern "system" fn DllMain(_module: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => unsafe {
            let _ = CreateThread(
                None,
                0,
                Some(init_thread),
                None,
                THREAD_CREATION_FLAGS(0),
                None,
            );
        },
        DLL_PROCESS_DETACH => unsafe {
            hooks::remove_all_hooks();
        },
        _ => {}
    }
    TRUE
}

unsafe extern "system" fn init_thread(_param: *mut c_void) -> u32 {
    console::alloc_console();

    hooks::install_all_hooks();

    0
}
