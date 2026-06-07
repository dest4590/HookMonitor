mod console;
pub mod hooks;

use colored::*;
use std::env;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::core::BOOL;
use windows::Win32::Foundation::{HMODULE, TRUE};
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

static HOOKS_INITIALIZED: AtomicBool = AtomicBool::new(false);

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

    let stealth_mode_str =
        env::var("HOOK_MONITOR_STEALTH_MODE").unwrap_or_else(|_| "hybrid".to_string());

        let stealth_mode = match stealth_mode_str.to_lowercase().as_str() {
        "inline" => hooks::stealth::StealthMode::Inline,
        "hardware-breakpoint" => hooks::stealth::StealthMode::HardwareBreakpoint,
        "page-guard" => hooks::stealth::StealthMode::PageGuard,
        _ => hooks::stealth::StealthMode::Hybrid,
    };

    let config = hooks::stealth::StealthConfig {
        mode: stealth_mode,
        enable_memory_cloak: true,
        enable_syscall_monitor: true,
        enable_hook_hiding: true,
    };

    if let Err(e) = hooks::stealth::set_stealth_config(config) {
        eprintln!("[!] Failed to set stealth config: {}", e);
    }

    let results = hooks::install_all_hooks();
    let successful = results.iter().filter(|r| r.success).count();
    let total = results.len();

    if successful > 0 {
        println!(
            "{}",
            format!(
                "[✓] Hook Monitor initialized | Mode: {:?} ({} / {} hooks active)",
                stealth_mode, successful, total
            )
            .green()
            .bold()
        );
    } else {
        println!("[!] Warning: No hooks were successfully installed");
    }

    HOOKS_INITIALIZED.store(true, Ordering::Release);

    0
}

pub fn wait_for_hooks() {
    let mut wait_count = 0;
    while !HOOKS_INITIALIZED.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_millis(10));
        wait_count += 1;
        if wait_count > 5000 {
            eprintln!("[!] Hook initialization timeout");
            break;
        }
    }
}
