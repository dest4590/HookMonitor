pub mod common;
pub mod file;
pub mod library;
pub mod memory;
pub mod process;
pub mod registry;

use colored::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

pub unsafe fn install_all_hooks() {
    common::log_debug("install_all_hooks started");
    let k32 = match GetModuleHandleW(windows::core::w!("kernel32.dll")) {
        Ok(h) => {
            common::log_debug("GetModuleHandleW(kernel32.dll) succeeded");
            h
        }
        Err(e) => {
            common::log_debug(&format!("GetModuleHandleW(kernel32.dll) failed: {:?}", e));
            return;
        }
    };

    common::log_debug("Installing file hooks...");
    file::install(k32);

    common::log_debug("Installing library hooks...");
    library::install(k32);

    common::log_debug("Installing process hooks...");
    process::install(k32);

    common::log_debug("Installing memory hooks...");
    memory::install(k32);

    common::log_debug("Installing registry hooks...");
    registry::install(k32);

    println!("{}", "[+] All hooks installed successfully.".green().bold());
    common::log_debug("install_all_hooks completed successfully");
}

pub unsafe fn remove_all_hooks() {
    file::remove();
    library::remove();
    process::remove();
    memory::remove();
    registry::remove();
}
