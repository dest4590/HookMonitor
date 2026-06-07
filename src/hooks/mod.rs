pub mod common;
pub mod dns;
pub mod file;
pub mod library;
pub mod memory;
pub mod network;
pub mod process;
pub mod registry;

use colored::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

use crate::hooks::common::log_debug;

#[derive(Debug)]
pub struct HookInstallResult {
    pub hook_name: &'static str,
    pub success: bool,
    pub error: Option<String>,
}

pub unsafe fn install_all_hooks() -> Vec<HookInstallResult> {
    let mut results = Vec::new();

    log_debug("install_all_hooks started");
    let k32 = match GetModuleHandleW(windows::core::w!("kernel32.dll")) {
        Ok(h) => {
            log_debug("GetModuleHandleW(kernel32.dll) succeeded");
            h
        }
        Err(e) => {
            let err_msg = format!("GetModuleHandleW(kernel32.dll) failed: {:?}", e);
            log_debug(&err_msg);
            eprintln!("[!] {}", err_msg);
            return results;
        }
    };

    // File hooks
    log_debug("Installing file hooks...");
    match file::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "CreateFileW",
                success: true,
                error: None,
            });
        }
        Err(e) => {
            log_debug(&format!("File hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "CreateFileW",
                success: false,
                error: Some(e),
            });
        }
    }

    // Library hooks
    log_debug("Installing library hooks...");
    match library::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "LoadLibraryW",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "GetProcAddress",
                success: true,
                error: None,
            });
        }
        Err(e) => {
            log_debug(&format!("Library hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "LoadLibraryW/GetProcAddress",
                success: false,
                error: Some(e),
            });
        }
    }

    // Process hooks
    log_debug("Installing process hooks...");
    match process::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "CreateProcessW",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "TerminateProcess",
                success: true,
                error: None,
            });
        }
        Err(e) => {
            log_debug(&format!("Process hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "CreateProcessW/TerminateProcess",
                success: false,
                error: Some(e),
            });
        }
    }

    // Memory hooks
    log_debug("Installing memory hooks...");
    match memory::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "VirtualAlloc",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "VirtualAllocEx",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "WriteProcessMemory",
                success: true,
                error: None,
            });
        }
        Err(e) => {
            log_debug(&format!("Memory hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "VirtualAlloc/VirtualAllocEx/WriteProcessMemory",
                success: false,
                error: Some(e),
            });
        }
    }

    // Registry hooks
    log_debug("Installing registry hooks...");
    match registry::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "RegOpenKeyExW",
                success: true,
                error: None,
            });
        }
        Err(e) => {
            log_debug(&format!("Registry hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "RegOpenKeyExW",
                success: false,
                error: Some(e),
            });
        }
    }

    // Network hooks
    log_debug("Installing network hooks...");
    match network::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "socket",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "connect",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "send",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "recv",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "InternetOpenW",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "InternetConnectW",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "HttpOpenRequestW",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "HttpSendRequestW",
                success: true,
                error: None,
            });
        }
        Err(e) => {
            log_debug(&format!("Network hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "Network (socket/connect/send/recv/InternetOpenW/InternetConnectW/HttpOpenRequestW/HttpSendRequestW)",
                success: false,
                error: Some(e),
            });
        }
    }

    // DNS hooks
    log_debug("Installing DNS hooks...");
    match dns::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "getaddrinfo",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "gethostbyname",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "GetAddrInfoExW",
                success: true,
                error: None,
            });
        }
        Err(e) => {
            log_debug(&format!("DNS hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "DNS (getaddrinfo/gethostbyname/GetAddrInfoExW)",
                success: false,
                error: Some(e),
            });
        }
    }

    // Print summary
    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();
    println!(
        "{}",
        format!(
            "[+] Hook installation summary: {} successful, {} failed",
            successful, failed
        )
        .green()
        .bold()
    );

    if failed > 0 {
        println!("{}", "[!] Failed hooks:".yellow().bold());
        for result in &results {
            if !result.success {
                if let Some(err) = &result.error {
                    println!("    - {}: {}", result.hook_name, err);
                } else {
                    println!("    - {}: unknown error", result.hook_name);
                }
            }
        }
    }

    log_debug("install_all_hooks completed");
    results
}

pub unsafe fn remove_all_hooks() {
    file::remove();
    library::remove();
    process::remove();
    memory::remove();
    registry::remove();
    network::remove();
    dns::remove();
}
