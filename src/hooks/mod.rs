pub mod common;
pub mod dns;
pub mod file;
pub mod hardware_bp;
pub mod library;
pub mod memory;
pub mod memory_cloak;
pub mod network;
pub mod process;
pub mod registry;
pub mod stealth;
pub mod syscall_monitor;
pub mod veh_hooks;

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

    // check stealth mode to decide which hook strategy to use
    let mode = stealth::get_stealth_config()
        .map(|c| c.mode)
        .unwrap_or(stealth::StealthMode::Hybrid);

    let use_inline = !matches!(mode, stealth::StealthMode::HardwareBreakpoint);

    if !use_inline {
        log_debug("HWBP-only mode: skipping inline detour hooks for monitored APIs");
    }

    // ============================================================
    // protection hooks — always installed regardless of mode
    // these are essential for HWBP to survive anti-debug:
    //   SetThreadContext / GetThreadContext — hide and restore our DR regs
    //   CreateThread — propagate breakpoints to new threads
    // ============================================================
    log_debug("Installing protection hooks (Set/GetThreadContext, CreateThread)...");
    match process::install(k32) {
        Ok(_) => {
            results.push(HookInstallResult {
                hook_name: "SetThreadContext (protection)",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "GetThreadContext (protection)",
                success: true,
                error: None,
            });
            results.push(HookInstallResult {
                hook_name: "CreateThread (propagation)",
                success: true,
                error: None,
            });
            if use_inline {
                // in inline mode these also serve as monitoring hooks
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
        }
        Err(e) => {
            log_debug(&format!("Process/protection hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "Protection hooks (process)",
                success: false,
                error: Some(e),
            });
        }
    }

    // ============================================================
    // inline monitoring hooks — only installed when NOT in pure HWBP mode
    // ============================================================
    if use_inline {
        // file hooks
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

        // library hooks
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

        // memory hooks
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

        // registry hooks
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

        // network hooks
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

        // dns hooks
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

        // memory cloaking hooks
        log_debug("Installing memory cloaking hooks...");
        match memory_cloak::install(k32) {
            Ok(_) => {
                results.push(HookInstallResult {
                    hook_name: "VirtualQuery (Cloaking)",
                    success: true,
                    error: None,
                });
                results.push(HookInstallResult {
                    hook_name: "ReadProcessMemory (Cloaking)",
                    success: true,
                    error: None,
                });
            }
            Err(e) => {
                log_debug(&format!("Memory cloaking installation failed: {}", e));
                results.push(HookInstallResult {
                    hook_name: "Memory Cloaking",
                    success: false,
                    error: Some(e),
                });
            }
        }
    }

    // ============================================================
    // stealth hooks (HWBP / page-guard) — always runs, respects mode internally
    // ============================================================
    log_debug("Installing stealth hooks...");
    match stealth::install_stealth_hooks(k32, &[]) {
        Ok(installed) => {
            for name in installed {
                results.push(HookInstallResult {
                    hook_name: Box::leak(name.into_boxed_str()),
                    success: true,
                    error: None,
                });
            }
        }
        Err(e) => {
            log_debug(&format!("Stealth hook installation failed: {}", e));
            results.push(HookInstallResult {
                hook_name: "Stealth hooks",
                success: false,
                error: Some(e),
            });
        }
    }

    let failed = results.iter().filter(|r| !r.success).count();

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
    memory_cloak::remove();
    hardware_bp::clear_all_breakpoints();
    veh_hooks::clear_all_veh_hooks();
}
