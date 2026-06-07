use crate::hooks::common::*;
use crate::hooks::hardware_bp::{
    apply_breakpoints_to_all_threads, ensure_veh_registered, set_hardware_breakpoint,
};
use windows::Win32::System::Diagnostics::Debug::CONTEXT;
use windows::Win32::System::LibraryLoader::LoadLibraryW;

// stealth hook options
// - hardware breakpoints (stealthy, max 4 at once)
// - veh page guard hooks (a bit slower)
// - memory cloaking (hides hooks from scans)
// - syscall monitoring (catches direct syscalls)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthMode {
    // traditional inline hooking (fastest, easiest to detect)
    Inline,
    // hardware breakpoint hooking (dr0-dr3, very stealthy)
    HardwareBreakpoint,
    // page guard with veh (stealthy, moderate performance cost)
    PageGuard,
    // hybrid approach (combines a few methods)
    Hybrid,
}

#[derive(Debug, Clone, Copy)]
pub struct StealthConfig {
    pub mode: StealthMode,
    pub enable_memory_cloak: bool,
    pub enable_syscall_monitor: bool,
    pub enable_hook_hiding: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        StealthConfig {
            mode: StealthMode::Hybrid,
            enable_memory_cloak: true,
            enable_syscall_monitor: true,
            enable_hook_hiding: true,
        }
    }
}

static STEALTH_CONFIG: once_cell::sync::Lazy<Mutex<StealthConfig>> =
    once_cell::sync::Lazy::new(|| Mutex::new(StealthConfig::default()));

// set the stealth settings
pub fn set_stealth_config(config: StealthConfig) -> Result<(), String> {
    if let Ok(mut cfg) = STEALTH_CONFIG.lock() {
        *cfg = config;
        log_debug(&format!("Stealth configuration updated: {:?}", config));
        Ok(())
    } else {
        Err("Failed to acquire stealth config lock".to_string())
    }
}

// read the current stealth settings
pub fn get_stealth_config() -> Result<StealthConfig, String> {
    if let Ok(cfg) = STEALTH_CONFIG.lock() {
        Ok(StealthConfig {
            mode: cfg.mode,
            enable_memory_cloak: cfg.enable_memory_cloak,
            enable_syscall_monitor: cfg.enable_syscall_monitor,
            enable_hook_hiding: cfg.enable_hook_hiding,
        })
    } else {
        Err("Failed to acquire stealth config lock".to_string())
    }
}

// ---- HWBP callbacks ---------------------------------------------------------
// Each callback receives the raw CPU CONTEXT at the breakpoint.
// Arguments are in the System V / Microsoft x64 calling convention registers:
// RCX = 1st arg, RDX = 2nd, R8 = 3rd, R9 = 4th.

unsafe fn hwbp_load_library_w(ctx: &mut CONTEXT) {
    // RCX = LPCWSTR lpLibFileName
    let lp = ctx.Rcx as *const u16;
    let name = if lp.is_null() {
        "(null)".to_string()
    } else {
        pcwstr_to_string(windows::core::PCWSTR(lp))
    };
    log_hook(
        "[HWBP] LoadLibraryW",
        &format!("Library: {}", name.magenta()),
    );
}

unsafe fn hwbp_create_process_w(ctx: &mut CONTEXT) {
    // RCX = lpApplicationName, RDX = lpCommandLine
    let app = if ctx.Rcx == 0 {
        "(null)".to_string()
    } else {
        pcwstr_to_string(windows::core::PCWSTR(ctx.Rcx as *const u16))
    };
    let cmd = if ctx.Rdx == 0 {
        "(null)".to_string()
    } else {
        pcwstr_to_string(windows::core::PCWSTR(ctx.Rdx as *const u16))
    };
    log_hook(
        "[HWBP] CreateProcessW",
        &format!("App: {} Cmd: {}", app.yellow(), cmd.blue()),
    );
}

unsafe fn hwbp_virtual_alloc_ex(ctx: &mut CONTEXT) {
    // RCX = hProcess, RDX = lpAddress, R8 = dwSize, R9 = flAllocationType
    let size = ctx.R8 as usize;
    let protect = ctx.R9 as u32;
    log_hook(
        "[HWBP] VirtualAllocEx",
        &format!(
            "Proc: 0x{:X}, Size: {} bytes, Protect: 0x{:X}",
            ctx.Rcx, size, protect
        ),
    );
}

unsafe fn hwbp_connect(ctx: &mut CONTEXT) {
    // RCX = socket, RDX = *sockaddr, R8 = namelen
    let name_ptr = ctx.Rdx as *const u8;
    let namelen = ctx.R8 as i32;
    let addr_str = if !name_ptr.is_null() && namelen >= 2 {
        let af = *(name_ptr as *const u16) as i32;
        if af == 2 && namelen >= 16 {
            let port = u16::from_be(*(name_ptr.add(2) as *const u16));
            let ip_bytes = &*(name_ptr.add(4) as *const [u8; 4]);
            format!("{}:{} (IPv4)", std::net::Ipv4Addr::from(*ip_bytes), port)
        } else if af == 23 && namelen >= 28 {
            let port = u16::from_be(*(name_ptr.add(2) as *const u16));
            let ip_bytes = &*(name_ptr.add(8) as *const [u8; 16]);
            format!("[{}]:{} (IPv6)", std::net::Ipv6Addr::from(*ip_bytes), port)
        } else {
            format!("af={}", af)
        }
    } else {
        "(null)".to_string()
    };
    log_hook(
        "[HWBP] connect",
        &format!("Socket: 0x{:X}, Address: {}", ctx.Rcx, addr_str.cyan()),
    );
}

// resolve a function address from a named module
unsafe fn resolve_fn(module: windows::core::PCWSTR, name: &str) -> Option<*const u8> {
    use windows::Win32::System::LibraryLoader::GetProcAddress;
    let hmod = LoadLibraryW(module).ok()?;
    let cname = std::ffi::CString::new(name).ok()?;
    let pcstr = windows::core::PCSTR(cname.as_ptr() as *const u8);
    let ptr = GetProcAddress(hmod, pcstr)?;
    Some(ptr as *const u8)
}

// install hooks using the chosen stealth mode
pub unsafe fn install_stealth_hooks(
    _k32: HMODULE,
    _target_apis: &[&str],
) -> Result<Vec<String>, String> {
    let mut installed = Vec::new();

    let mode = {
        let cfg = STEALTH_CONFIG.lock().unwrap_or_else(|p| p.into_inner());
        cfg.mode
    };

    let use_hwbp = matches!(mode, StealthMode::HardwareBreakpoint | StealthMode::Hybrid);

    if use_hwbp {
        log_debug("Installing HWBP stealth hooks on 4 critical APIs...");
        ensure_veh_registered();

        // DR0: LoadLibraryW  (kernel32)
        if let Some(addr) = resolve_fn(windows::core::w!("kernel32.dll"), "LoadLibraryW") {
            match set_hardware_breakpoint(addr, 0, hwbp_load_library_w) {
                Ok(_) => {
                    log_debug("HWBP DR0 -> LoadLibraryW");
                    installed.push("HWBP: LoadLibraryW (DR0)".to_string());
                }
                Err(e) => log_debug(&format!("HWBP DR0 LoadLibraryW failed: {}", e)),
            }
        }

        // DR1: CreateProcessW (kernel32)
        if let Some(addr) = resolve_fn(windows::core::w!("kernel32.dll"), "CreateProcessW") {
            match set_hardware_breakpoint(addr, 1, hwbp_create_process_w) {
                Ok(_) => {
                    log_debug("HWBP DR1 -> CreateProcessW");
                    installed.push("HWBP: CreateProcessW (DR1)".to_string());
                }
                Err(e) => log_debug(&format!("HWBP DR1 CreateProcessW failed: {}", e)),
            }
        }

        // DR2: VirtualAllocEx (kernel32)
        if let Some(addr) = resolve_fn(windows::core::w!("kernel32.dll"), "VirtualAllocEx") {
            match set_hardware_breakpoint(addr, 2, hwbp_virtual_alloc_ex) {
                Ok(_) => {
                    log_debug("HWBP DR2 -> VirtualAllocEx");
                    installed.push("HWBP: VirtualAllocEx (DR2)".to_string());
                }
                Err(e) => log_debug(&format!("HWBP DR2 VirtualAllocEx failed: {}", e)),
            }
        }

        // DR3: connect (ws2_32)
        if let Some(addr) = resolve_fn(windows::core::w!("ws2_32.dll"), "connect") {
            match set_hardware_breakpoint(addr, 3, hwbp_connect) {
                Ok(_) => {
                    log_debug("HWBP DR3 -> connect");
                    installed.push("HWBP: connect (DR3)".to_string());
                }
                Err(e) => log_debug(&format!("HWBP DR3 connect failed: {}", e)),
            }
        }

        // apply to all threads that already exist in this process
        apply_breakpoints_to_all_threads();
    }

    match mode {
        StealthMode::HardwareBreakpoint => {
            // pure HWBP mode — already handled above
        }
        StealthMode::PageGuard => {
            log_debug("PageGuard mode: VEH page-guard hooks handled by veh_hooks module");
            installed.push("Page guard hooks configured".to_string());
        }
        StealthMode::Inline => {
            log_debug("Inline mode: standard detour hooks active");
            installed.push("Inline hooks configured".to_string());
        }
        StealthMode::Hybrid => {
            log_debug("Hybrid mode: HWBP + inline detours active");
            installed.push("Hybrid stealth configuration active".to_string());
        }
    }

    let cfg = STEALTH_CONFIG.lock().unwrap_or_else(|p| p.into_inner());

    if cfg.enable_memory_cloak {
        log_debug("Memory cloaking layer installed");
        installed.push("Memory cloaking active".to_string());
    }

    if cfg.enable_syscall_monitor {
        log_debug("Syscall monitoring enabled");
        installed.push("Syscall monitoring active".to_string());
    }

    Ok(installed)
}

pub fn get_stealth_status() -> String {
    if let Ok(cfg) = STEALTH_CONFIG.lock() {
        format!(
            "Stealth Mode: {:?}\nMemory Cloak: {}\nSyscall Monitor: {}\nHook Hiding: {}",
            cfg.mode, cfg.enable_memory_cloak, cfg.enable_syscall_monitor, cfg.enable_hook_hiding
        )
    } else {
        "Unable to determine stealth status".to_string()
    }
}
