pub use chrono::Local;
pub use colored::*;
pub use retour::GenericDetour;
pub use std::cell::Cell;
pub use std::sync::Mutex;
pub use windows::core::{s, w, BOOL, PCSTR, PCWSTR, PWSTR};
pub use windows::Win32::{
    Foundation::{HANDLE, HMODULE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE},
    System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW},
    System::Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE},
    System::Registry::{HKEY, REG_SAM_FLAGS},
    System::Threading::{PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW},
};

thread_local! {
    pub static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

#[macro_export]
macro_rules! with_recursion_guard {
    ($body:block) => {
        if !$crate::hooks::common::IN_HOOK.with(|h| h.get()) {
            $crate::hooks::common::IN_HOOK.with(|h| h.set(true));
            let _res = (|| $body)();
            $crate::hooks::common::IN_HOOK.with(|h| h.set(false));
        }
    };
}

static LOG_PATH: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join("dll_debug.log").to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| r"C:\hook_monitor\dll_debug.log".to_owned())
});

pub fn log_debug(msg: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_PATH.as_str())
    {
        let now = Local::now().format("%H:%M:%S%.3f");
        let _ = writeln!(file, "[{now}] {msg}");
    }
}

pub fn log_hook(name: &str, details: &str) {
    let now = Local::now().format("%H:%M:%S%.3f");
    if !name.contains("GetMessage")
        && !name.contains("CreateWindow")
        && !name.contains("PeekMessage")
    {
        log_debug(&format!("log_hook: {name} — {details}"));
    }

    if !name.contains("GetMessage") && !name.contains("PeekMessage") {
        println!(
            "{} {} {} {}",
            format!("[{now}]").bright_black(),
            "[Hooked]".red().bold(),
            name.green().bold(),
            details
        );
    }
}

pub unsafe fn pcwstr_to_string(ptr: PCWSTR) -> String {
    if ptr.is_null() {
        return "NULL".to_string();
    }

    let mut wide_chars = Vec::new();
    let mut offset = 0;
    loop {
        let ch = *(ptr.as_ptr().add(offset));
        if ch == 0 {
            break;
        }
        wide_chars.push(ch);
        offset += 1;
    }

    String::from_utf16_lossy(&wide_chars).to_owned()
}

#[macro_export]
macro_rules! get_function_ptr {
    ($module:expr, $fn_name:expr, $fn_type:ty) => {{
        match GetProcAddress($module, $crate::hooks::common::s($fn_name)) {
            Some(fn_ptr) => {
                let fn_ptr: $fn_type = std::mem::transmute(fn_ptr);
                Ok(fn_ptr)
            }
            None => Err(anyhow::anyhow!("Failed to get {}", $fn_name)),
        }
    }};
}

#[macro_export]
macro_rules! install_hook {
    ($detour:expr, $original_fn:expr, $hooked_fn:expr, $hook_name:expr) => {{
        match unsafe { $detour.enable() } {
            Ok(_) => {
                $crate::hooks::common::log_debug(&format!("{} hook installed", $hook_name));
                Ok(())
            }
            Err(e) => {
                let msg = format!("Failed to enable {} hook: {:?}", $hook_name, e);
                $crate::hooks::common::log_debug(&msg);
                Err(anyhow::anyhow!(msg))
            }
        }
    }};
}

#[macro_export]
macro_rules! remove_hook {
    ($detour:expr, $hook_name:expr) => {{
        if let Err(e) = unsafe { $detour.disable() } {
            $crate::hooks::common::log_debug(&format!(
                "Warning: Failed to disable {} hook: {:?}",
                $hook_name, e
            ));
        }
    }};
}

#[macro_export]
macro_rules! log_hooked_call {
    ($hook_name:expr, $details:expr) => {{
        if !$crate::hooks::common::IN_HOOK.with(|h| h.get()) {
            $crate::hooks::common::IN_HOOK.with(|h| h.set(true));
            $crate::hooks::common::log_hook($hook_name, $details);
            $crate::hooks::common::IN_HOOK.with(|h| h.set(false));
        }
    }};
}

#[macro_export]
macro_rules! call_hooked {
    ($mutex:expr, $detour_call:expr, $fallback:expr) => {{
        match $mutex.lock() {
            Ok(guard) => guard.as_ref().map_or_else(|| $fallback, $detour_call),
            Err(poisoned) => {
                $crate::hooks::common::log_debug("mutex poisoned");
                let guard = poisoned.into_inner();
                guard.as_ref().map_or_else(|| $fallback, $detour_call)
            }
        }
    }};
}

#[macro_export]
macro_rules! install_detour {
    ($module:expr, $fn_name:expr, $fn_type:ty, $hooked:expr, $hook_static:expr) => {{
        use windows::core::s;
        if let Some(proc) = GetProcAddress($module, s!($fn_name)) {
            let target: $fn_type = std::mem::transmute(proc);
            if let Ok(hook) = GenericDetour::new(target, $hooked) {
                let _ = hook.enable();
                match $hook_static.lock() {
                    Ok(mut guard) => *guard = Some(hook),
                    Err(poisoned) => {
                        let mut guard = poisoned.into_inner();
                        *guard = Some(hook);
                    }
                }
            }
        }
    }};
}

#[macro_export]
macro_rules! remove_detour {
    ($hook_static:expr) => {{
        let mut guard = $hook_static.lock().unwrap_or_else(|e| e.into_inner());
        let _ = guard.take().map(|h| h.disable());
    }};
}
