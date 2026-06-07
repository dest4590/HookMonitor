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
