use crate::hooks::common::*;
use crate::with_recursion_guard;
use retour::GenericDetour;
use std::sync::Mutex;
use windows::core::{s, PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

// --- getaddrinfo (ANSI) ---
pub type FnGetAddrInfoA = unsafe extern "system" fn(PCSTR, PCSTR, *const u8, *mut *mut u8) -> i32;
static HOOK_GETADDRINFO_A: Mutex<Option<GenericDetour<FnGetAddrInfoA>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_getaddrinfo_a(
    pnode_name: PCSTR,
    pservice_name: PCSTR,
    phints: *const u8,
    ppresults: *mut *mut u8,
) -> i32 {
    let domain = if pnode_name.is_null() {
        "NULL".to_string()
    } else {
        pnode_name.to_string().unwrap_or_else(|_| "invalid".into())
    };
    let port = if pservice_name.is_null() {
        "NULL".to_string()
    } else {
        pservice_name
            .to_string()
            .unwrap_or_else(|_| "invalid".into())
    };

    with_recursion_guard!({
        log_hook(
            "getaddrinfo (A)",
            &format!("Domain: {} Port: {}", domain.cyan().bold(), port),
        );
    });

    match HOOK_GETADDRINFO_A.lock().unwrap().as_ref() {
        Some(detour) => detour.call(pnode_name, pservice_name, phints, ppresults),
        None => -1,
    }
}

// --- getaddrinfo (Wide/Unicode) ---
pub type FnGetAddrInfoW = unsafe extern "system" fn(PCWSTR, PCWSTR, *const u8, *mut *mut u8) -> i32;
static HOOK_GETADDRINFO_W: Mutex<Option<GenericDetour<FnGetAddrInfoW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_getaddrinfo_w(
    pnode_name: PCWSTR,
    pservice_name: PCWSTR,
    phints: *const u8,
    ppresults: *mut *mut u8,
) -> i32 {
    let domain = pcwstr_to_string(pnode_name);
    let port = pcwstr_to_string(pservice_name);

    with_recursion_guard!({
        log_hook(
            "getaddrinfo (W)",
            &format!("Domain: {} Port: {}", domain.cyan().bold(), port),
        );
    });

    match HOOK_GETADDRINFO_W.lock().unwrap().as_ref() {
        Some(detour) => detour.call(pnode_name, pservice_name, phints, ppresults),
        None => -1,
    }
}

// --- gethostbyname (ANSI) ---
pub type FnGetHostByName = unsafe extern "system" fn(PCSTR) -> *const u8;
static HOOK_GETHOSTBYNAME: Mutex<Option<GenericDetour<FnGetHostByName>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_gethostbyname(name: PCSTR) -> *const u8 {
    let hostname = if name.is_null() {
        "NULL".to_string()
    } else {
        name.to_string().unwrap_or_else(|_| "invalid".into())
    };

    with_recursion_guard!({
        log_hook(
            "gethostbyname",
            &format!("Domain: {}", hostname.cyan().bold()),
        );
    });

    match HOOK_GETHOSTBYNAME.lock().unwrap().as_ref() {
        Some(detour) => detour.call(name),
        None => std::ptr::null(),
    }
}

pub unsafe fn install(_k32: HMODULE) -> Result<(), String> {
    let ws2 =
        LoadLibraryW(windows::core::w!("ws2_32.dll")).map_err(|_| "Failed to load ws2_32.dll")?;

    // Hook ANSI getaddrinfo
    if let Some(proc) = GetProcAddress(ws2, s!("getaddrinfo")) {
        let target: FnGetAddrInfoA = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_getaddrinfo_a) {
            let _ = hook.enable();
            *HOOK_GETADDRINFO_A.lock().unwrap() = Some(hook);
        }
    }

    // Hook Wide getaddrinfo
    if let Some(proc) = GetProcAddress(ws2, s!("GetAddrInfoW")) {
        let target: FnGetAddrInfoW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_getaddrinfo_w) {
            let _ = hook.enable();
            *HOOK_GETADDRINFO_W.lock().unwrap() = Some(hook);
        }
    }

    // Hook gethostbyname
    if let Some(proc) = GetProcAddress(ws2, s!("gethostbyname")) {
        let target: FnGetHostByName = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_gethostbyname) {
            let _ = hook.enable();
            *HOOK_GETHOSTBYNAME.lock().unwrap() = Some(hook);
        }
    }

    Ok(())
}

pub unsafe fn remove() {
    HOOK_GETADDRINFO_A
        .lock()
        .unwrap()
        .take()
        .map(|h| h.disable());
    HOOK_GETADDRINFO_W
        .lock()
        .unwrap()
        .take()
        .map(|h| h.disable());
    HOOK_GETHOSTBYNAME
        .lock()
        .unwrap()
        .take()
        .map(|h| h.disable());
}
