use crate::hooks::common::*;
use crate::{call_hooked, install_detour, log_hooked_call, remove_detour};
use retour::GenericDetour;
use std::sync::Mutex;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

// getaddrinfo (ansi)
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

    log_hooked_call!(
        "getaddrinfo (A)",
        &format!("Domain: {} Port: {}", domain.cyan().bold(), port)
    );

    call_hooked!(
        HOOK_GETADDRINFO_A,
        |detour| detour.call(pnode_name, pservice_name, phints, ppresults),
        -1
    )
}

// getaddrinfo (wide/unicode)
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

    log_hooked_call!(
        "getaddrinfo (W)",
        &format!("Domain: {} Port: {}", domain.cyan().bold(), port)
    );

    call_hooked!(
        HOOK_GETADDRINFO_W,
        |detour| detour.call(pnode_name, pservice_name, phints, ppresults),
        -1
    )
}

// gethostbyname (ansi)
pub type FnGetHostByName = unsafe extern "system" fn(PCSTR) -> *const u8;
static HOOK_GETHOSTBYNAME: Mutex<Option<GenericDetour<FnGetHostByName>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_gethostbyname(name: PCSTR) -> *const u8 {
    let hostname = if name.is_null() {
        "NULL".to_string()
    } else {
        name.to_string().unwrap_or_else(|_| "invalid".into())
    };

    log_hooked_call!("gethostbyname", &format!("Domain: {}", hostname.magenta()));

    call_hooked!(
        HOOK_GETHOSTBYNAME,
        |detour| detour.call(name),
        std::ptr::null()
    )
}

pub unsafe fn install(_k32: HMODULE) -> Result<(), String> {
    let ws2 =
        LoadLibraryW(windows::core::w!("ws2_32.dll")).map_err(|_| "Failed to load ws2_32.dll")?;

    install_detour!(
        ws2,
        "getaddrinfo",
        FnGetAddrInfoA,
        hooked_getaddrinfo_a,
        &HOOK_GETADDRINFO_A
    );
    install_detour!(
        ws2,
        "GetAddrInfoW",
        FnGetAddrInfoW,
        hooked_getaddrinfo_w,
        &HOOK_GETADDRINFO_W
    );
    install_detour!(
        ws2,
        "gethostbyname",
        FnGetHostByName,
        hooked_gethostbyname,
        &HOOK_GETHOSTBYNAME
    );

    Ok(())
}

pub unsafe fn remove() {
    remove_detour!(&HOOK_GETADDRINFO_A);
    remove_detour!(&HOOK_GETADDRINFO_W);
    remove_detour!(&HOOK_GETHOSTBYNAME);
}
