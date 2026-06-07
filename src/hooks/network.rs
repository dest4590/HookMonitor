use crate::hooks::common::*;

// --- socket (WinSock2) ---
pub type FnSocket = unsafe extern "system" fn(i32, i32, i32) -> usize;
static HOOK_SOCKET: Mutex<Option<GenericDetour<FnSocket>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_socket(af: i32, socket_type: i32, protocol: i32) -> usize {
    let af_str = match af {
        2 => "AF_INET",
        23 => "AF_INET6",
        1 => "AF_UNSPEC",
        _ => "UNKNOWN",
    };
    let type_str = match socket_type {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        _ => "UNKNOWN",
    };

    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "socket",
            &format!(
                "Family: {} ({}), Type: {} ({}), Protocol: {}",
                af_str, af, type_str, socket_type, protocol
            ),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_SOCKET.lock() {
        Ok(guard) => guard
            .as_ref()
            .map_or_else(|| 0, |detour| detour.call(af, socket_type, protocol)),
        Err(poisoned) => {
            log_debug("socket mutex poisoned");
            let guard = poisoned.into_inner();
            guard
                .as_ref()
                .map_or_else(|| 0, |detour| detour.call(af, socket_type, protocol))
        }
    }
}

// --- connect (WinSock2) ---
pub type FnConnect = unsafe extern "system" fn(usize, *const u8, i32) -> i32;
static HOOK_CONNECT: Mutex<Option<GenericDetour<FnConnect>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_connect(socket: usize, name: *const u8, namelen: i32) -> i32 {
    let addr_str = if !name.is_null() && namelen >= 2 {
        let af = *(name as *const u16) as i32;
        if af == 2 && namelen >= 16 {
            // AF_INET (IPv4)
            let port = u16::from_be(*(name.add(2) as *const u16));
            let ip_bytes = &*(name.add(4) as *const [u8; 4]);
            format!("{}:{} (IPv4)", std::net::Ipv4Addr::from(*ip_bytes), port)
        } else if af == 23 && namelen >= 28 {
            // AF_INET6 (IPv6)
            let port = u16::from_be(*(name.add(2) as *const u16));
            let ip_bytes = &*(name.add(8) as *const [u8; 16]);
            format!("[{}]:{} (IPv6)", std::net::Ipv6Addr::from(*ip_bytes), port)
        } else {
            format!("Unknown address family: {}", af)
        }
    } else {
        "NULL/Invalid".to_string()
    };

    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "connect",
            &format!("Socket: {:x}, Address: {}", socket, addr_str.cyan()),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_CONNECT.lock() {
        Ok(guard) => guard
            .as_ref()
            .map_or_else(|| -1, |detour| detour.call(socket, name, namelen)),
        Err(poisoned) => {
            log_debug("connect mutex poisoned");
            let guard = poisoned.into_inner();
            guard
                .as_ref()
                .map_or_else(|| -1, |detour| detour.call(socket, name, namelen))
        }
    }
}

// --- InternetOpenW (WinInet) ---
pub type FnInternetOpenW =
    unsafe extern "system" fn(PCWSTR, u32, PCWSTR, PCWSTR, u32) -> *mut std::ffi::c_void;
static HOOK_INTERNET_OPEN: Mutex<Option<GenericDetour<FnInternetOpenW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_internet_open_w(
    lpsz_agent: PCWSTR,
    dw_access_type: u32,
    lpsz_proxy: PCWSTR,
    lpsz_proxy_bypass: PCWSTR,
    dw_flags: u32,
) -> *mut std::ffi::c_void {
    let agent = pcwstr_to_string(lpsz_agent);
    let access_type = match dw_access_type {
        0 => "PRECONFIG",
        1 => "DIRECT",
        3 => "NAMED_PROXY",
        4 => "NAMED_PROXY_BYPASS",
        _ => "UNKNOWN",
    };

    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "InternetOpenW",
            &format!("Agent: {}, AccessType: {}", agent.magenta(), access_type),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_INTERNET_OPEN.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || std::ptr::null_mut(),
            |detour| {
                detour.call(
                    lpsz_agent,
                    dw_access_type,
                    lpsz_proxy,
                    lpsz_proxy_bypass,
                    dw_flags,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("InternetOpenW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || std::ptr::null_mut(),
                |detour| {
                    detour.call(
                        lpsz_agent,
                        dw_access_type,
                        lpsz_proxy,
                        lpsz_proxy_bypass,
                        dw_flags,
                    )
                },
            )
        }
    }
}

// --- InternetConnectW (WinInet) ---
pub type FnInternetConnectW = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    PCWSTR,
    u16,
    PCWSTR,
    PCWSTR,
    u32,
    u32,
    usize,
) -> *mut std::ffi::c_void;
static HOOK_INTERNET_CONNECT: Mutex<Option<GenericDetour<FnInternetConnectW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_internet_connect_w(
    h_internet: *mut std::ffi::c_void,
    lpsz_server_name: PCWSTR,
    n_server_port: u16,
    lpsz_user_name: PCWSTR,
    lpsz_password: PCWSTR,
    dw_service: u32,
    dw_flags: u32,
    dw_context: usize,
) -> *mut std::ffi::c_void {
    let server = pcwstr_to_string(lpsz_server_name);
    let service = match dw_service {
        1 => "FTP",
        3 => "HTTP",
        2 => "GOPHER",
        _ => "UNKNOWN",
    };

    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        log_hook(
            "InternetConnectW",
            &format!(
                "Domain: {}:{} ({})",
                server.cyan().bold(),
                n_server_port,
                service
            ),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_INTERNET_CONNECT.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || std::ptr::null_mut(),
            |detour| {
                detour.call(
                    h_internet,
                    lpsz_server_name,
                    n_server_port,
                    lpsz_user_name,
                    lpsz_password,
                    dw_service,
                    dw_flags,
                    dw_context,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("InternetConnectW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || std::ptr::null_mut(),
                |detour| {
                    detour.call(
                        h_internet,
                        lpsz_server_name,
                        n_server_port,
                        lpsz_user_name,
                        lpsz_password,
                        dw_service,
                        dw_flags,
                        dw_context,
                    )
                },
            )
        }
    }
}

// --- HttpOpenRequestW (WinInet) ---
pub type FnHttpOpenRequestW = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    PCWSTR,
    PCWSTR,
    PCWSTR,
    PCWSTR,
    PCWSTR,
    u32,
    usize,
) -> *mut std::ffi::c_void;
static HOOK_HTTP_OPEN_REQUEST: Mutex<Option<GenericDetour<FnHttpOpenRequestW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_http_open_request_w(
    h_connect: *mut std::ffi::c_void,
    lpsz_verb: PCWSTR,
    lpsz_object_name: PCWSTR,
    lpsz_version: PCWSTR,
    lpsz_referrer: PCWSTR,
    lplpsz_accept_types: PCWSTR,
    dw_flags: u32,
    dw_context: usize,
) -> *mut std::ffi::c_void {
    let verb = pcwstr_to_string(lpsz_verb);
    let path = pcwstr_to_string(lpsz_object_name);

    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));
        let referrer = pcwstr_to_string(lpsz_referrer);
        log_hook(
            "HttpOpenRequestW",
            &format!(
                "Method: {} {}, Referrer: {}",
                verb.bright_yellow(),
                path.cyan(),
                referrer.bright_black()
            ),
        );
        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_HTTP_OPEN_REQUEST.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || std::ptr::null_mut(),
            |detour| {
                detour.call(
                    h_connect,
                    lpsz_verb,
                    lpsz_object_name,
                    lpsz_version,
                    lpsz_referrer,
                    lplpsz_accept_types,
                    dw_flags,
                    dw_context,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("HttpOpenRequestW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || std::ptr::null_mut(),
                |detour| {
                    detour.call(
                        h_connect,
                        lpsz_verb,
                        lpsz_object_name,
                        lpsz_version,
                        lpsz_referrer,
                        lplpsz_accept_types,
                        dw_flags,
                        dw_context,
                    )
                },
            )
        }
    }
}

// --- HttpSendRequestW (WinInet) ---
pub type FnHttpSendRequestW =
    unsafe extern "system" fn(*mut std::ffi::c_void, PCWSTR, u32, *const u8, u32) -> BOOL;
static HOOK_HTTP_SEND_REQUEST: Mutex<Option<GenericDetour<FnHttpSendRequestW>>> = Mutex::new(None);

pub unsafe extern "system" fn hooked_http_send_request_w(
    h_request: *mut std::ffi::c_void,
    lpsz_headers: PCWSTR,
    dw_headers_length: u32,
    lpopt_ional: *const u8,
    dw_optional_length: u32,
) -> BOOL {
    let headers = pcwstr_to_string(lpsz_headers);

    let body_preview = if !lpopt_ional.is_null() && dw_optional_length > 0 {
        format!("{}B", dw_optional_length)
    } else {
        "0B".to_string()
    };

    if !IN_HOOK.with(|h| h.get()) {
        IN_HOOK.with(|h| h.set(true));

        log_hook(
            "HttpSendRequestW",
            &format!(
                "Headers: {}, Body: {}",
                headers.bright_black(),
                body_preview.yellow()
            ),
        );

        IN_HOOK.with(|h| h.set(false));
    }

    match HOOK_HTTP_SEND_REQUEST.lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || BOOL::default(),
            |detour| {
                detour.call(
                    h_request,
                    lpsz_headers,
                    dw_headers_length,
                    lpopt_ional,
                    dw_optional_length,
                )
            },
        ),
        Err(poisoned) => {
            log_debug("HttpSendRequestW mutex poisoned");
            let guard = poisoned.into_inner();
            guard.as_ref().map_or_else(
                || BOOL::default(),
                |detour| {
                    detour.call(
                        h_request,
                        lpsz_headers,
                        dw_headers_length,
                        lpopt_ional,
                        dw_optional_length,
                    )
                },
            )
        }
    }
}

pub unsafe fn install(_k32: HMODULE) -> Result<(), String> {
    let ws2 = match LoadLibraryW(windows::core::w!("ws2_32.dll")) {
        Ok(h) => h,
        Err(_) => {
            return Err("Failed to load ws2_32.dll".to_string());
        }
    };

    if let Some(proc) = GetProcAddress(ws2, s!("socket")) {
        let target: FnSocket = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_socket) {
            let _ = hook.enable();
            match HOOK_SOCKET.lock() {
                Ok(mut guard) => *guard = Some(hook),
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(ws2, s!("connect")) {
        let target: FnConnect = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_connect) {
            let _ = hook.enable();
            match HOOK_CONNECT.lock() {
                Ok(mut guard) => *guard = Some(hook),
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                }
            }
        }
    }

    let wininet = match LoadLibraryW(windows::core::w!("wininet.dll")) {
        Ok(h) => h,
        Err(_) => {
            return Err("Failed to load wininet.dll".to_string());
        }
    };

    if let Some(proc) = GetProcAddress(wininet, s!("InternetOpenW")) {
        let target: FnInternetOpenW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_internet_open_w) {
            let _ = hook.enable();
            match HOOK_INTERNET_OPEN.lock() {
                Ok(mut guard) => *guard = Some(hook),
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(wininet, s!("InternetConnectW")) {
        let target: FnInternetConnectW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_internet_connect_w) {
            let _ = hook.enable();
            match HOOK_INTERNET_CONNECT.lock() {
                Ok(mut guard) => *guard = Some(hook),
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(wininet, s!("HttpOpenRequestW")) {
        let target: FnHttpOpenRequestW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_http_open_request_w) {
            let _ = hook.enable();
            match HOOK_HTTP_OPEN_REQUEST.lock() {
                Ok(mut guard) => *guard = Some(hook),
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                }
            }
        }
    }

    if let Some(proc) = GetProcAddress(wininet, s!("HttpSendRequestW")) {
        let target: FnHttpSendRequestW = std::mem::transmute(proc);
        if let Ok(hook) = GenericDetour::new(target, hooked_http_send_request_w) {
            let _ = hook.enable();
            match HOOK_HTTP_SEND_REQUEST.lock() {
                Ok(mut guard) => *guard = Some(hook),
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    *guard = Some(hook);
                }
            }
        }
    }

    Ok(())
}

pub unsafe fn remove() {
    HOOK_SOCKET
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_CONNECT
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_INTERNET_OPEN
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_INTERNET_CONNECT
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_HTTP_OPEN_REQUEST
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
    HOOK_HTTP_SEND_REQUEST
        .lock()
        .ok()
        .and_then(|mut g| g.take().map(|h| h.disable()));
}
