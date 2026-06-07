use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use windows::core::PWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, GetExitCodeThread, OpenProcess, ResumeThread,
    WaitForSingleObject, CREATE_SUSPENDED, PROCESS_ALL_ACCESS, PROCESS_INFORMATION, STARTUPINFOW,
};

fn find_dll_path() -> Result<PathBuf, String> {
    if let Ok(path) = env::var("HOOK_MONITOR_DLL") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
    }

    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let candidates = [
                "hook_monitor.dll",
                "../hook_monitor.dll",
                "../../target/debug/hook_monitor.dll",
                "../../target/release/hook_monitor.dll",
            ];
            for candidate in &candidates {
                let full_path = exe_dir.join(candidate);
                if full_path.exists() {
                    return Ok(full_path);
                }
            }
        }
    }

    Err(
        "Could not find hook_monitor.dll. Set HOOK_MONITOR_DLL environment variable or place DLL in expected location."
            .to_string(),
    )
}

fn find_process_by_name(process_name: &str) -> Result<u32, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|_| "Failed to create toolhelp snapshot".to_string())?;

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        Process32FirstW(snapshot, &mut entry)
            .map_err(|_| "Failed to enumerate first process".to_string())?;

        loop {
            let exe_name = String::from_utf16_lossy(&entry.szExeFile)
                .trim_matches(char::from(0))
                .to_string();

            if exe_name.eq_ignore_ascii_case(process_name)
                || exe_name.eq_ignore_ascii_case(&format!("{}.exe", process_name))
            {
                let pid = entry.th32ProcessID;
                println!("[+] Found process '{}' with PID: {}", exe_name, pid);
                return Ok(pid);
            }

            if let Err(_) = Process32NextW(snapshot, &mut entry) {
                break;
            }
        }

        Err(format!("Process '{}' not found", process_name))
    }
}

fn inject_into_process(process: HANDLE, dll_path: &Path) -> Result<(), String> {
    unsafe {
        let absolute_path = std::fs::canonicalize(dll_path)
            .map_err(|e| format!("Failed to resolve DLL path: {}", e))?;
        let dll_path_str = absolute_path.to_str().unwrap_or_else(|| "<invalid path>");
        let dll_path_w: Vec<u16> = OsStr::new(dll_path_str)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let remote_mem = VirtualAllocEx(
            process,
            None,
            dll_path_w.len() * 2,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err("Failed to allocate memory in target process".to_string());
        }

        if WriteProcessMemory(
            process,
            remote_mem,
            dll_path_w.as_ptr() as *const _,
            dll_path_w.len() * 2,
            None,
        )
        .is_err()
        {
            return Err("Failed to write DLL path to target process memory".to_string());
        }



        let kernel32 = match GetModuleHandleW(windows::core::w!("kernel32.dll")) {
            Ok(handle) => handle,
            Err(_) => {
                return Err("Failed to get kernel32.dll handle".to_string());
            }
        };

        let load_lib = match GetProcAddress(kernel32, windows::core::s!("LoadLibraryW")) {
            Some(addr) => addr,
            None => {
                return Err("LoadLibraryW not found in kernel32.dll".to_string());
            }
        };

        let thread_handle = match CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute(load_lib)),
            Some(remote_mem),
            0,
            None,
        ) {
            Ok(handle) => handle,
            Err(_) => {
                return Err("Failed to create remote thread in target process".to_string());
            }
        };

        let wait_result = WaitForSingleObject(thread_handle, 10000);
        match wait_result.0 {
            0 => {
                let mut exit_code = 0u32;
                if GetExitCodeThread(thread_handle, &mut exit_code).is_ok() {
                    if exit_code == 0 {
                        return Err("DLL failed to load - LoadLibraryW returned NULL".to_string());
                    }
                }
            }
            258 => {
                println!("[!] Warning: Remote thread wait timed out");
            }
            _ => {}
        }

        Ok(())
    }
}

fn find_and_tail_log() {
    let log_path = PathBuf::from(r"C:\Users\Public\hook_monitor\dll_debug.log");

    println!("[*] Searching for log file...");

    for attempt in 0..30 {
        if log_path.exists() {
            println!("[+] Found log file: {}", log_path.display());
            println!("[*] Press Ctrl+C to stop\n");

            let mut last_pos: u64 = 0;

            if let Ok(metadata) = std::fs::metadata(&log_path) {
                last_pos = metadata.len();
            }

            loop {
                if let Ok(metadata) = std::fs::metadata(&log_path) {
                    let current_size = metadata.len();

                    if current_size > last_pos {
                        if let Ok(mut file) = File::open(&log_path) {
                            let _ = file.seek(SeekFrom::Start(last_pos));
                            let reader = BufReader::new(file);

                            for line in reader.lines().flatten() {
                                println!("{}", line);
                            }

                            last_pos = current_size;
                        }
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }
        }

        if attempt == 0 {
            print!("[*] Waiting for DLL to initialize");
        } else if attempt % 5 == 0 {
            print!(".");
        }

        thread::sleep(Duration::from_millis(100));
    }

    println!("\n[!] Could not find log file after 3 seconds");
    println!("[!] Expected location: {}", log_path.display());
    println!("[!] The DLL may not have initialized properly.");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let dll_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        match find_dll_path() {
            Ok(path) => path,
            Err(e) => {
                eprintln!("[!] Error: {}", e);
                eprintln!(
                    "[!] Usage: injector.exe [dll_path] <target_exe|process_name> [--mode MODE]"
                );
                eprintln!("[!] Modes: inline, hardware-breakpoint, page-guard, hybrid (default)");
                eprintln!("[!] Examples:");
                eprintln!("[!]   injector.exe hook_monitor.dll .\\anarchy.exe");
                eprintln!("[!]   injector.exe hook_monitor.dll anarchy --mode hybrid");
                eprintln!("[!]   injector.exe hook_monitor.dll app.exe --mode hardware-breakpoint");
                std::process::exit(1);
            }
        }
    };

    if !dll_path.exists() {
        eprintln!("[!] Error: DLL not found at {}", dll_path.display());
        std::process::exit(1);
    }

    let target = if args.len() > 2 {
        &args[2]
    } else {
        eprintln!("[!] Error: Target executable or process name required");
        eprintln!("[!] Usage: injector.exe [dll_path] <target_exe|process_name> [--mode MODE]");
        eprintln!("[!] Modes: inline, hardware-breakpoint, page-guard, hybrid (default)");
        eprintln!("[!] Examples:");
        eprintln!("[!]   injector.exe hook_monitor.dll .\\anarchy.exe");
        eprintln!("[!]   injector.exe hook_monitor.dll anarchy --mode hybrid");
        eprintln!("[!]   injector.exe hook_monitor.dll app.exe --mode hardware-breakpoint");
        std::process::exit(1);
    };

    let mut stealth_mode = "hybrid".to_string();
    if args.len() > 3 && args[3] == "--mode" && args.len() > 4 {
        let mode = &args[4].to_lowercase();
        if matches!(
            mode.as_str(),
            "inline" | "hardware-breakpoint" | "page-guard" | "hybrid"
        ) {
            stealth_mode = mode.clone();
        } else {
            eprintln!("[!] Error: Invalid stealth mode '{}'", mode);
            eprintln!("[!] Valid modes: inline, hardware-breakpoint, page-guard, hybrid");
            std::process::exit(1);
        }
    }

    println!(
        "[*] Injecting {} into {} (Mode: {})",
        dll_path.file_name().unwrap_or_else(|| dll_path.as_os_str()).to_string_lossy(),
        target,
        stealth_mode
    );
    env::set_var("HOOK_MONITOR_STEALTH_MODE", &stealth_mode);

    let (process_handle, main_thread_handle, is_attaching) = if Path::new(target).exists() {
        unsafe {
            let startup_info = STARTUPINFOW::default();
            let mut process_info = PROCESS_INFORMATION::default();
            let mut cmd_line: Vec<u16> = OsStr::new(target).encode_wide().chain(Some(0)).collect();

            if CreateProcessW(
                None,
                Some(PWSTR(cmd_line.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &startup_info,
                &mut process_info,
            )
            .is_err()
            {
                eprintln!("[!] Error: Failed to create process '{}'", target);
                std::process::exit(1);
            }

            println!(
                "[✓] Created suspended process (PID: {})",
                process_info.dwProcessId
            );
            (process_info.hProcess, Some(process_info.hThread), false)
        }
    } else {
        println!("[*] Target: {} (finding process)", target);

        unsafe {
            let _ = AllocConsole();
        }

        let pid = match find_process_by_name(target) {
            Ok(pid) => pid,
            Err(e) => {
                eprintln!("[!] Error: {}", e);
                std::process::exit(1);
            }
        };

        unsafe {
            match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
                Ok(handle) => (handle, None, true),
                Err(_) => {
                    eprintln!("[!] Error: Failed to open process with PID {}", pid);
                    std::process::exit(1);
                }
            }
        }
    };

    match inject_into_process(process_handle, &dll_path) {
        Ok(_) => {
            println!("[✓] DLL injected successfully!");
            if let Some(h_thread) = main_thread_handle {
                println!("[*] Resuming target main thread...");
                unsafe {
                    let _ = ResumeThread(h_thread);
                    let _ = windows::Win32::Foundation::CloseHandle(h_thread);
                }
            }
            if is_attaching {
                println!("[*] Opening console window...\n");
                find_and_tail_log();
            }
        }
        Err(e) => {
            if let Some(h_thread) = main_thread_handle {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(h_thread);
                }
            }
            eprintln!("[!] Error: {}", e);
            std::process::exit(1);
        }
    }
}
