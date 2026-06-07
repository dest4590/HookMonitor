use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, ResumeThread, TerminateProcess, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
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

fn main() {
    let args: Vec<String> = env::args().collect();

    let dll_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        match find_dll_path() {
            Ok(path) => path,
            Err(e) => {
                eprintln!("[!] Error: {}", e);
                eprintln!("[!] Usage: injector.exe [dll_path] [target_exe]");
                std::process::exit(1);
            }
        }
    };

    if !dll_path.exists() {
        eprintln!("[!] Error: DLL not found at {}", dll_path.display());
        std::process::exit(1);
    }

    let target_path = if args.len() > 2 {
        &args[2]
    } else {
        eprintln!("[!] Error: Target executable path required");
        eprintln!("[!] Usage: injector.exe [dll_path] <target_exe>");
        std::process::exit(1);
    };

    if !Path::new(target_path).exists() {
        eprintln!("[!] Error: Target executable not found at {}", target_path);
        std::process::exit(1);
    }

    println!("[*] Hook Monitor Injector");
    println!("[*] DLL: {}", dll_path.display());
    println!("[*] Target: {}", target_path);

    let startup_info = STARTUPINFOW::default();
    let mut process_info = PROCESS_INFORMATION::default();
    let mut cmd_line: Vec<u16> = OsStr::new(target_path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
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
            eprintln!("[!] Error: Failed to create process '{}'", target_path);
            std::process::exit(1);
        }

        println!("[+] Process created (PID: {})", process_info.dwProcessId);

        let process = process_info.hProcess;
        let dll_path_str = dll_path.to_str().unwrap_or_else(|| "<invalid path>");
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
            eprintln!("[!] Error: Failed to allocate memory in target process");
            let _ = TerminateProcess(process, 1);
            std::process::exit(1);
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
            eprintln!("[!] Error: Failed to write DLL path to target process memory");
            let _ = TerminateProcess(process, 1);
            std::process::exit(1);
        }

        println!("[+] DLL path written to remote memory");

        let kernel32 = match GetModuleHandleW(windows::core::w!("kernel32.dll")) {
            Ok(handle) => handle,
            Err(_) => {
                eprintln!("[!] Error: Failed to get kernel32.dll handle");
                let _ = TerminateProcess(process, 1);
                std::process::exit(1);
            }
        };

        let load_lib = match GetProcAddress(kernel32, windows::core::s!("LoadLibraryW")) {
            Some(addr) => addr,
            None => {
                eprintln!("[!] Error: LoadLibraryW not found in kernel32.dll");
                let _ = TerminateProcess(process, 1);
                std::process::exit(1);
            }
        };

        if CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute(load_lib)),
            Some(remote_mem),
            0,
            None,
        )
        .is_err()
        {
            eprintln!("[!] Error: Failed to create remote thread in target process");
            let _ = TerminateProcess(process, 1);
            std::process::exit(1);
        }

        println!("[+] Remote thread created");

        let res = ResumeThread(process_info.hThread);
        if res == 0 {
            eprintln!("[!] Warning: ResumeThread returned 0 (process may have exited)");
        }

        println!("[✓] DLL injected successfully!");
    }
}
