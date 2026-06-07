use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION,
    STARTUPINFOW,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    let dll_path = if args.len() > 1 {
        &args[1]
    } else {
        "C:\\Users\\Purpl3\\IT\\hook_monitor\\target\\debug\\hook_monitor.dll"
    };

    let target_path = if args.len() > 2 {
        &args[2]
    } else {
        "C:\\Users\\Purpl3\\Documents\\anarchyloader_2.0.0_lts.exe"
    };

    println!("[*] Hook Monitor Injector");
    println!("[*] DLL: {}", dll_path);
    println!("[*] Target: {}", target_path);

    let startup_info = STARTUPINFOW::default();
    let mut process_info = PROCESS_INFORMATION::default();
    let mut cmd_line: Vec<u16> = OsStr::new(target_path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        CreateProcessW(
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
        .expect("Failed to create process");

        println!("[+] Process created (PID: {})", process_info.dwProcessId);

        let process = process_info.hProcess;
        let dll_path_w: Vec<u16> = OsStr::new(dll_path).encode_wide().chain(Some(0)).collect();

        let remote_mem = VirtualAllocEx(
            process,
            None,
            dll_path_w.len() * 2,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        WriteProcessMemory(
            process,
            remote_mem,
            dll_path_w.as_ptr() as *const _,
            dll_path_w.len() * 2,
            None,
        )
        .expect("Failed to write memory");

        println!("[+] DLL path written to remote memory");

        let kernel32 = GetModuleHandleW(windows::core::w!("kernel32.dll")).unwrap();
        let load_lib = GetProcAddress(kernel32, windows::core::s!("LoadLibraryW"))
            .expect("LoadLibraryW not found");

        CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute(load_lib)),
            Some(remote_mem),
            0,
            None,
        )
        .expect("Failed to create remote thread");

        println!("[+] Remote thread created");

        let res = ResumeThread(process_info.hThread);
        if res == 0 {
            println!("[!] Warning: ResumeThread returned 0");
        }

        println!("[✓] DLL injected successfully!");
    }
}
