use windows::Win32::System::Console::{
    AllocConsole, GetConsoleMode, GetStdHandle, SetConsoleMode, SetConsoleTitleW, SetStdHandle,
    CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
};

pub unsafe fn alloc_console() {
    AllocConsole().ok();
    SetConsoleTitleW(windows::core::w!("[ Hook Monitor ]")).ok();

    if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
        SetStdHandle(STD_OUTPUT_HANDLE, handle).ok();

        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode).is_ok() {
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    println!("[*] Console attached to target process.");
}
