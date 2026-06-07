<div align=center>

<img width="256" src="https://github.com/user-attachments/assets/b998588d-1a4c-48cf-b727-d9488f9e1746" />

<h1>Hook Monitor</h1>

<h3>A Windows DLL that monitors and logs API calls made by a target process. Useful for understanding what an application is doing at runtime, or catching unexpected behavior.</h3>
  
</div> 

## What It Does

Hook Monitor injects itself into a running process and hooks key Windows API functions. As the target process calls these APIs, Hook Monitor logs the calls with details and prints them to a console window. You also get a debug log file on disk for later review.

The hooked functions include:

- **File operations** – CreateFileW shows what files the process is opening
- **Library loading** – LoadLibraryW and GetProcAddress track DLL dependencies
- **Process management** – CreateProcessW and TerminateProcess show subprocess activity
- **Memory operations** – VirtualAlloc, VirtualAllocEx, and WriteProcessMemory reveal memory allocation and modification
- **Registry access** – RegOpenKeyExW logs registry key access

### Example

<img width="960" height="480" alt="image" src="https://github.com/user-attachments/assets/d7799471-0c00-4101-b7e6-b5eefd1fa587" />

## How to Use

### Building

```bash
cargo build --release
```

The release build produces two outputs:

- `hook_monitor.dll` – The monitoring DLL
- `injector.exe` – The injection tool

### Injecting Into a Process

Use the injector to launch a target process with the hook already loaded:

```bash
injector.exe C:\path\to\hook_monitor.dll C:\path\to\target\app.exe
```

The injector creates the target process in a suspended state, writes the DLL path into its memory, calls LoadLibraryW via a remote thread, then resumes execution. The DLL initialization code runs in the context of the target process, sets up a console window, and installs all the hooks.

### Output

While the hooked process runs, a console window will display API calls as they happen:

```
[HH:MM:SS] [Hooked] CreateFileW Path: C:\Users\Public\log.txt
[HH:MM:SS] [Hooked] LoadLibraryW Library: shell32.dll
[HH:MM:SS] [Hooked] VirtualAllocEx Proc: 0x???, Addr: 0x???, Size: 4096, Protect: PAGE_EXECUTE_READWRITE
```

A debug log also gets written to `dll_debug.log` in the same directory as the DLL.

## How It Works

### DLL Injection Process

When you run the injector:

1. Create a new process in a suspended state
2. Allocate memory in the target process
3. Write the DLL path into that memory
4. Get the address of `LoadLibraryW` from kernel32.dll
5. Create a remote thread that calls `LoadLibraryW` with the DLL path
6. Resume the main thread

The DLL then runs its `DllMain` function, spawns a monitoring thread, and hooks the APIs.

### Hook Installation

The DLL uses the `retour` crate to detour Windows API functions. For each hooked function:

1. Get the original function address from kernel32.dll
2. Create a detour that intercepts calls
3. In the detour, log the call details
4. Forward the call to the original function
5. Return the result

Most hooks use a recursion guard to prevent infinite loops if the logging code itself calls hooked functions (like WriteProcessMemory).

## Architecture

```
src/
├── lib.rs          – DLL entry point (DllMain)
├── console.rs      – Console window setup
├── bin/injector.rs – Injection tool
└── hooks/
    ├── mod.rs      – Hook installation/removal
    ├── common.rs   – Logging utilities and recursion guard
    ├── file.rs     – File operation hooks
    ├── library.rs  – Library loading hooks
    ├── process.rs  – Process management hooks
    ├── memory.rs   – Memory operation hooks
    └── registry.rs – Registry access hooks
```

## Dependencies

- `retour` – Function detouring
- `colored` – Colored console output
- `chrono` – Timestamps
- `anyhow` – Error handling
- `windows` – Windows API bindings

## Notes

- The hook uses thread-local storage to track whether we're already inside a hooked function, which prevents log spam from recursive calls
- Some frequently-called functions like GetMessage and PeekMessage are filtered out to reduce noise
- The DLL requires debug symbols or manifest info to resolve all the APIs properly
- This is a monitoring tool and will slow down the target process significantly due to all the logging overhead
