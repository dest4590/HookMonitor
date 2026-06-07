<div align=center>

<img width="256" src="https://github.com/user-attachments/assets/b998588d-1a4c-48cf-b727-d9488f9e1746" />

<h1>Hook Monitor</h1>

<h3>A Windows DLL that monitors and logs API calls made by a target process. Useful for understanding what an application is doing at runtime, or catching unexpected behavior.</h3>
  
</div> 

## What It Does

Hook Monitor injects itself into a running process and hooks key Windows API functions. As the target process calls these APIs, Hook Monitor logs the calls with details and prints them to a console window. You also get a debug log file on disk for later review.

The hooked functions include:

### File & Registry Operations

- **File operations** – CreateFileW shows what files the process is opening
- **Registry access** – RegOpenKeyExW logs registry key access

### Library Loading

- **LoadLibraryW** – Tracks DLL dependencies and loaded modules
- **GetProcAddress** – Monitors symbol resolution

### Process Management

- **CreateProcessW** – Shows subprocess creation with command lines
- **TerminateProcess** – Logs process termination

### Memory Operations

- **VirtualAlloc** – Memory allocation in current process
- **VirtualAllocEx** – Memory allocation in target processes (code injection)
- **WriteProcessMemory** – Memory writes to other processes

### Network Operations

- **socket** – Socket creation (AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM)
- **connect** – TCP connections to IPs and ports
- **send/recv** – Raw socket data transfer
- **InternetOpenW** – HTTP session creation
- **InternetConnectW** – HTTP server connections (domain:port)
- **HttpOpenRequestW** – HTTP request details (method, path, headers)
- **HttpSendRequestW** – HTTP request body and headers

### DNS Resolution

- **getaddrinfo** – Modern DNS API (returns domain → IP mapping)
- **gethostbyname** – Legacy DNS lookups
- **GetAddrInfoExW** – Asynchronous DNS resolution

### Example Output

<img width="960" height="480" alt="image" src="https://github.com/user-attachments/assets/d7799471-0c00-4101-b7e6-b5eefd1fa587" />

## How to Use

### Building

```bash
cargo build --release
```

The release build produces two outputs:

- `hook_monitor.dll` – The monitoring DLL (in `target/release/`)
- `injector.exe` – The injection tool (in `target/release/`)

### Injecting Into a Process

#### Option 1: Launch a new process and inject

```bash
injector.exe .\hook_monitor.dll C:\path\to\target\app.exe
```

Creates the target process in a suspended state, injects the DLL, then resumes execution.

#### Option 2: Attach to a running process by name

```bash
injector.exe .\hook_monitor.dll figma
# or with extension
injector.exe .\hook_monitor.dll figma.exe
```

Finds the first running process with that name and injects the DLL. A new console window opens showing real-time log output.

#### Option 3: Auto-discover DLL path

```bash
injector.exe anarchy.exe
# or find and attach to running process
injector.exe anarchy
```

The injector searches standard locations for `hook_monitor.dll` automatically.

### Output

While the hooked process runs, a console window displays API calls as they happen:

```
[14:32:15.123] [Hooked] CreateFileW Path: C:\Users\Public\log.txt
[14:32:15.145] [Hooked] socket Family: AF_INET (2), Type: SOCK_STREAM (1), Protocol: 6
[14:32:15.152] [Hooked] getaddrinfo Domain: api.github.com:443 (DNS Resolution)
[14:32:15.183] [Hooked] connect Socket: 1a4, Address: 140.82.121.6:443 (IPv4)
[14:32:15.201] [Hooked] HttpOpenRequestW Method: GET, Path: /repos/microsoft/windows-rs
[14:32:15.215] [Hooked] HttpSendRequestW Headers: Content-Length: 0
```

A debug log is also written to `dll_debug.log` in the same directory as the DLL.

## How It Works

### DLL Injection Process

When you run the injector:

1. Create a new process in a suspended state (or find an existing process)
2. Allocate memory in the target process
3. Write the DLL path into that memory
4. Get the address of `LoadLibraryW` from kernel32.dll
5. Create a remote thread that calls `LoadLibraryW` with the DLL path
6. Resume the main thread
7. (For attachment) Allocate console and tail the log file in real-time

The DLL then runs its `DllMain` function and installs all the hooks.

### Hook Installation

The DLL uses the `retour` crate to detour Windows API functions. For each hooked function:

1. Get the original function address from the module
2. Create a detour that intercepts calls
3. In the detour, log the call details with recursion guard
4. Forward the call to the original function
5. Return the result unchanged

Recursion guards prevent infinite loops when the logging code itself calls hooked functions.

## Architecture

```
src/
├── lib.rs              – DLL entry point (DllMain)
├── console.rs          – Console window setup
├── bin/
│   └── injector.rs     – Process injection tool with attachment support
└── hooks/
    ├── mod.rs          – Hook installation/removal coordination
    ├── common.rs       – Macros (install_detour!, remove_detour!), logging, recursion guard
    ├── file.rs         – CreateFileW hook
    ├── library.rs      – LoadLibraryW, GetProcAddress hooks
    ├── process.rs      – CreateProcessW, TerminateProcess hooks
    ├── memory.rs       – VirtualAlloc, VirtualAllocEx, WriteProcessMemory hooks
    ├── registry.rs     – RegOpenKeyExW hook
    ├── network.rs      – socket, connect, send/recv, InternetOpenW/ConnectW, HttpOpenRequestW/SendRequestW hooks
    └── dns.rs          – getaddrinfo, gethostbyname, GetAddrInfoExW hooks
```

## Features

✅ **Macro-based hook installation** – Reduces boilerplate, easy to add new hooks  
✅ **Poison recovery** – Continues operation even if locks are poisoned  
✅ **Process attachment** – Find and inject into running processes by name  
✅ **Real-time log tailing** – Console shows hooks as they happen  
✅ **Network monitoring** – Full socket and HTTP tracking  
✅ **DNS resolution capture** – See domain names (not just IPs)  
✅ **Colored output** – Easy to read console with syntax highlighting  
✅ **File logging** – Persistent debug log for offline analysis

## Dependencies

- `retour` – Function detouring
- `colored` – Colored console output
- `chrono` – Timestamps
- `anyhow` – Error handling
- `windows` – Windows API bindings
- `once_cell` – Lazy statics

## Notes

- The hook uses thread-local storage (`IN_HOOK`) to prevent recursion and infinite loops
- Null pointer checks prevent crashes when APIs receive invalid arguments
- UTF-16 conversion handles wide strings properly (fixing garbled characters)
- Hook installation is coordinated to ensure all APIs are hooked before application code runs
- On detach, all hooks are safely removed and resources cleaned up
- This is a monitoring tool and will slow down the target process significantly due to logging overhead
- Perfect for malware analysis to understand C2 communication, file exfiltration, DLL injection, etc.
