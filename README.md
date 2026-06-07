<div align=center>

<img width="256" src="https://github.com/user-attachments/assets/b998588d-1a4c-48cf-b727-d9488f9e1746" />

<h1>Hook Monitor</h1>

<h3>A Windows DLL that monitors and logs API calls from a running process. Helps you understand what an application is doing at runtime or catch unexpected behavior.</h3>

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
# With specific stealth mode
injector.exe .\hook_monitor.dll C:\path\to\target\app.exe --mode hybrid
```

Creates the target process in a suspended state, injects the DLL, then resumes execution.

#### Option 2: Attach to a running process by name

```bash
injector.exe .\hook_monitor.dll figma
# With stealth mode
injector.exe .\hook_monitor.dll figma --mode hardware-breakpoint
```

Finds the first running process with that name and injects the DLL. A new console window opens showing real-time log output.

#### Option 3: Auto-discover DLL path

```bash
injector.exe anarchy.exe --mode hybrid
# Find and attach to running process with inline mode
injector.exe anarchy --mode inline
```

The injector searches standard locations for `hook_monitor.dll` automatically.

#### Stealth Modes

Available modes (use with `--mode` flag):

- **inline** – Traditional hooking, fastest but most detectable
- **hardware-breakpoint** – Uses CPU debug registers (DR0-DR3), very stealthy but limited to 4 APIs
- **page-guard** – VEH-based hooking with page guard exceptions, moderate stealth
- **hybrid** – Combines all techniques with minimal overhead (default, recommended)

### Output

While the hooked process runs, a console window displays API calls as they happen:

```
[18:25:36.661] CreateFileW -> Opening file: C:\Users\Public\hook_monitor
[18:25:36.662] CreateFileW -> Opening file: C:\Users\Public\hook_monitor\dll_debug.log
[18:25:36.662] GetProcAddress -> Resolving symbol: LoadLibraryW
[18:25:36.666] LoadLibraryW -> Loading library: advapi32.dll
[18:25:36.668] GetProcAddress -> Resolving symbol: RegOpenKeyExW
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
    ├── dns.rs          – getaddrinfo, gethostbyname, GetAddrInfoExW hooks
    ├── hardware_bp.rs         - CPU debug register hooking (DR0-DR3)
    ├── veh_hooks.rs           - PAGE_GUARD + VEH exception hooks
    ├── memory_cloak.rs        - VirtualQuery/ReadProcessMemory spoofing
    ├── syscall_monitor.rs     - Direct syscall detection (30+ APIs)
    └── stealth.rs - Unified stealth configuration
```

## Features

- Macro-based hook installation for easy extension
- Continues operating if locks are poisoned
- Process attachment by process name
- Real-time console log output
- Network monitoring with socket and HTTP tracking
- DNS resolution capture showing domain names
- Colored console output for readability
- File logging for offline analysis
- Stealth monitoring modes:
    - Hardware breakpoint hooks
    - Memory cloaking
    - Syscall monitoring
    - VEH page guard hooks
    - Hybrid mode

## Dependencies

- `retour` – Function detouring
- `colored` – Colored console output
- `chrono` – Timestamps
- `anyhow` – Error handling
- `windows` – Windows API bindings
- `once_cell` – Lazy statics

## Stealth Mode Performance

| Mode                   | Overhead | Detection | Best For         |
| ---------------------- | -------- | --------- | ---------------- |
| **Inline**             | ~0.1%    | High      | Speed            |
| **HardwareBreakpoint** | ~2-5%    | Very Low  | Critical APIs    |
| **PageGuard**          | ~10-20%  | Low       | Specific regions |
| **Hybrid**             | ~0.9%    | Very Low  | Production       |

Hybrid mode combines all techniques with minimal overhead. Works against Themida, VMProtect, StarForce, and Code Virtualizer.

## Notes

- The hook uses thread-local storage (`IN_HOOK`) to prevent recursion and infinite loops
- Null pointer checks prevent crashes when APIs receive invalid arguments
- UTF-16 conversion handles wide strings properly (fixing garbled characters)
- Hook installation is coordinated to ensure all APIs are hooked before application code runs
- On detach, all hooks are safely removed and resources cleaned up
- This is a monitoring tool and will slow down the target process due to logging overhead
- Stealth monitoring adds minimal overhead with hybrid mode
- Hardware breakpoints use CPU debug registers without modifying code
- Memory cloaking spoofs integrity checks
- Good for malware analysis, reverse engineering, and understanding C2 communication, file exfiltration, and code injection.
