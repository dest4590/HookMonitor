use crate::hooks::common::*;
use std::collections::HashMap;
use std::sync::Mutex;

// syscall detection module
// keeps track of direct system calls, helps catch when software tries to bypass user-mode hooks

pub struct SyscallTrace {
    pub syscall_number: u32,
    pub name: String,
    pub timestamp: String,
    pub thread_id: u32,
}

static SYSCALL_TRACES: Mutex<Vec<SyscallTrace>> = Mutex::new(Vec::new());

// a list of common windows system calls we want to keep an eye on
pub static SYSCALL_DATABASE: &[(&str, u32)] = &[
    ("NtCreateFile", 0x55),
    ("NtOpenFile", 0x33),
    ("NtReadFile", 0x6),
    ("NtWriteFile", 0x8),
    ("NtQueryInformationFile", 0x17),
    ("NtSetInformationFile", 0x22),
    ("NtQueryDirectoryFile", 0x53),
    ("NtCreateProcess", 0x26),
    ("NtCreateProcessEx", 0xb1),
    ("NtCreateThread", 0x29),
    ("NtOpenProcess", 0x26),
    ("NtOpenThread", 0x20),
    ("NtTerminateProcess", 0x2c),
    ("NtTerminateThread", 0x31),
    ("NtAllocateVirtualMemory", 0x18),
    ("NtFreeVirtualMemory", 0x1e),
    ("NtProtectVirtualMemory", 0x50),
    ("NtQueryVirtualMemory", 0x23),
    ("NtMapViewOfSection", 0x25),
    ("NtUnmapViewOfSection", 0x27),
    ("NtLoadDriver", 0xb0),
    ("NtUnloadDriver", 0xb1),
    ("NtQuerySystemInformation", 0x36),
    ("NtSetSystemInformation", 0x37),
    ("NtGetContextThread", 0x181),
    ("NtSetContextThread", 0x182),
    ("NtSuspendThread", 0x14),
    ("NtResumeThread", 0x15),
    ("NtRegOpenKey", 0x1),
    ("NtRegCreateKey", 0x2),
    ("NtRegDeleteKey", 0x3),
    ("NtRegQueryKey", 0x4),
    ("NtRegQueryValueKey", 0x5),
    ("NtRegSetValueKey", 0x6),
];

// log a system call when we spot it
pub fn log_syscall(syscall_number: u32, name: &str, thread_id: u32) {
    let trace = SyscallTrace {
        syscall_number,
        name: name.to_string(),
        timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
        thread_id,
    };

    if let Ok(mut traces) = SYSCALL_TRACES.lock() {
        traces.push(trace);
        if traces.len() > 1000 {
            traces.remove(0); // keep the list size under control
        }
    }

    log_debug(&format!(
        "Syscall detected: {} (0x{:x}) TID: {}",
        name, syscall_number, thread_id
    ));
}

// find a syscall's name using its number
pub fn lookup_syscall(syscall_number: u32) -> Option<&'static str> {
    SYSCALL_DATABASE
        .iter()
        .find(|(_, num)| *num == syscall_number)
        .map(|(name, _)| *name)
}

// get a copy of all the syscalls we've logged so far
pub fn get_syscall_traces() -> Vec<(String, String, u32, u32)> {
    if let Ok(traces) = SYSCALL_TRACES.lock() {
        traces
            .iter()
            .map(|t| {
                (
                    t.name.clone(),
                    t.timestamp.clone(),
                    t.thread_id,
                    t.syscall_number,
                )
            })
            .collect()
    } else {
        Vec::new()
    }
}

// wipe the history of logged syscalls
pub fn clear_syscall_traces() {
    if let Ok(mut traces) = SYSCALL_TRACES.lock() {
        traces.clear();
        log_debug("All syscall traces cleared");
    }
}

// spot when something is looking up system call numbers on the fly
// game protectors and packers often resolve these dynamically to bypass hooks
pub fn detect_ssn_resolution(api_name: &str) -> Result<u32, String> {
    // look up the ssn from our database
    SYSCALL_DATABASE
        .iter()
        .find(|(name, _)| *name == api_name)
        .map(|(_, num)| *num)
        .ok_or_else(|| format!("Unknown API: {}", api_name))
}

// count how many times each system call was triggered
pub fn get_syscall_stats() -> HashMap<String, u32> {
    let mut stats = HashMap::new();

    if let Ok(traces) = SYSCALL_TRACES.lock() {
        for trace in traces.iter() {
            *stats.entry(trace.name.clone()).or_insert(0) += 1;
        }
    }

    stats
}
