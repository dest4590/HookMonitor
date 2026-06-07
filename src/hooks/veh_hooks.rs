use crate::hooks::common::*;
use std::sync::Mutex;
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_PROTECTION_FLAGS,
};

// vectored exception handler (veh) based page guard hooking
// uses page faults (page_guard) to intercept api calls without modifying function bytes
// more stealthy than inline hooks but has performance overhead

pub type VehCallback = fn() -> ();

pub struct VehHook {
    pub target_address: *const u8,
    pub page_size: usize,
    pub original_protect: PAGE_PROTECTION_FLAGS,
    pub callback: Option<VehCallback>,
}

unsafe impl Send for VehHook {}
unsafe impl Sync for VehHook {}

static ACTIVE_VEH_HOOKS: Mutex<Vec<VehHook>> = Mutex::new(Vec::new());

// install a veh-based page guard hook
// the target function's page is marked with page_guard, causing exceptions on access
pub unsafe fn install_veh_hook(
    target_addr: *const u8,
    callback: VehCallback,
) -> Result<(), String> {
    let page_size = 4096;
    let original_protect = PAGE_EXECUTE_READWRITE;

    let page_base = (target_addr as usize & !0xFFF) as *mut _;

    let new_protect = PAGE_EXECUTE_READWRITE | PAGE_GUARD;
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);

    if VirtualProtect(page_base, page_size, new_protect, &mut old_protect).is_ok() {
        log_debug(&format!(
            "VEH hook installed at {:?}, page size: {}, original protect: {:?}",
            target_addr, page_size, original_protect
        ));

        if let Ok(mut hooks) = ACTIVE_VEH_HOOKS.lock() {
            hooks.push(VehHook {
                target_address: target_addr,
                page_size,
                original_protect,
                callback: Some(callback),
            });
        }

        Ok(())
    } else {
        Err("Failed to set page protection with PAGE_GUARD".to_string())
    }
}

// remove a veh-based page guard hook
pub unsafe fn remove_veh_hook(target_addr: *const u8) -> Result<(), String> {
    if let Ok(mut hooks) = ACTIVE_VEH_HOOKS.lock() {
        if let Some(hook_idx) = hooks.iter().position(|h| h.target_address == target_addr) {
            let hook = hooks.remove(hook_idx);

            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            if VirtualProtect(
                hook.target_address as *mut _,
                hook.page_size,
                hook.original_protect,
                &mut old_protect,
            )
            .is_ok()
            {
                log_debug(&format!("VEH hook removed from {:?}", hook.target_address));
                return Ok(());
            }
        }
    }
    Err("Hook not found or failed to remove".to_string())
}

// clear all veh hooks
pub unsafe fn clear_all_veh_hooks() {
    if let Ok(mut hooks) = ACTIVE_VEH_HOOKS.lock() {
        for hook in hooks.iter() {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtect(
                hook.target_address as *mut _,
                hook.page_size,
                hook.original_protect,
                &mut old_protect,
            );
        }
        hooks.clear();
        log_debug("All VEH hooks cleared");
    }
}
