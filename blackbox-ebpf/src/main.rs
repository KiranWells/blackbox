#![no_std]
#![no_main]

mod handlers;
mod types;

use handlers::sys_read_write_handler;
use types::{EbpfError, SysExitCtx};

use aya_bpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, raw_tracepoint},
    maps::Array,
    programs::RawTracePointContext,
};
use aya_log_ebpf::debug;

use crate::types::SysEnterCtx;

#[map]
static mut PIDS: Array<u32> = Array::with_max_entries(128, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn handle_sys_enter(ctx: RawTracePointContext) -> i32 {
    match try_handle_sys_enter(&ctx) {
        Ok(()) => 0,
        Err(err) => {
            err.log(&ctx);
            1
        }
    }
}

fn try_handle_sys_enter(ctx: &RawTracePointContext) -> Result<(), EbpfError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    // this is more like the PID in user-space
    let tgid = (pid_tgid >> 32) as u32;
    // this is more like the thread ID in user-space
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;

    // TODO: handle multiple PIDS
    let traced_pid = *unsafe { PIDS.get(0) }.ok_or(EbpfError::Map)?;

    if tgid != traced_pid {
        return Ok(());
    }

    let typed_ctx = SysEnterCtx::try_from(ctx)?;

    // TODO: send a sys_enter event to userspace for timing
    debug!(
        ctx,
        "syscall 0x{:x} called by process {} in thread {}", typed_ctx.id, tgid, pid,
    );
    Ok(())
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn handle_sys_exit(ctx: RawTracePointContext) -> i32 {
    match try_handle_sys_exit(&ctx) {
        Ok(()) => 0,
        Err(err) => {
            err.log(&ctx);
            1
        }
    }
}

fn try_handle_sys_exit(ctx: &RawTracePointContext) -> Result<(), EbpfError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    // this is more like the PID in user-space
    let tgid = (pid_tgid >> 32) as u32;
    // this is more like the thread ID in user-space
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let typed_ctx = SysExitCtx::try_from(ctx)?;

    // TODO: handle multiple PIDS
    let traced_pid = *unsafe { PIDS.get(0) }.ok_or(EbpfError::Map)?;

    if tgid != traced_pid {
        return Ok(());
    }

    match typed_ctx.id {
        0 => sys_read_write_handler(ctx, &typed_ctx),
        1 => sys_read_write_handler(ctx, &typed_ctx),
        _ => {
            debug!(
                ctx,
                "syscall 0x{:x} returned to process {} in thread {}", typed_ctx.id, tgid, pid,
            );
            Ok(())
        }
    }?;
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
