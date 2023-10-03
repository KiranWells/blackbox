#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_ulong,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    macros::raw_tracepoint,
    programs::RawTracePointContext,
    BpfContext,
};
use aya_log_ebpf::info;

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn blackbox(ctx: RawTracePointContext) -> i32 {
    match try_blackbox(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_blackbox(ctx: RawTracePointContext) -> Result<i32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    // this is more like the PID in user-space
    let tgid = (pid_tgid >> 32) as u32;
    // this is more like the thread ID in user-space
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;
    let id =
        unsafe { bpf_probe_read((ctx.as_ptr() as *const c_ulong).offset(1)) }.map_err(|_| 1)?;
    info!(
        &ctx,
        "tracepoint sys_enter called by process {} in thread {} with syscall id {}", tgid, pid, id
    );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
