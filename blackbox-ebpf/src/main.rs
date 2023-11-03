#![no_std]
#![no_main]

mod handlers;
mod types;

use aya_log_ebpf::debug;
use blackbox_common::{EventBuffer, SyscallEvent, SyscallID};
use handlers::sys_read_write_handler;
use types::{EbpfError, SysExitCtx};

use aya_bpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, raw_tracepoint},
    maps::{Array, PerfEventArray},
    programs::RawTracePointContext,
};

use crate::{handlers::sys_open_handler, types::SysEnterCtx};

#[map]
static mut PIDS: Array<u32> = Array::with_max_entries(128, 0);
#[map]
static mut EVENT_OUTPUT: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);
#[map]
static mut BUFFER_OUTPUT: PerfEventArray<EventBuffer> = PerfEventArray::new(0);

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
    // let typed_ctx = SysEnterCtx::try_from(ctx)?;
    // if typed_ctx.id == 1 {
    //     debug!(
    //         ctx,
    //         "Received enter event {} with pid: {} and thread id: {}",
    //         typed_ctx.id,
    //         tgid,
    //         pid_tgid & 0xFFFF_FFFF
    //     );
    // }

    // TODO: handle multiple PIDS
    let traced_pid = *unsafe { PIDS.get(0) }.ok_or(EbpfError::Map)?;

    if tgid != traced_pid {
        return Ok(());
    }

    let typed_ctx = SysEnterCtx::try_from(ctx)?;
    let syscall_event = SyscallEvent::try_from(&typed_ctx)?;
    debug!(ctx, "Received enter event with id: {}", typed_ctx.id);

    match typed_ctx.id.into() {
        SyscallID::Read => send_event(ctx, &syscall_event),
        SyscallID::Write => sys_read_write_handler(ctx, syscall_event).map(|_| ()),
        SyscallID::Open => sys_open_handler(ctx, syscall_event).map(|_| ()),
        SyscallID::OpenAt => sys_open_handler(ctx, syscall_event).map(|_| ()),
        SyscallID::Close => send_event(ctx, &syscall_event),
        SyscallID::Socket => send_event(ctx, &syscall_event),
        SyscallID::Shutdown => send_event(ctx, &syscall_event),
        SyscallID::Fork => send_event(ctx, &syscall_event),
        SyscallID::Execve => send_event(ctx, &syscall_event),
        SyscallID::Exit => send_event(ctx, &syscall_event),
        SyscallID::ExitGroup => send_event(ctx, &syscall_event),
        SyscallID::Unhandled => send_event(ctx, &syscall_event),
    }?;
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

    // TODO: handle multiple PIDS
    let traced_pid = *unsafe { PIDS.get(0) }.ok_or(EbpfError::Map)?;

    if tgid != traced_pid {
        return Ok(());
    }
    let typed_ctx = SysExitCtx::try_from(ctx)?;
    let syscall_event = SyscallEvent::try_from(&typed_ctx)?;
    debug!(ctx, "Received exit event with id: {}", typed_ctx.id);

    match typed_ctx.id.into() {
        SyscallID::Read => sys_read_write_handler(ctx, syscall_event).map(|_| ()),
        SyscallID::Write => send_event(ctx, &syscall_event),
        SyscallID::Open => send_event(ctx, &syscall_event),
        SyscallID::OpenAt => send_event(ctx, &syscall_event),
        SyscallID::Close => send_event(ctx, &syscall_event),
        SyscallID::Socket => send_event(ctx, &syscall_event),
        SyscallID::Shutdown => send_event(ctx, &syscall_event),
        SyscallID::Fork => send_event(ctx, &syscall_event),
        SyscallID::Execve => send_event(ctx, &syscall_event),
        SyscallID::Exit => send_event(ctx, &syscall_event),
        SyscallID::ExitGroup => send_event(ctx, &syscall_event),
        SyscallID::Unhandled => send_event(ctx, &syscall_event),
    }?;
    Ok(())
}

fn send_event(ctx: &RawTracePointContext, event: &SyscallEvent) -> Result<(), EbpfError> {
    unsafe { EVENT_OUTPUT.output(ctx, event, 0) };
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
