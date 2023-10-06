#![no_std]
#![no_main]

mod types;

use core::slice;

use types::{EbpfError, SysEnterArgs, SysExitCtx};

use aya_bpf::{
    cty::c_uint,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, raw_tracepoint},
    maps::{Array, HashMap},
    programs::RawTracePointContext,
};
use aya_log_ebpf::{debug, info};

use crate::types::SysEnterCtx;

#[map]
static mut SYSCALL_MAP_DATA: HashMap<(u32, u64), SysEnterArgs> = HashMap::with_max_entries(128, 0);

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

    // unsafe { SYSCALL_MAP_DATA.insert(&(tgid, typed_ctx.id), &SysEnterArgs::try_from(ctx)?, 0) }
    //     .map_err(|_| EbpfError::Map)
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

    // let sys_enter_args = unsafe { SYSCALL_MAP_DATA.get(&(tgid, typed_ctx.id)) }; //.ok_or(EbpfError::Map)?;
    // let sys_enter_args = match sys_enter_args {
    //     Some(a) => a,
    //     None => {
    //         error!(
    //             ctx,
    //             "Failed to fetch value from map in pid {} with syscall id: {}", tgid, typed_ctx.id
    //         );
    //         return Err(EbpfError::Map);
    //     }
    // };
    // unsafe {
    //     // remove unneded value from map
    //     SYSCALL_MAP_DATA
    //         .remove(&(tgid, typed_ctx.id))
    //         .map_err(|_| EbpfError::Map)?;
    // }

    match typed_ctx.id {
        0 => sys_read_write_handler(ctx, &typed_ctx, false),
        1 => sys_read_write_handler(ctx, &typed_ctx, true),
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

struct SysReadArgs {
    fd: c_uint,
    user_buf: *const u8,
    count: usize,
}

impl TryFrom<&SysExitCtx> for SysReadArgs {
    type Error = EbpfError;

    fn try_from(data: &SysExitCtx) -> Result<Self, Self::Error> {
        Ok(Self {
            fd: data.arg(0)? as c_uint,
            user_buf: data.arg(1)? as *const u8,
            count: data.arg(2)? as usize,
        })
    }
}

fn sys_read_write_handler(
    ctx: &RawTracePointContext,
    // enter_args: &SysEnterArgs,
    exit_args: &SysExitCtx,
    write: bool,
) -> Result<(), EbpfError> {
    let args = SysReadArgs::try_from(exit_args)?;
    let fd: c_uint = args.fd;

    let mut string_data = [0u8; 64];

    let len_to_print = string_data.len().min(exit_args.ret as usize);
    let str_read = unsafe { bpf_probe_read_user_str_bytes(args.user_buf, string_data.as_mut()) }
        .map_err(|_| EbpfError::Read)?;

    let str_read = unsafe { slice::from_raw_parts(str_read.as_ptr(), len_to_print) };

    info!(
        ctx,
        "sys_{}(fd: {}, user_buf: 0x{:x}=\"{}{}\", count: {}) = {}",
        if write { "write" } else { "read" },
        fd,
        args.user_buf as usize,
        unsafe { core::str::from_utf8_unchecked(str_read) },
        if exit_args.ret as usize > str_read.len() {
            "..."
        } else {
            ""
        },
        args.count,
        exit_args.ret,
    );

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
