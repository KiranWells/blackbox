use core::slice;

use aya_bpf::{helpers::bpf_probe_read_user_str_bytes, programs::RawTracePointContext};
use aya_log_ebpf::info;

use crate::types::{EbpfError, SysExitCtx, SysReadArgs};

/// Handle a read or write syscall
pub fn sys_read_write_handler(
    ctx: &RawTracePointContext,
    exit_args: &SysExitCtx,
) -> Result<(), EbpfError> {
    let is_write = exit_args.id == 1;
    let args = SysReadArgs::try_from(exit_args)?;
    let fd = args.fd;

    let mut string_data = [0u8; 64];

    let len_to_print = string_data.len().min(exit_args.ret as usize);
    let str_read = unsafe { bpf_probe_read_user_str_bytes(args.user_buf, string_data.as_mut()) }
        .map_err(|_| EbpfError::Read)?;

    let str_read = unsafe { slice::from_raw_parts(str_read.as_ptr(), len_to_print) };

    // TODO: send events to the user for this syscall
    info!(
        ctx,
        "sys_{}(fd: {}, user_buf: 0x{:x}=\"{}{}\", count: {}) = {}",
        if is_write { "write" } else { "read" },
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
