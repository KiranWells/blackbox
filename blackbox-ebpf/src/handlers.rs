use core::num::NonZeroUsize;

use aya_bpf::helpers::bpf_probe_read_user_buf;
use aya_bpf::maps::PerCpuArray;
use aya_bpf::{macros::map, programs::RawTracePointContext};
use aya_log_ebpf::debug;

use crate::types::EbpfError;
use crate::{send_event, BUFFER_OUTPUT};
use blackbox_common::{EventBuffer, SyscallEvent, BUFFER_SIZE};

#[map]
static mut DATA_BUFFER: PerCpuArray<EventBuffer> = PerCpuArray::with_max_entries(1, 0);

/// Handle a read or write syscall
///
/// Returns a u128 as the ok value to prevent an llvm error
/// with tuple returns. It should be treated as a () return
pub fn sys_read_write_handler(
    ctx: &RawTracePointContext,
    mut event: SyscallEvent,
) -> Result<u128, EbpfError> {
    let is_write = event.syscall_id == 1;

    let length = if is_write {
        NonZeroUsize::new(event.arg_2 as usize)
    } else {
        // read returns a ssize_t, which should be isize
        let ret = event.return_val.ok_or(EbpfError::Logic)? as isize;
        if ret < 0 {
            // there was an error returned by the function
            None
        } else {
            NonZeroUsize::new(ret as usize)
        }
    };
    let length = length.map(|l| unsafe { NonZeroUsize::new_unchecked(BUFFER_SIZE.min(l.get())) });

    let data_buffer = unsafe {
        let ptr = DATA_BUFFER.get_ptr_mut(0).ok_or(EbpfError::Map)?;
        &mut *ptr
    };

    event.data_size = length;
    data_buffer.pid = event.pid;
    data_buffer.tgid = event.tgid;
    data_buffer.timestamp = event.timestamp;

    if let Some(length) = length {
        debug!(ctx, "Sending buffer of len: {}", length.get());
        let buf_ptr = data_buffer.data_buffer.as_mut_ptr();

        let limited_length = length.get().min(BUFFER_SIZE);
        let dest = unsafe { core::slice::from_raw_parts_mut(buf_ptr, limited_length) };

        unsafe {
            bpf_probe_read_user_buf(event.arg_1 as *const u8, dest).map_err(|_| EbpfError::Read)?;
        };
        unsafe {
            BUFFER_OUTPUT.output(ctx, data_buffer, 0);
        }
    }

    send_event(ctx, &event)?;

    Ok(0)
}
