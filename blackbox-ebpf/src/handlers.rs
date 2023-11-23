use core::num::NonZeroUsize;

use aya_bpf::helpers::{bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes};
use aya_bpf::maps::PerCpuArray;
use aya_bpf::{macros::map, programs::RawTracePointContext};

use crate::types::EbpfError;
use crate::{send_event, BUFFER_OUTPUT};
use blackbox_common::{EventBuffer, EventID, GetEventId, SyscallEvent, SyscallID, BUFFER_SIZE};

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

    event.data_size = length;

    if let Some(length) = length {
        let result = read_bytes_and_send(
            ctx,
            event.arg_1 as *const u8,
            length.get(),
            event.get_event_id(),
            event.syscall_id,
        );
        if let Err(error) = result {
            event.data_size = None;
            send_event(ctx, &event)?;
            return Err(error);
        }
    }

    send_event(ctx, &event)?;
    Ok(0)
}

pub fn filename_handler(
    ctx: &RawTracePointContext,
    mut event: SyscallEvent,
) -> Result<u128, EbpfError> {
    let ptr = if event.syscall_id == SyscallID::OpenAt as u64
        || event.syscall_id == SyscallID::ExecveAt as u64
    {
        event.arg_1 as *const u8
    } else {
        // open or creat or execve
        event.arg_0 as *const u8
    };
    let length = read_string_and_send(ctx, ptr, event.get_event_id(), event.syscall_id);
    event.data_size = length.unwrap_or(None);
    send_event(ctx, &event)?;
    length?;
    Ok(0)
}

fn read_bytes_and_send(
    ctx: &RawTracePointContext,
    ptr: *const u8,
    length: usize,
    event_id: EventID,
    syscall_id: u64,
) -> Result<(), EbpfError> {
    let data_buffer = unsafe {
        let ptr = DATA_BUFFER.get_ptr_mut(0).ok_or(EbpfError::Map)?;
        &mut *ptr
    };
    data_buffer.pid = event_id.pid;
    data_buffer.tgid = event_id.tgid;
    data_buffer.timestamp = event_id.timestamp;
    data_buffer.syscall_id = syscall_id;

    let buf_ptr = data_buffer.data_buffer.as_mut_ptr();

    let limited_length = length.min(BUFFER_SIZE);
    let dest = unsafe { core::slice::from_raw_parts_mut(buf_ptr, limited_length) };

    unsafe {
        bpf_probe_read_user_buf(ptr, dest).map_err(|_| EbpfError::Read(Some(syscall_id)))?;
    };
    unsafe {
        BUFFER_OUTPUT.output(ctx, data_buffer, 0);
    }
    Ok(())
}

fn read_string_and_send(
    ctx: &RawTracePointContext,
    ptr: *const u8,
    event_id: EventID,
    syscall_id: u64,
) -> Result<Option<NonZeroUsize>, EbpfError> {
    let data_buffer = unsafe {
        let ptr = DATA_BUFFER.get_ptr_mut(0).ok_or(EbpfError::Map)?;
        &mut *ptr
    };
    data_buffer.pid = event_id.pid;
    data_buffer.tgid = event_id.tgid;
    data_buffer.timestamp = event_id.timestamp;
    data_buffer.syscall_id = syscall_id;

    let buf_ptr = data_buffer.data_buffer.as_mut_ptr();

    let dest = unsafe { core::slice::from_raw_parts_mut(buf_ptr, BUFFER_SIZE) };
    let result_slice = unsafe {
        bpf_probe_read_user_str_bytes(ptr, dest).map_err(|_| EbpfError::Read(Some(syscall_id)))?
    };

    if !result_slice.is_empty() {
        unsafe {
            BUFFER_OUTPUT.output(ctx, data_buffer, 0);
        }
    }
    Ok(NonZeroUsize::new(result_slice.len()))
}
