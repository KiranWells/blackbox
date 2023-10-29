use std::collections::HashMap;

use std::ffi::OsString;
use std::mem::size_of;
use std::os::unix::prelude::OsStringExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aya::maps::{Array, AsyncPerfEventArray};
use aya::programs::RawTracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use blackbox_common::{EventBuffer, EventID, GetEventId, SyscallEvent, SyscallID};
use bytes::BytesMut;
use color_eyre::eyre::Result;
use color_eyre::Report;
use log::{debug, info, warn};
use tokio::sync::Mutex;

use crate::types::{
    CloseData, Event, EventType, ForkData, OpenData, ReadData, TraceEvent, WriteData,
};

pub async fn start_tracing(pid: u32, tx: tokio::sync::mpsc::Sender<TraceEvent>) -> Result<()> {
    let event_staging = Arc::new(Mutex::new(HashMap::<EventID, SyscallEvent>::new()));
    let buffer_staging = Arc::new(Mutex::new(HashMap::<EventID, EventBuffer>::new()));
    let mut bpf = init_bpf(pid)?;
    let mut event_output = AsyncPerfEventArray::try_from(bpf.take_map("EVENT_OUTPUT").unwrap())?;
    let mut buffer_output = AsyncPerfEventArray::try_from(bpf.take_map("BUFFER_OUTPUT").unwrap())?;
    let mut handles = Vec::new();
    for cpu_id in online_cpus()? {
        debug!("Creating listener: {}/{}", cpu_id, 23);
        // open a separate perf buffer for each cpu
        let mut buf = event_output.open(cpu_id, Some(128))?;
        let movable_buffer_staging = buffer_staging.clone();
        let movable_event_staging = event_staging.clone();
        let movable_tx = tx.clone();
        let done_outer = Arc::new(AtomicBool::new(false));
        let done = done_outer.clone();

        handles.push(tokio::task::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(size_of::<SyscallEvent>()))
                .collect::<Vec<_>>();

            'outer: loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await?;

                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for buf in buffers.iter_mut().take(events.read) {
                    let payload = unsafe {
                        let ptr = buf.as_ptr() as *const SyscallEvent;
                        (*ptr).clone()
                    };

                    if payload.has_data() {
                        // get the associated data
                        let associated_buffer = {
                            // debug!("locking buffer");
                            let mut map = movable_buffer_staging.lock().await;
                            map.remove(&payload.get_event_id())
                        };
                        // debug!("unlocked buffer");

                        match associated_buffer {
                            Some(expr) => {
                                if send_event(payload, Some(expr), &movable_tx).await? {
                                    done.swap(true, Ordering::Release);
                                    break 'outer;
                                }
                            }
                            None => {
                                // if there is no data, we need to wait for it. We'll save this for
                                // later
                                // debug!("locking event");
                                {
                                    let mut map = movable_event_staging.lock().await;
                                    map.insert(payload.get_event_id(), payload);
                                }
                                // debug!("unlocked event");
                            }
                        }
                    } else {
                        // If there is no associated_buffer, we don't need to wait for it
                        if send_event(payload, None, &movable_tx).await? {
                            done.swap(true, Ordering::Release);
                            break 'outer;
                        }
                    }
                }
                if done.load(Ordering::Acquire) {
                    break;
                }
            }
            debug!("after loop: events");

            // This is necessary to tell the compiler what type this block returns
            Ok::<(), Report>(())
        }));

        let mut buf = buffer_output.open(cpu_id, Some(128))?;
        let movable_buffer_staging = buffer_staging.clone();
        let movable_event_staging = event_staging.clone();
        let movable_tx = tx.clone();
        let done = done_outer.clone();
        handles.push(tokio::task::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(size_of::<EventBuffer>()))
                .collect::<Vec<_>>();

            'outer: loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await?;

                for buf in buffers.iter_mut().take(events.read) {
                    let payload = unsafe {
                        let ptr = buf.as_ptr() as *const EventBuffer;
                        (*ptr).clone()
                    };

                    // get the associated event
                    let associated_buffer = {
                        // debug!("locking event");
                        let mut map = movable_event_staging.lock().await;
                        map.remove(&payload.get_event_id())
                    };
                    // debug!("unlocked event");

                    match associated_buffer {
                        Some(expr) => {
                            if send_event(expr, Some(payload), &movable_tx).await? {
                                done.swap(true, Ordering::Release);
                                break 'outer;
                            }
                        }
                        None => {
                            // if there is no event, we need to wait for it. We'll save this for
                            // later
                            // debug!("locking buffer");
                            {
                                let mut map = movable_buffer_staging.lock().await;
                                map.insert(payload.get_event_id(), payload);
                            }
                            // debug!("unlocked buffer");
                        }
                    }
                }
                if done.load(Ordering::Acquire) {
                    break;
                }
            }
            debug!("after loop: buffers");

            // This is necessary to tell the compiler what type this block returns
            Ok::<(), Report>(())
        }));
    }

    // TODO: handle the fact that these will never rejoin if stuck awaiting events
    for handle in handles {
        handle.await??;
    }

    Ok(())
}

async fn send_event(
    event: SyscallEvent,
    buffer: Option<EventBuffer>,
    tx: &tokio::sync::mpsc::Sender<TraceEvent>,
) -> Result<bool> {
    let mut data = None;
    if let Some(buffer) = buffer {
        assert!(event.has_data(), "Recieved data for an event with no data!");
        let len = event.data_size.unwrap();
        data = Some(buffer.data_buffer[..len.get()].to_owned());
    }
    let event_data = match event.syscall_id.into() {
        SyscallID::Read => EventType::Read(ReadData {
            file_descriptor: event.arg_0 as i32,
            count: event.arg_2 as usize,
            data_read: data,
            bytes_read: event.return_val.map(|r| {
                if (r as isize) < 0 {
                    Err(r as isize)
                } else {
                    Ok(r as usize)
                }
            }),
        }),
        SyscallID::Write => EventType::Write(WriteData {
            file_descriptor: event.arg_0 as i32,
            count: event.arg_2 as usize,
            data_written: data,
            bytes_written: event.return_val.map(|r| {
                if (r as isize) < 0 {
                    Err(r as isize)
                } else {
                    Ok(r as usize)
                }
            }),
        }),
        SyscallID::Open => EventType::Open(OpenData {
            filename: data.map(OsString::from_vec),
            flags: event.arg_1 as i32,
            file_descriptor: event.return_val.map(|r| {
                if (r as i32) < 0 {
                    Err(r as i32)
                } else {
                    Ok(r as u32)
                }
            }),
        }),
        SyscallID::OpenAt => EventType::Open(OpenData {
            filename: data.map(OsString::from_vec),
            flags: event.arg_2 as i32,
            file_descriptor: event.return_val.map(|r| {
                if (r as i32) < 0 {
                    Err(r as i32)
                } else {
                    Ok(r as u32)
                }
            }),
        }),
        SyscallID::Close => EventType::Close(CloseData {
            file_descriptor: event.arg_0 as i32,
            return_val: event.return_val.map(|r| {
                if (r as i32) < 0 {
                    Err(r as i32)
                } else {
                    Ok(())
                }
            }),
        }),
        SyscallID::Socket => EventType::Socket(crate::types::SocketData {
            domain: event.arg_0 as i32,
            r#type: event.arg_1 as i32,
            protocol: event.arg_2 as i32,
            file_descriptor: event.return_val.map(|r| {
                if (r as i32) < 0 {
                    Err(r as i32)
                } else {
                    Ok(r as u32)
                }
            }),
        }),
        SyscallID::Shutdown => EventType::Shutdown(crate::types::ShutdownData {
            file_descriptor: event.arg_0 as i32,
            how: event.arg_1 as i32,
            return_val: event.return_val.map(|r| {
                if (r as i32) < 0 {
                    Err(r as i32)
                } else {
                    Ok(())
                }
            }),
        }),
        SyscallID::Fork => EventType::Fork(ForkData {
            pid: event.return_val.map(|r| {
                if (r as i32) < 0 {
                    Err(r as i32)
                } else {
                    Ok(r as u32)
                }
            }),
        }),
        SyscallID::Exit => EventType::Exit(crate::types::ExitData {
            status: event.arg_0 as i32,
        }),
        SyscallID::ExitGroup => EventType::Exit(crate::types::ExitData {
            status: event.arg_0 as i32,
        }),
        SyscallID::Unhandled => EventType::Unhandled(crate::types::UnhandledSyscallData {
            syscall_id: event.syscall_id,
            arg_0: event.arg_0,
            arg_1: event.arg_1,
            arg_2: event.arg_2,
            arg_3: event.arg_3,
            arg_4: event.arg_4,
            arg_5: event.arg_5,
            return_val: event.return_val,
        }),
    };
    let is_process_exit = matches!(event_data, EventType::Exit(_));

    let event_to_send = TraceEvent {
        pid: event.tgid,
        thread_id: event.pid,
        event: if event.is_enter() {
            Event::Enter
        } else {
            Event::Exit
        },
        monotonic_timestamp: event.timestamp,
        event_type: event_data,
    };

    tx.send(event_to_send).await?;
    Ok(is_process_exit)
}

fn init_bpf(pid: u32) -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/blackbox"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/blackbox"
    ))?;

    // #[cfg(debug_assertions)]
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // set up the sys_enter and sys_exit tracepoints
    let program: &mut RawTracePoint = bpf.program_mut("handle_sys_enter").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;
    let program: &mut RawTracePoint = bpf.program_mut("handle_sys_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_exit")?;

    // populate PID filter buffer
    let mut traced_pids: aya::maps::array::Array<_, u32> =
        Array::try_from(bpf.map_mut("PIDS").unwrap())?;

    traced_pids.set(0, pid, 0)?;

    info!("Tracing PID {}", pid);

    Ok(bpf)
}
