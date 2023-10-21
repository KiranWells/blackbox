use std::collections::HashMap;

use std::mem::size_of;
use std::sync::Arc;

use aya::maps::{Array, AsyncPerfEventArray};
use aya::programs::RawTracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use blackbox_common::{EventBuffer, EventID, GetEventId, SyscallEvent};
use bytes::BytesMut;
use color_eyre::eyre::Result;
use color_eyre::Report;
use log::{debug, info, warn};
use tokio::sync::Mutex;

use crate::types::TraceEvent;

pub async fn start_tracing(pid: u32, tx: tokio::sync::mpsc::Sender<TraceEvent>) -> Result<()> {
    let event_staging = Arc::new(Mutex::new(HashMap::<EventID, SyscallEvent>::new()));
    let buffer_staging = Arc::new(Mutex::new(HashMap::<EventID, EventBuffer>::new()));
    let mut bpf = init_bpf(pid)?;
    let mut event_output = AsyncPerfEventArray::try_from(bpf.take_map("EVENT_OUTPUT").unwrap())?;
    let mut buffer_output = AsyncPerfEventArray::try_from(bpf.take_map("BUFFER_OUTPUT").unwrap())?;
    let mut handles = Vec::new();
    for cpu_id in online_cpus()? {
        debug!("Creating listener: {}/{:?}", cpu_id, online_cpus());
        // open a separate perf buffer for each cpu
        let mut buf = event_output.open(cpu_id, Some(128))?;
        debug!("got buffer");
        let movable_buffer_staging = buffer_staging.clone();
        let movable_event_staging = event_staging.clone();
        let movable_tx = tx.clone();

        debug!("Making handles");
        handles.push(tokio::task::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(size_of::<SyscallEvent>()))
                .collect::<Vec<_>>();

            loop {
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
                            Some(expr) => send_event(payload, Some(expr), &movable_tx),
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
                        send_event(payload, None, &movable_tx);
                    }
                }
            }

            // This is necessary to tell the compiler what type this block returns
            #[allow(unreachable_code)]
            Ok::<(), Report>(())
        }));

        let mut buf = buffer_output.open(cpu_id, Some(128))?;
        let movable_buffer_staging = buffer_staging.clone();
        let movable_event_staging = event_staging.clone();
        let movable_tx = tx.clone();
        handles.push(tokio::task::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(size_of::<EventBuffer>()))
                .collect::<Vec<_>>();

            loop {
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
                        Some(expr) => send_event(expr, Some(payload), &movable_tx),
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
            }

            // This is necessary to tell the compiler what type this block returns
            #[allow(unreachable_code)]
            Ok::<(), Report>(())
        }));
        debug!("Finished creating listener {cpu_id}");
    }

    // TODO: handle the fact that these will never rejoin if working correctly
    for handle in handles {
        handle.await??;
    }

    Ok(())
}

fn send_event(
    event: SyscallEvent,
    _buffer: Option<EventBuffer>,
    _tx: &tokio::sync::mpsc::Sender<TraceEvent>,
) {
    dbg!(event);
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
