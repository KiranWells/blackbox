use std::collections::HashMap;
use std::ffi::OsString;
use std::mem::size_of;
use std::os::unix::prelude::OsStringExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aya::maps::perf::AsyncPerfEventArrayBuffer;
use aya::maps::{Array, AsyncPerfEventArray, MapData};
use aya::programs::RawTracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use blackbox_common::{EventBuffer, EventID, GetEventId, SyscallEvent, SyscallID};
use bytes::BytesMut;
use color_eyre::eyre::Result;
use color_eyre::Report;
use futures::stream::FuturesUnordered;
use futures::TryStreamExt;
use log::{debug, error, info, warn};
use nix::sys::signal::Signal;
use tokio::select;
use tokio::sync::mpsc::{self, Sender};

use crate::types::{
    CloseData, ForkData, OpenData, ReadData, SyscallData, TraceEvent, TracepointType, WriteData,
};

#[derive(Debug)]
pub struct SyscallBuilder {
    enter_args: Option<SyscallEvent>,
    data: Option<EventBuffer>,
    exit_args: Option<SyscallEvent>,
}

impl SyscallBuilder {
    fn event_id(event: &SyscallEvent) -> (u64, u64) {
        let ptid = ((event.pid as u64) << 32) & (event.tgid as u64);
        (ptid, event.syscall_id)
    }
    fn new() -> Self {
        Self {
            enter_args: None,
            data: None,
            exit_args: None,
        }
    }
    fn is_finished(&self) -> bool {
        if let (Some(enter), Some(exit)) = (&self.enter_args, &self.exit_args) {
            (!enter.has_data() || self.data.is_some()) && (!exit.has_data() || self.data.is_some())
        } else if let Some(enter) = &self.enter_args {
            SyscallID::from(enter.syscall_id).is_noreturn()
        } else {
            false
        }
    }

    pub fn get_return(&self) -> u64 {
        self.exit_args.as_ref().unwrap().return_val.unwrap()
    }
}

pub async fn tracing_thread<T>(
    tx: Sender<T>,
    mut buf: AsyncPerfEventArrayBuffer<MapData>,
    done: Arc<AtomicBool>,
) -> Result<()>
where
    T: Clone + std::fmt::Debug + Sync + Send + 'static,
{
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
                let ptr = buf.as_ptr() as *const T;
                (*ptr).clone()
            };

            tx.send(payload).await?;
        }
        if events.lost > 0 {
            warn!("Lost {} events!", events.lost);
        }
        if done.load(Ordering::Acquire) {
            break;
        }
    }
    debug!("after loop");
    Ok(())
}

pub async fn start_tracing(pid: u32, tx: tokio::sync::mpsc::Sender<TraceEvent>) -> Result<()> {
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    let (mut bpf, detach_action) = init_bpf(pid)?;
    let mut event_output = AsyncPerfEventArray::try_from(bpf.take_map("EVENT_OUTPUT").unwrap())?;
    let mut buffer_output = AsyncPerfEventArray::try_from(bpf.take_map("BUFFER_OUTPUT").unwrap())?;
    let mut handles = FuturesUnordered::new();
    let done = Arc::new(AtomicBool::new(false));
    let (args_tx, mut args_rx) = mpsc::channel::<SyscallEvent>(256);
    let (buffer_tx, mut buffer_rx) = mpsc::channel::<EventBuffer>(256);
    for cpu_id in online_cpus()? {
        debug!("Creating listener: {}/{}", cpu_id, 23);
        // open a separate perf buffer for each cpu
        let buf = event_output.open(cpu_id, Some(128))?;

        let movable_tx = args_tx.clone();
        let movable_done = done.clone();
        handles.push(tokio::task::spawn(async move {
            tracing_thread(movable_tx, buf, movable_done).await
        }));
        let buf = buffer_output.open(cpu_id, Some(128))?;

        let movable_tx = buffer_tx.clone();
        let movable_done = done.clone();
        handles.push(tokio::task::spawn(async move {
            tracing_thread(movable_tx, buf, movable_done).await
        }));
    }
    handles.push(tokio::task::spawn(async move {
        let mut events = vec![];
        let mut buffers = HashMap::<EventID, EventBuffer>::new();
        let mut start_time = None;
        loop {
            select! {
                Some(args) = args_rx.recv() => {
                    if args.syscall_id == SyscallID::Execve as u64 && start_time.is_none() {
                        start_time = Some(args.timestamp);
                    }
                    if args.syscall_id == SyscallID::Exit as u64 || args.syscall_id == SyscallID::ExitGroup as u64 {
                        break;
                    }
                    events.push(args);
                }
                Some(buffer) = buffer_rx.recv() => {
                    buffers.insert(buffer.get_event_id(), buffer);
                }
                else => break
            };
        }
        let mut map = HashMap::<(u64, u64), SyscallBuilder>::new();
        events.sort_by(|a,b| a.timestamp.cmp(&b.timestamp));
        for event in events {
            let id = SyscallBuilder::event_id(&event);
            let is_finished = {
                let builder = map.entry(id).or_insert(SyscallBuilder::new());
                if event.has_data() {
                    let buffer = buffers.remove(&event.get_event_id());
                    builder.data = buffer;
                }
                if event.is_enter() {
                    builder.enter_args = Some(event);
                } else {
                    builder.exit_args = Some(event);
                }
                builder.is_finished()
            };

            if is_finished {
                let builder = map.remove(&id).unwrap();

                if send_event(builder, &tx, start_time).await? {
                    done.store(true, Ordering::Release);
                }
            }
        }
        info!("Done with collection thread");

        Ok::<(), Report>(())
    }));

    // wait for tracing to initialize
    tokio::time::sleep(Duration::from_millis(300)).await;
    // start the traced process
    unsafe { nix::libc::kill(pid as i32, Signal::SIGCONT as i32) };

    // tokio::spawn(async move {
    //     tokio::signal::ctrl_c().await.unwrap();
    //     unsafe { nix::libc::kill(pid as i32, Signal::SIGINT as i32) };
    // });
    if let Some(result) = handles.try_next().await? {
        info!("detaching!");
        detach_action(&mut bpf)?;
        result?;
    }

    // TODO: handle the fact that these will never rejoin if stuck awaiting events
    // while let Some(result) = handles.try_next().await? {
    //     info!("thread exited!");
    //     result?
    // }

    Ok(())
}

async fn send_event(
    syscall: SyscallBuilder,
    tx: &tokio::sync::mpsc::Sender<TraceEvent>,
    start_time: Option<u64>,
) -> Result<bool> {
    let entry = syscall.enter_args.as_ref().unwrap();
    let exit = syscall.exit_args.as_ref();
    {
        if let Some(timestamp) = start_time {
            if entry.timestamp <= timestamp {
                return Ok(false);
            }
        } else {
            debug!("timestamp is none!");
            return Ok(false);
        }
    }

    if let Some(exit) = exit {
        if entry.timestamp > exit.timestamp {
            if entry.syscall_id == SyscallID::Execve as u64
                || entry.syscall_id == SyscallID::ExecveAt as u64
            {
                info!("execve with timing anomaly");
            } else {
                error!("Received incorrect event: enter after exit!\n{:?}", syscall);
                return Ok(false);
            }
        }
    }

    let mut data = None;
    if let Some(buffer) = &syscall.data {
        if !entry.has_data() && !exit.unwrap().has_data() {
            error!("Recieved data for an event with no data! {:?}", syscall);
        } else {
            let len = if entry.has_data() {
                entry.data_size.unwrap()
            } else {
                exit.unwrap().data_size.unwrap()
            };
            data = Some(buffer.data_buffer[..len.get()].to_owned());
        }
    }

    let event_data = match entry.syscall_id.into() {
        SyscallID::Read => SyscallData::Read(ReadData {
            file_descriptor: entry.arg_0 as i32,
            count: entry.arg_2 as usize,
            data_read: data,
            bytes_read: match syscall.get_return() {
                r if r as isize > 0 => Ok(r as usize),
                r => Err(r as isize),
            },
        }),
        SyscallID::Write => SyscallData::Write(WriteData {
            file_descriptor: entry.arg_0 as i32,
            count: entry.arg_2 as usize,
            data_written: data,
            bytes_written: match syscall.get_return() {
                r if r as isize > 0 => Ok(r as usize),
                r => Err(r as isize),
            },
        }),
        SyscallID::Open => SyscallData::Open(OpenData {
            filename: data.map(OsString::from_vec),
            flags: entry.arg_1 as i32,
            file_descriptor: match syscall.get_return() {
                r if r as i32 > 0 => Ok(r as i32),
                r => Err(r as i32),
            },
            directory_fd: None,
            mode: entry.arg_2 as u32,
        }),
        SyscallID::OpenAt => SyscallData::Open(OpenData {
            filename: data.map(OsString::from_vec),
            flags: entry.arg_2 as i32,
            file_descriptor: match syscall.get_return() {
                r if r as i32 > 0 => Ok(r as i32),
                r => Err(r as i32),
            },
            directory_fd: Some(entry.arg_0 as i32),
            mode: entry.arg_3 as u32,
        }),
        SyscallID::Creat => SyscallData::Open(OpenData {
            filename: data.map(OsString::from_vec),
            // according to man open(2): A call to creat() is equivalent to calling open()
            // with flags equal to O_CREAT|O_WRONLY|O_TRUNC.
            flags: nix::libc::O_CREAT | nix::libc::O_WRONLY | nix::libc::O_TRUNC,
            file_descriptor: match syscall.get_return() {
                r if r as i32 > 0 => Ok(r as i32),
                r => Err(r as i32),
            },
            directory_fd: None,
            mode: entry.arg_1 as u32,
        }),
        SyscallID::Close => SyscallData::Close(CloseData {
            file_descriptor: entry.arg_0 as i32,
            return_val: match syscall.get_return() {
                r if r as i32 > 0 => Ok(()),
                r => Err(r as i32),
            },
        }),
        SyscallID::Socket => SyscallData::Socket(crate::types::SocketData {
            domain: entry.arg_0 as i32,
            r#type: entry.arg_1 as i32,
            protocol: entry.arg_2 as i32,
            file_descriptor: match syscall.get_return() {
                r if r as i32 > 0 => Ok(r as i32),
                r => Err(r as i32),
            },
        }),
        SyscallID::Shutdown => SyscallData::Shutdown(crate::types::ShutdownData {
            file_descriptor: entry.arg_0 as i32,
            how: entry.arg_1 as i32,
            return_val: match syscall.get_return() {
                r if r as i32 > 0 => Ok(()),
                r => Err(r as i32),
            },
        }),
        SyscallID::Fork => SyscallData::Fork(ForkData {
            pid: match syscall.get_return() {
                r if r as i32 > 0 => Ok(r as u32),
                r => Err(r as i32),
            },
        }),
        SyscallID::Execve => SyscallData::Execve(crate::types::ExecveData {
            filename: data.map(OsString::from_vec),
            args: entry.arg_1,
            environment: entry.arg_2,
            directory_fd: None,
            flags: None,
        }),
        SyscallID::ExecveAt => SyscallData::Execve(crate::types::ExecveData {
            filename: data.map(OsString::from_vec),
            args: entry.arg_2,
            environment: entry.arg_3,
            directory_fd: Some(entry.arg_0 as i32),
            flags: Some(entry.arg_5 as i32),
        }),
        SyscallID::Exit => SyscallData::Exit(crate::types::ExitData {
            status: entry.arg_0 as i32,
        }),
        SyscallID::ExitGroup => SyscallData::Exit(crate::types::ExitData {
            status: entry.arg_0 as i32,
        }),
        SyscallID::Unhandled => SyscallData::Unhandled(crate::types::UnhandledSyscallData {
            syscall_id: entry.syscall_id,
            arg_0: entry.arg_0,
            arg_1: entry.arg_1,
            arg_2: entry.arg_2,
            arg_3: entry.arg_3,
            arg_4: entry.arg_4,
            arg_5: entry.arg_5,
            return_val: syscall.get_return(),
        }),
    };
    let is_process_exit = matches!(event_data, SyscallData::Exit(_));

    let event_to_send = TraceEvent {
        pid: entry.tgid,
        thread_id: entry.pid,
        tracepoint: if entry.is_enter() {
            TracepointType::Enter
        } else {
            TracepointType::Exit
        },
        monotonic_enter_timestamp: entry.timestamp,
        // if there is no exit event (e.g. with non-returning functions)
        // then we consider the exection to take no time
        monotonic_exit_timestamp: exit.map(|e| e.timestamp).unwrap_or(entry.timestamp),
        data: event_data,
    };

    tx.send(event_to_send).await?;
    Ok(is_process_exit)
}

type DetachAction = Box<dyn FnOnce(&mut Bpf) -> Result<()> + Send>;

fn init_bpf(pid: u32) -> Result<(Bpf, DetachAction)> {
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
    let enter_handle = program.attach("sys_enter")?;
    let program: &mut RawTracePoint = bpf.program_mut("handle_sys_exit").unwrap().try_into()?;
    program.load()?;
    let exit_handle = program.attach("sys_exit")?;

    // populate PID filter buffer
    let mut traced_pids: aya::maps::array::Array<_, u32> =
        Array::try_from(bpf.map_mut("PIDS").unwrap())?;

    traced_pids.set(0, pid, 0)?;

    info!("Tracing PID {}", pid);

    let use_handles = move |bpf: &mut Bpf| -> Result<()> {
        let program: &mut RawTracePoint =
            bpf.program_mut("handle_sys_enter").unwrap().try_into()?;
        program.detach(enter_handle)?;
        let program: &mut RawTracePoint = bpf.program_mut("handle_sys_exit").unwrap().try_into()?;
        program.detach(exit_handle)?;
        Ok(())
    };

    Ok((bpf, Box::new(use_handles)))
}
