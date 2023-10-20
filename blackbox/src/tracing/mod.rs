use std::ffi::OsString;

use aya::maps::Array;
use aya::programs::RawTracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use color_eyre::eyre::Result;
use log::warn;

use crate::types::{Event, TraceEvent};

pub async fn start_tracing(pid: u32, tx: tokio::sync::mpsc::Sender<TraceEvent>) -> Result<()> {
    // collect trace events
    // send fake data here
    for i in 0..10 {
        let t = TraceEvent {
            pid: 0,
            thread_id: 0,
            monotonic_timestamp: i,
            event: Event::Enter,
            event_type: crate::types::EventType::Open(crate::types::OpenData {
                filename: OsString::new(),
                file_descriptor: None,
                flags: 0,
            }),
        };

        tx.send(t).await?;
    }
    Ok(())
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

    #[cfg(debug_assertions)]
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

    Ok(bpf)
}
