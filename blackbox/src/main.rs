mod processing;
mod tracing;
mod types;

use aya::maps::Array;
use aya::programs::RawTracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use color_eyre::eyre::Result;
use log::{debug, info, warn};
use tokio::signal;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// PID of the program to trace
    #[arg(short, long)]
    pid: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    color_eyre::install()?;

    let args = Args::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/blackbox"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/blackbox"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut RawTracePoint = bpf.program_mut("handle_sys_enter").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;
    let program: &mut RawTracePoint = bpf.program_mut("handle_sys_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_exit")?;

    // populate PID filter buffer
    let mut traced_pids: aya::maps::array::Array<_, u32> =
        Array::try_from(bpf.map_mut("PIDS").unwrap())?;

    traced_pids.set(0, args.pid, 0)?;

    // create message queue
    let (tx, rx) = tokio::sync::mpsc::channel(100);

    // the tracing has started
    let tracing_job = tokio::spawn(tracing::start_tracing(bpf, tx));
    let processing_job = tokio::spawn(processing::start_processing(rx));

    // run both jobs in parallel
    let _ = tokio::try_join!(tracing_job, processing_job)?;

    // display info to UI
    // TODO

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
