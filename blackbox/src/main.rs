mod processing;
mod tracing;
mod types;

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
    // let rlim = libc::rlimit {
    //     rlim_cur: libc::RLIM_INFINITY,
    //     rlim_max: libc::RLIM_INFINITY,
    // };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    // if ret != 0 {
    //     debug!("remove limit on locked memory failed, ret is: {}", ret);
    // }

    // create message queue
    let (tx, rx) = tokio::sync::mpsc::channel(100);

    // spawn the processes in parallel
    let tracing_job = tokio::spawn(tracing::start_tracing(args.pid, tx));
    let processing_job = tokio::spawn(processing::start_processing(rx));

    // display info to UI
    // TODO

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    // wait for both processes; we only care aboud errors
    let _ = tokio::try_join!(tracing_job, processing_job)?;
    Ok(())
}
