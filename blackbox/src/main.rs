mod processing;
mod tracing;
mod types;

use std::{fs::OpenOptions, path::PathBuf, process::Command};

use clap::Parser;
use color_eyre::eyre::Result;
use log::info;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// command of the program to run and trace
    #[arg(short, long)]
    command: String,
    /// the file to read the process's stdin from
    #[arg(short='i', long, default_value=None)]
    stdin_file: Option<PathBuf>,
    /// the file to read the process's stdin from
    #[arg(short = 'o', long, default_value = "stdout.dat")]
    stdout_file: PathBuf,
    /// the file to read the process's stdin from
    #[arg(short = 'e', long, default_value = "stderr.dat")]
    stderr_file: PathBuf,
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
    let stdout = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(args.stdout_file.as_path())?;
    let stderr = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(args.stdout_file.as_path())?;
    let mut command = Command::new("./runner.sh");

    command
        .arg("-c")
        .arg(args.command)
        .stdout(stdout)
        .stderr(stderr);
    if let Some(stdin) = args.stdin_file.clone() {
        let stdin = OpenOptions::new().read(true).open(stdin.as_path())?;
        command.stdin(stdin);
    }
    let child = command.spawn()?;
    // create message queue
    let (tx, rx) = tokio::sync::mpsc::channel(100);

    // spawn the processes in parallel
    let _tracing_job = tokio::spawn(tracing::start_tracing(child.id(), tx));
    let _processing_job = tokio::spawn(processing::start_processing(rx));

    // display info to UI
    // TODO
    info!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    info!("Exiting...");

    // wait for both processes; we only care aboud errors
    // let _ = tokio::try_join!(tracing_job, processing_job)?;
    Ok(())
}
