mod processing;
mod tracing;
mod types;

use std::{fs::OpenOptions, path::PathBuf, process::Command};

use clap::Parser;
use color_eyre::eyre::Result;

/// Blackbox: a kernel-level process analyzer. Collects
/// system call data about the traced process similarly to
/// strace, but creates a simple, understandable report of
/// the process's behavior.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Command of the program to run and trace
    #[arg(short, long)]
    command: String,
    /// User to run the process as
    #[arg(short, long)]
    user: String,
    /// File to read the process's stdin from [default: blackbox's stdin]
    #[arg(short='i', long, default_value=None)]
    stdin_file: Option<PathBuf>,
    /// File to read the process's stdin from [default: blackbox's stdout]
    #[arg(short = 'o', long, default_value=None)]
    stdout_file: Option<PathBuf>,
    /// File to read the process's stdin from
    #[arg(short = 'e', long, default_value = "stderr.dat")]
    stderr_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    color_eyre::install()?;

    let args = Args::parse();

    let stderr = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(args.stderr_file.as_path())?;
    let mut command = Command::new("/bin/su");

    command
        .arg(args.user)
        .arg("--shell")
        .arg("/bin/bash")
        .arg("--command")
        .arg(format!("kill -STOP $$; exec {}", args.command))
        .stderr(stderr);
    if let Some(stdout) = args.stdout_file.clone() {
        let stdout = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(stdout.as_path())?;
        command.stdin(stdout);
    }
    if let Some(stdin) = args.stdin_file.clone() {
        let stdin = OpenOptions::new().read(true).open(stdin.as_path())?;
        command.stdin(stdin);
    }
    let child = command.spawn()?;

    // create message queue
    let (tx, rx) = tokio::sync::mpsc::channel(100);

    // spawn the processes in parallel
    // the child of su will be one pid greater, unless there is an extreme race condition
    let tracing_job = tokio::spawn(tracing::start_tracing(child.id() + 1, tx));
    let processing_job = tokio::spawn(processing::start_processing(rx));

    // display info to UI
    // TODO

    // wait for both processes; we only care about errors
    let _ = tokio::try_join!(tracing_job, processing_job)?;
    Ok(())
}
