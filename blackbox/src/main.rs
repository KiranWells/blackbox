mod processing;
mod tracing;
mod types;
mod ui;

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use clap::Parser;
use color_eyre::eyre::Result;
use log::{debug, warn};
use tokio::sync::{Mutex, Semaphore};
use types::ProcessingData;

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
    /// File to read the process's stdin from [default: blackbox's stdout]
    #[arg(short = 'e', long, default_value = None)]
    stderr_file: Option<PathBuf>,
    /// File to write system call events to in JSON format. If this is set, no UI will be started;
    /// only tracing will occur.
    #[arg(short, long, default_value=None)]
    file_to_write: Option<PathBuf>,
    /// Include the initial execve of the program being traced. This is turned off by default to
    /// make the output more intuitive.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    include_initial_execve: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(Path::new("blackbox.log"))?;
    env_logger::builder()
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .init();
    color_eyre::install()?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = nix::libc::rlimit {
        rlim_cur: nix::libc::RLIM_INFINITY,
        rlim_max: nix::libc::RLIM_INFINITY,
    };
    let ret = unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut command = Command::new("/bin/su");
    command
        .arg(args.user)
        .arg("--preserve-environment")
        .arg("--shell")
        .arg("/bin/bash")
        .arg("--command")
        .arg(format!(
            "cd {}; kill -STOP $$; exec {}",
            std::env::current_dir()?.to_string_lossy(),
            args.command
        ));
    if let Some(stdout) = args.stdout_file.clone() {
        let stdout = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(stdout.as_path())?;
        command.stdin(stdout);
    }
    if let Some(stderr) = args.stderr_file.clone() {
        let stderr = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(stderr.as_path())?;
        command.stdin(stderr);
    }
    if let Some(stdin) = args.stdin_file.clone() {
        let stdin = OpenOptions::new().read(true).open(stdin.as_path())?;
        command.stdin(stdin);
    }
    let mut child = command.spawn()?;

    let wait_result = unsafe {
        nix::libc::waitpid(
            child.id() as i32,
            std::ptr::null_mut(),
            nix::libc::WUNTRACED,
        )
    };

    if wait_result != child.id() as i32 {
        warn!("WaitPID did not exit correctly!")
    }

    // we are really interested in the child of `su`, so we need to get its PID
    let children_file = format!("/proc/{0}/task/{0}/children", child.id());
    let children = std::fs::read_to_string(children_file).unwrap();
    let child_pid = children
        .strip_suffix(' ')
        .unwrap()
        .parse::<u32>()
        .expect("expected a single valid PID");

    // create message queue
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    // let (progress_tx, progress_rx) = tokio::sync::mpsc::channel(10);
    let done_wait = Arc::new(Semaphore::new(0));
    let shared_state: Arc<Mutex<Option<ProcessingData>>> = Arc::new(Mutex::new(None));

    // spawn the processes in parallel
    // the child of su will be one pid greater, unless there is an extreme race condition
    let tracing_job = tokio::spawn(tracing::start_tracing(
        child_pid,
        tx,
        args.include_initial_execve,
    ));

    if args.file_to_write.is_none() {
        let processing_job = tokio::spawn(processing::start_processing(
            rx,
            Arc::clone(&done_wait),
            Arc::clone(&shared_state),
        ));

        // display info to UI
        ui::run(done_wait, shared_state)?;
        child.kill()?;

        // wait for both processes; we only care about errors
        let _ = tokio::try_join!(tracing_job, processing_job)?;
        Ok(())
    } else {
        let consumer = tokio::spawn(async move {
            let mut output_file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(args.file_to_write.unwrap())?;
            while let Some(i) = rx.recv().await {
                write!(output_file, "{}\n", serde_json::to_string(&i)?)?;
            }
            Ok::<(), color_eyre::Report>(())
        });
        let _ = tokio::try_join!(tracing_job, consumer)?;
        Ok(())
    }
}
