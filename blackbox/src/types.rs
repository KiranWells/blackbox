use std::ffi::OsString;

#[derive(Debug, Clone)]
pub struct OpenData {
    /// The file name passed to open. This is Some unless there are errors reading the memory
    // This is an OsString because it may be different binary layout from the String type
    pub filename: Option<OsString>,
    /// The flags for the open call. See man open(2) for details
    pub flags: i32,
    /// A file descriptor or the error return value
    pub file_descriptor: Result<i32, i32>,
    /// the directory file_descriptor passed to openat. None if the system call was not openat.
    pub directory_fd: Option<i32>,
    /// The permissions mode the file is opened in (e.x. 0644)
    pub mode: u32,
}

#[derive(Debug, Clone)]
pub struct ReadData {
    pub file_descriptor: i32,
    /// The number of bytes the user requested to be read
    pub count: usize,
    /// The data read from the file descriptor. None indicates an error reading the memory
    pub data_read: Option<Vec<u8>>,
    /// The number of bytes read, or the error value.
    /// Zero indicates EOF
    pub bytes_read: Result<usize, isize>,
}

#[derive(Debug, Clone)]
pub struct WriteData {
    pub file_descriptor: i32,
    /// The number of bytes the user requested to be written
    pub count: usize,
    /// The data written to the file descriptor. None indicates an error reading the memory
    pub data_written: Option<Vec<u8>>,
    /// The number of bytes written, or the error value.
    pub bytes_written: Result<usize, isize>,
}

#[derive(Debug, Clone)]
pub struct CloseData {
    pub file_descriptor: i32,
    /// Success or the returned error
    pub return_val: Result<(), i32>,
}

#[derive(Debug, Clone)]
pub struct SocketData {
    /// See socket(2) for possible values
    pub domain: i32,
    /// See socket(2) for possible values
    pub r#type: i32,
    pub protocol: i32,
    /// A file descriptor or the error return value
    pub file_descriptor: Result<i32, i32>,
}

#[derive(Debug, Clone)]
pub struct ShutdownData {
    pub file_descriptor: i32,
    /// See shutdown(2) for possible values
    pub how: i32,
    /// Success or the returned error
    pub return_val: Result<(), i32>,
}

#[derive(Debug, Clone)]
pub struct ForkData {
    /// 0 for the child thread, the child PID for the parent, or the error returned
    pub pid: Result<u32, i32>,
}

#[derive(Debug, Clone)]
pub struct ExecveData {
    /// the file of the process to execute
    pub filename: Option<OsString>,
    /// the arguments passed to the process. This pointer is not read
    pub args: u64,
    /// the environment variables for the process. This pointer is not read
    pub environment: u64,
    /// the file descriptor to use instead of pwd. None if this call is not execveat
    pub directory_fd: Option<i32>,
    /// flags passed to execveat. None if this call is not execveat
    pub flags: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct ExitData {
    /// The status value returned from the process to the operating sytem.
    /// The value status & 0xFF is returned to the parent process.
    pub status: i32,
}

#[derive(Debug, Clone)]
pub struct UnhandledSyscallData {
    pub syscall_id: u64,
    pub arg_0: u64,
    pub arg_1: u64,
    pub arg_2: u64,
    pub arg_3: u64,
    pub arg_4: u64,
    pub arg_5: u64,
    pub return_val: u64,
}

#[derive(Debug, Clone)]
pub enum SyscallData {
    Open(OpenData),
    Read(ReadData),
    Write(WriteData),
    Close(CloseData),
    Socket(SocketData),
    Shutdown(ShutdownData),
    Fork(ForkData),
    Execve(ExecveData),
    Exit(ExitData),
    Unhandled(UnhandledSyscallData),
}

#[derive(Debug, Clone, Copy)]
pub enum TracepointType {
    Enter,
    Exit,
}

#[derive(Debug, Clone)]
pub struct TraceEvent {
    /// The process ID, also the thread global ID in kernel space
    pub pid: u32,
    /// The thread ID, also the process ID in kernel space
    pub thread_id: u32,
    /// Whether the event is an enter or exit
    pub tracepoint: TracepointType,
    /// the value returned by bpf_ktime_get_ns: nanoseconds running since boot for the sys_enter
    /// event
    pub monotonic_enter_timestamp: u64,
    /// the value returned by bpf_ktime_get_ns: nanoseconds running since boot for the sys_exit
    /// event
    pub monotonic_exit_timestamp: u64,
    pub data: SyscallData,
}
