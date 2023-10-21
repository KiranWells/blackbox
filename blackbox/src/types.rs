use std::ffi::OsString;

#[derive(Debug, Clone)]
pub struct OpenData {
    // This may be different binary layout from the String type
    pub filename: Option<OsString>,
    /// The flags for the open call. See man open(2) for details
    pub flags: i32,
    /// A file descriptor or the error return value
    pub file_descriptor: Option<Result<u32, i32>>,
}

#[derive(Debug, Clone)]
pub struct ReadData {
    pub file_descriptor: i32,
    /// The number of bytes the user requested to be read
    pub count: usize,
    /// None in the enter event. If None in exit, data could not be read
    pub data_read: Option<Vec<u8>>,
    /// The number of bytes read, or the error value.
    /// Zero indicates EOF
    pub bytes_read: Option<Result<usize, isize>>,
}

#[derive(Debug, Clone)]
pub struct WriteData {
    pub file_descriptor: i32,
    /// The number of bytes the user requested to be written
    pub count: usize,
    /// None in the exit event to save data transfer. If None in enter, data could not be read
    pub data_written: Option<Vec<u8>>,
    /// The number of bytes written, or the error value.
    pub bytes_written: Option<Result<usize, isize>>,
}

#[derive(Debug, Clone)]
pub struct CloseData {
    pub file_descriptor: i32,
    /// Success or the returned error
    pub return_val: Option<Result<(), i32>>,
}

#[derive(Debug, Clone)]
pub struct SocketData {
    /// See socket(2) for possible values
    pub domain: i32,
    /// See socket(2) for possible values
    pub r#type: i32,
    pub protocol: i32,
    /// A file descriptor or the error return value
    pub file_descriptor: Option<Result<u32, i32>>,
}

#[derive(Debug, Clone)]
pub struct ShutdownData {
    pub file_descriptor: i32,
    /// See shutdown(2) for possible values
    pub how: i32,
    /// Success or the returned error
    pub return_val: Option<Result<(), i32>>,
}

#[derive(Debug, Clone)]
pub struct ForkData {
    /// 0 for the child thread, the child PID for the parent, or the error returned
    pub pid: Option<Result<u32, i32>>,
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
    /// None on sys_enter
    pub return_val: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum EventType {
    Open(OpenData),
    Read(ReadData),
    Write(WriteData),
    Close(CloseData),
    Socket(SocketData),
    Shutdown(ShutdownData),
    Fork(ForkData),
    Exit(ExitData),
    Unhandled(UnhandledSyscallData),
}

#[derive(Debug, Clone, Copy)]
pub enum Event {
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
    pub event: Event,
    /// the value returned by bpf_ktime_get_ns: nanoseconds running since boot
    pub monotonic_timestamp: u64,
    pub event_type: EventType,
}
