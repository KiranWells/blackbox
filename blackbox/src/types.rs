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

// ============================== processing types ==============================

/// The access type for a file or directory; whether it was read, written to, or executed.
/// Similar to the Unix file permissions, but for a specific file.
#[derive(Debug, Clone, Copy, Default)]
pub struct AccessType {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

//  TODO(ui): add a warning in the UI that shows to the user if there is something bad
/// A process's overall file behavior in relation to various
/// important system path categories.
#[derive(Debug, Clone, Default)]
pub struct FileBehavior {
    /// The behavior of the process with respect to stdin, stdout, and stderr.
    pub stdio: AccessType,
    /// The behavior of the process with respect to the current directory.
    /// File names matching this include:
    /// - ./tempfile.txt
    /// - ../tempfile.txt
    pub current_dir: AccessType,
    /// The behavior of the process with respect to the home directory.
    /// File names matching this include:
    /// - ~/.bash_history
    /// - /home/<USER>/
    pub home_dir: AccessType,
    /// The behavior of the process with respect to the system.
    /// File names matching this include:
    /// - /opt/...
    /// - /bin/..
    pub system: AccessType,
    /// The behavior of the process with respect to the runtime.
    /// File names matching this include:
    /// - /proc/
    /// - /dev/nvme0
    pub runtime: AccessType,
}

/// A summary of the file accesses: information as to the amount of accesses, bytes written/read, as well directories and overall behavior
#[derive(Debug, Clone)]
pub struct FileSummary {
    /// number of accesses
    pub access_count: u64,
    /// number of bytes written
    pub bytes_written: u64,
    /// number of bytes read
    pub bytes_read: u64,
    /// the directories accessed by the process
    pub directories: Vec<OsString>,
    /// the overall behavior of the process with respect to major system directory types
    pub behavior: FileBehavior,
}

/// The domain of the connection when created from a socket.
/// Other includes unix sockets, netlink, and raw sockets.
#[derive(Debug, Clone, Copy)]
pub enum ConnectionDomain {
    IPv4,
    IPv6,
    Other,
}

#[allow(clippy::upper_case_acronyms)]
/// The protocol of the connection when created from a socket.
#[derive(Debug, Clone, Copy)]
pub enum ConnectionProtocol {
    // TODO(processing): ICMP?
    TCP,
    UDP,
    Other,
}

///General summary of the connection, including the start and endtime for each connection, as well the domain and protocol
#[derive(Debug, Clone)]
pub struct Connection {
    /// the monotonic timestamp when the processs first began
    pub start_time: u64,
    /// the
    pub end_time: u64,
    pub domain: ConnectionDomain,
    pub protocol: ConnectionProtocol,
}

/// A summary of the process's other pawned processes
#[derive(Debug, Clone)]
pub struct ProcessSummary {
    /// the programs executed by the process
    pub programs: Vec<OsString>,
    /// the number of other processes spawned by the process, including forks
    pub processes_created: u32,
    /// the most common spawn type of the process
    pub most_common_spawn_type: SpawnType,
}

/// A summary of the network accesses: information as to the number of
/// connections, domains, and protocols used by the process
#[derive(Debug, Clone)]
pub struct NetworkSummary {
    /// number of connections created by the process
    pub connection_count: u64,
    /// The domains accessed by the process
    pub domains: Vec<ConnectionDomain>,
    /// The protocols used by the process
    pub protocols: Vec<ConnectionProtocol>,
}

/// The type of spawn: fork or exec
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnType {
    Fork,
    Exec,
}

/// An event indicating a new process being spawned
#[derive(Clone, Debug)]
pub struct SpawnEvent {
    /// Whether the process was forked or exec'd
    pub spawn_type: SpawnType,
    /// The monotonic timestamp when the processs first began
    pub spawn_time: u64,
    /// the process ID of the spawned process
    pub process_id: u32,
    /// the parent process ID of the spawned process
    pub parent_id: u32,
    /// the command/filename of the spawned process
    pub command: Option<OsString>,
    // TODO(tracing): add arguments and environment
}

/// The total sum of the data collected from the tracing and processing stages
#[derive(Debug, Clone)]
pub struct ProcessingData {
    pub file_summary: FileSummary,
    pub file_events: Vec<FileAccess>,
    pub network_summary: NetworkSummary,
    pub network_events: Vec<Connection>,
    pub process_summary: ProcessSummary,
    pub process_events: Vec<SpawnEvent>,
    pub alerts: Vec<Alert>,
    /// The system call IDs that were not handled by the tracing stage
    pub unhandled_ids: Vec<u64>,
}

/// An alert indicating a potential security issue, such as writing to root directory.
#[derive(Debug, Clone)]
pub struct Alert {
    /// The severity of the alert; lower is more severe
    pub severity: u8,
    /// A short message describing the alert
    pub message: String,
}

/// A file access event that includes all of the relevant data about the file interaction
#[derive(Debug, Clone)]
pub struct FileAccess {
    /// The name of the file accessed
    pub file_name: Option<OsString>,
    /// The file descriptor of the file accessed
    pub file_descriptor: i32,
    /// The number of bytes read or written
    pub data_length: usize,
    /// The data read from the file descriptor
    pub read_data: Vec<u8>,
    /// The data written to the file descriptor
    pub write_data: Vec<u8>,
    /// The monotonic timestamp when the process first began
    pub start_time: u64,
    /// The monotonic timestamp when the process completed
    pub end_time: u64,
    /// The number of errors that occured during the file access
    pub error_count: i32,
    /// The access type of the file access
    pub access_type: AccessType,
}

impl Default for ProcessingData {
    fn default() -> Self {
        ProcessingData {
            file_summary: FileSummary {
                access_count: 0,
                bytes_written: 0,
                bytes_read: 0,
                directories: vec![],
                behavior: FileBehavior::default(),
            },
            file_events: vec![],
            network_summary: NetworkSummary {
                connection_count: 0,
                domains: vec![],
                protocols: vec![],
            },
            network_events: vec![],
            process_summary: ProcessSummary {
                programs: vec![],
                processes_created: 0,
                most_common_spawn_type: SpawnType::Fork,
            },
            process_events: vec![],
            alerts: vec![],
            unhandled_ids: vec![],
        }
    }
}

impl AccessType {
    pub fn update(&mut self, other: &Self) {
        self.read |= other.read;
        self.write |= other.write;
        self.execute |= other.execute;
    }
}

impl ConnectionDomain {
    pub fn text(self) -> String {
        format!("{:?}", self)
    }

    pub fn tooltip(self) -> String {
        match self {
            ConnectionDomain::IPv4 => String::from("IP version 4"),
            ConnectionDomain::IPv6 => String::from("IP version 6"),
            ConnectionDomain::Other => {
                String::from("Another domain, such as raw sockets or unix domains")
            }
        }
    }
}

impl ConnectionProtocol {
    pub fn text(self) -> String {
        format!("{:?}", self)
    }

    pub fn tooltip(self) -> String {
        match self {
            ConnectionProtocol::TCP => String::from("Transmission Control Protocol"),
            ConnectionProtocol::UDP => String::from("User Datagram Protocol"),
            ConnectionProtocol::Other => String::from("Another protocol such as raw sockets"),
        }
    }
}

impl SpawnType {
    pub fn text(self) -> String {
        format!("{:?}", self)
    }

    pub fn tooltip(self) -> String {
        match self {
            SpawnType::Fork => String::from("This process was spawned by forking"),
            SpawnType::Exec => {
                String::from("This process was spawned by executing another command")
            }
        }
    }
}

impl AccessType {
    pub fn update(&mut self, other: &Self) {
        self.read |= other.read;
        self.write |= other.write;
        self.execute |= other.execute;
    }
}
