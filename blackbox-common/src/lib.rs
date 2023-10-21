#![no_std]

use core::num::NonZeroUsize;

/// The maximum amount of data that can be read into the buffer to pass to userspace
pub const BUFFER_SIZE: usize = 1024;

/// A syscall event from sys_enter or sys_exit. It contains all
/// of the relevant data from the event for reconstructing the call,
/// as well as the amount of data collected from the event.
///
/// If an event does not have data associated, `data_size` will be
/// `None`. Otherwise, `data_size` will be the size of the data read,
/// and an associated [`EventBuffer`] object will be sent to userspace.
///
/// The [`EventID`] struct is used to connect [`EventBuffer`] object
/// with this event.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SyscallEvent {
    /// a timestamp from the montonic system clock
    pub timestamp: u64,
    /// the thread global ID, or PID
    pub tgid: u32,
    /// the process id (user-space thread id)
    pub pid: u32,
    /// The value from rax
    pub syscall_id: u64,
    // argument values from rdi, etc.
    pub arg_0: u64,
    pub arg_1: u64,
    pub arg_2: u64,
    pub arg_3: u64,
    pub arg_4: u64,
    pub arg_5: u64,
    /// None on sys_enter
    pub return_val: Option<u64>,
    /// None if there is no buffer data available
    pub data_size: Option<NonZeroUsize>,
}

/// A static-sized buffer that contains data read in from memory
/// that is associated with a [`SyscallEvent`]. The [`EventID`]
/// struct is used to correlate the two.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct EventBuffer {
    /// a timestamp from the montonic system clock
    pub timestamp: u64,
    /// the thread global ID, or PID
    pub tgid: u32,
    /// the process id (user-space thread id)
    pub pid: u32,
    /// a constant-size buffer for data to be read from
    pub data_buffer: [u8; BUFFER_SIZE],
}

/// A collection of data sufficient for determining a unique
/// event. This can be used to link an [`EventBuffer`] and a
/// [`SyscallEvent`] together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct EventID {
    /// a timestamp from the montonic system clock
    pub timestamp: u64,
    /// the thread global ID, or PID
    pub tgid: u32,
    /// the process id (user-space thread id)
    pub pid: u32,
}

impl SyscallEvent {
    /// Returns whether this event is an enter or exit event
    pub fn is_enter(&self) -> bool {
        self.return_val.is_none()
    }

    pub fn has_data(&self) -> bool {
        self.data_size.is_some()
    }
}

/// A utility trait for getting an [`EventID`] from a struct.
pub trait GetEventId {
    fn get_event_id(&self) -> EventID;
}

impl GetEventId for EventBuffer {
    fn get_event_id(&self) -> EventID {
        EventID {
            timestamp: self.timestamp,
            tgid: self.tgid,
            pid: self.pid,
        }
    }
}

impl GetEventId for SyscallEvent {
    fn get_event_id(&self) -> EventID {
        EventID {
            timestamp: self.timestamp,
            tgid: self.tgid,
            pid: self.pid,
        }
    }
}

#[repr(u16)]
pub enum SyscallID {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Socket = 41,
    Shutdown = 48,
    Fork = 57,
    Exit = 60,
    Unhandled,
}

impl<T> From<T> for SyscallID
where
    T: TryInto<u16>,
{
    fn from(value: T) -> Self {
        let Ok(num): Result<u16, _> = value.try_into() else {
            return Self::Unhandled;
        };
        match num {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Open,
            3 => Self::Close,
            41 => Self::Socket,
            48 => Self::Shutdown,
            57 => Self::Fork,
            60 => Self::Exit,
            _ => Self::Unhandled,
        }
    }
}
