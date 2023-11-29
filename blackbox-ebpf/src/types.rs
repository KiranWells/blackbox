#![allow(dead_code)]
use aya_bpf::{
    bindings::pt_regs,
    cty::{c_uint, c_ulong},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read, bpf_probe_read_kernel},
    programs::RawTracePointContext,
    BpfContext,
};
use aya_log_ebpf::error;
use blackbox_common::SyscallEvent;

/// A general error enum for error handling
#[derive(Clone, Copy)]
pub enum EbpfError {
    /// Should be used when reading from memory. Contains the error returned from the read
    /// operation
    Read(i64),
    /// Should be used when extracting arguments from registers
    Arg(usize),
    /// Should only be used where it guarantees a logic error occurred, such as where you would
    /// normally panic
    Logic,
    /// Used when accessing a buffer map
    Map,
}

impl EbpfError {
    pub fn log(self, ctx: &RawTracePointContext) {
        match self {
            EbpfError::Read(errno) => {
                error!(ctx, "Failed to read address in eBPF handler: {}", errno)
            }
            EbpfError::Arg(v) => {
                error!(ctx, "Failed to extract arg number {}", v);
            }
            EbpfError::Logic => {
                error!(ctx, "There was a logic error in the code");
            }
            EbpfError::Map => {
                error!(ctx, "Failed to get or set a value in a map");
            }
        }
    }
}

/// Parsed arguments passed to the sys_enter raw tracepoint
pub struct SysEnterCtx {
    pub regs: *mut pt_regs,
    pub id: c_ulong,
}

impl TryFrom<&RawTracePointContext> for SysEnterCtx {
    type Error = EbpfError;
    fn try_from(ctx: &RawTracePointContext) -> Result<Self, Self::Error> {
        let pt_regs_ptr = unsafe {
            bpf_probe_read_kernel(ctx.as_ptr() as *const *mut pt_regs).map_err(EbpfError::Read)
        }?;

        let address = unsafe { (ctx.as_ptr() as *const c_ulong).offset(1) };
        let id = unsafe { bpf_probe_read_kernel(address).map_err(EbpfError::Read) }?;
        Ok(Self {
            regs: pt_regs_ptr,
            id,
        })
    }
}

impl SysEnterCtx {
    /// gets a function argument from the registers with an index `n`
    pub fn arg(&self, n: usize) -> Result<c_ulong, EbpfError> {
        let ctx = unsafe { &*self.regs };
        match n {
            0 => unsafe { bpf_probe_read(&ctx.rdi).map_err(|_| EbpfError::Arg(n)) },
            1 => unsafe { bpf_probe_read(&ctx.rsi).map_err(|_| EbpfError::Arg(n)) },
            2 => unsafe { bpf_probe_read(&ctx.rdx).map_err(|_| EbpfError::Arg(n)) },
            3 => unsafe { bpf_probe_read(&ctx.rcx).map_err(|_| EbpfError::Arg(n)) },
            4 => unsafe { bpf_probe_read(&ctx.r8).map_err(|_| EbpfError::Arg(n)) },
            5 => unsafe { bpf_probe_read(&ctx.r9).map_err(|_| EbpfError::Arg(n)) },
            _ => Err(EbpfError::Logic),
        }
    }
}

/// Parsed arguments passed to the sys_exit raw tracepoint
pub struct SysExitCtx {
    pub regs: *mut pt_regs,
    pub id: c_ulong,
    pub ret: c_ulong,
}

impl TryFrom<&RawTracePointContext> for SysExitCtx {
    type Error = EbpfError;
    fn try_from(ctx: &RawTracePointContext) -> Result<Self, Self::Error> {
        let pt_regs_ptr = unsafe {
            bpf_probe_read_kernel(ctx.as_ptr() as *const *mut pt_regs).map_err(EbpfError::Read)
        }?;

        let id = unsafe { bpf_probe_read(&(*pt_regs_ptr).orig_rax).map_err(EbpfError::Read)? }
            as c_ulong;

        let address = unsafe { (ctx.as_ptr() as *const c_ulong).offset(1) };
        let ret = unsafe { bpf_probe_read_kernel(address).map_err(EbpfError::Read) }?;
        Ok(Self {
            regs: pt_regs_ptr,
            id,
            ret,
        })
    }
}

impl SysExitCtx {
    /// gets a function argument from the registers with an index `n`
    pub fn arg(&self, n: usize) -> Result<c_ulong, EbpfError> {
        let ctx = unsafe { &*self.regs };
        match n {
            0 => unsafe { bpf_probe_read(&ctx.rdi).map_err(|_| EbpfError::Arg(n)) },
            1 => unsafe { bpf_probe_read(&ctx.rsi).map_err(|_| EbpfError::Arg(n)) },
            2 => unsafe { bpf_probe_read(&ctx.rdx).map_err(|_| EbpfError::Arg(n)) },
            3 => unsafe { bpf_probe_read(&ctx.rcx).map_err(|_| EbpfError::Arg(n)) },
            4 => unsafe { bpf_probe_read(&ctx.r8).map_err(|_| EbpfError::Arg(n)) },
            5 => unsafe { bpf_probe_read(&ctx.r9).map_err(|_| EbpfError::Arg(n)) },
            _ => Err(EbpfError::Logic),
        }
    }

    /// gets a function return value from the arguments
    pub fn ret(&self) -> Result<c_ulong, EbpfError> {
        let ctx = unsafe { &*self.regs };
        unsafe { bpf_probe_read(&ctx.rax).map_err(EbpfError::Read) }
    }
}

/// Arguments for the sys_read and sys_write args
pub struct SysReadArgs {
    pub fd: c_uint,
    pub user_buf: *const u8,
    pub count: usize,
}

impl TryFrom<&SysExitCtx> for SysReadArgs {
    type Error = EbpfError;

    fn try_from(data: &SysExitCtx) -> Result<Self, Self::Error> {
        Ok(Self {
            fd: data.arg(0)? as c_uint,
            user_buf: data.arg(1)? as *const u8,
            count: data.arg(2)? as usize,
        })
    }
}

impl TryFrom<&SysEnterCtx> for SyscallEvent {
    type Error = EbpfError;

    fn try_from(data: &SysEnterCtx) -> Result<Self, Self::Error> {
        let pid_tgid = bpf_get_current_pid_tgid();
        // this is more like the PID in user-space
        let tgid = (pid_tgid >> 32) as u32;
        // this is more like the thread ID in user-space
        let pid = (pid_tgid & 0xFFFF_FFFF) as u32;
        Ok(Self {
            timestamp: unsafe { bpf_ktime_get_ns() },
            pid,
            tgid,
            arg_0: data.arg(0)?,
            arg_1: data.arg(1)?,
            arg_2: data.arg(2)?,
            arg_3: data.arg(3)?,
            arg_4: data.arg(4)?,
            arg_5: data.arg(5)?,
            syscall_id: data.id,
            // This is handled in each individual handler
            data_size: None,
            // this is an enter event, there is no return val
            return_val: None,
        })
    }
}
impl TryFrom<&SysExitCtx> for SyscallEvent {
    type Error = EbpfError;

    fn try_from(data: &SysExitCtx) -> Result<Self, Self::Error> {
        let pid_tgid = bpf_get_current_pid_tgid();
        // this is more like the PID in user-space
        let tgid = (pid_tgid >> 32) as u32;
        // this is more like the thread ID in user-space
        let pid = (pid_tgid & 0xFFFF_FFFF) as u32;
        Ok(Self {
            timestamp: unsafe { bpf_ktime_get_ns() },
            pid,
            tgid,
            arg_0: data.arg(0)?,
            arg_1: data.arg(1)?,
            arg_2: data.arg(2)?,
            arg_3: data.arg(3)?,
            arg_4: data.arg(4)?,
            arg_5: data.arg(5)?,
            syscall_id: data.id,
            // This is handled in each individual handler
            data_size: None,
            return_val: Some(data.ret),
        })
    }
}
