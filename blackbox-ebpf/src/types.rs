use aya_bpf::{
    bindings::pt_regs,
    cty::c_ulong,
    helpers::{bpf_probe_read, bpf_probe_read_kernel},
    programs::RawTracePointContext,
    BpfContext,
};
use aya_log_ebpf::error;

#[derive(Clone, Copy)]
pub enum EbpfError {
    Read,
    Arg(usize),
    Logic,
    Map,
}

impl EbpfError {
    pub fn log(self, ctx: &RawTracePointContext) {
        match self {
            EbpfError::Read => {
                error!(ctx, "Failed to read address in eBPF handler");
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

pub struct SysEnterCtx {
    pub regs: *mut pt_regs,
    pub id: c_ulong,
}

impl TryFrom<&RawTracePointContext> for SysEnterCtx {
    type Error = EbpfError;
    fn try_from(ctx: &RawTracePointContext) -> Result<Self, Self::Error> {
        let pt_regs_ptr = unsafe {
            bpf_probe_read_kernel(ctx.as_ptr() as *const *mut pt_regs).map_err(|_| EbpfError::Read)
        }?;

        let address = unsafe { (ctx.as_ptr() as *const c_ulong).offset(1) };
        let id = unsafe { bpf_probe_read_kernel(address).map_err(|_| EbpfError::Read) }?;
        Ok(Self {
            regs: pt_regs_ptr,
            id,
        })
    }
}

impl SysEnterCtx {
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

pub struct SysExitCtx {
    pub regs: *mut pt_regs,
    pub id: c_ulong,
    pub ret: c_ulong,
}

impl TryFrom<&RawTracePointContext> for SysExitCtx {
    type Error = EbpfError;
    fn try_from(ctx: &RawTracePointContext) -> Result<Self, Self::Error> {
        let pt_regs_ptr = unsafe {
            bpf_probe_read_kernel(ctx.as_ptr() as *const *mut pt_regs).map_err(|_| EbpfError::Read)
        }?;

        let id = unsafe { bpf_probe_read(&(&*pt_regs_ptr).orig_rax).map_err(|_| EbpfError::Read)? }
            as c_ulong;

        let address = unsafe { (ctx.as_ptr() as *const c_ulong).offset(1) };
        let ret = unsafe { bpf_probe_read_kernel(address).map_err(|_| EbpfError::Read) }?;
        Ok(Self {
            regs: pt_regs_ptr,
            id,
            ret,
        })
    }
}

impl SysExitCtx {
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
    pub fn ret(&self) -> Result<c_ulong, EbpfError> {
        let ctx = unsafe { &*self.regs };
        unsafe { bpf_probe_read(&ctx.rax).map_err(|_| EbpfError::Read) }
    }
}

pub struct SysEnterArgs {
    pub args: [u64; 6],
    pub syscall_id: u64,
}

impl TryFrom<&RawTracePointContext> for SysEnterArgs {
    type Error = EbpfError;
    fn try_from(ctx: &RawTracePointContext) -> Result<Self, Self::Error> {
        let pt_regs = unsafe {
            &*bpf_probe_read_kernel(ctx.as_ptr() as *const *mut pt_regs)
                .map_err(|_| EbpfError::Read)?
        };

        let address = unsafe { (ctx.as_ptr() as *const c_ulong).offset(1) };
        let id = unsafe { bpf_probe_read_kernel(address).map_err(|_| EbpfError::Read) }?;
        Ok(Self {
            args: [
                unsafe { bpf_probe_read(&pt_regs.rdi) }.map_err(|_| EbpfError::Arg(0))?,
                unsafe { bpf_probe_read(&pt_regs.rsi) }.map_err(|_| EbpfError::Arg(1))?,
                unsafe { bpf_probe_read(&pt_regs.rdx) }.map_err(|_| EbpfError::Arg(2))?,
                unsafe { bpf_probe_read(&pt_regs.rcx) }.map_err(|_| EbpfError::Arg(3))?,
                unsafe { bpf_probe_read(&pt_regs.r8) }.map_err(|_| EbpfError::Arg(4))?,
                unsafe { bpf_probe_read(&pt_regs.r9) }.map_err(|_| EbpfError::Arg(5))?,
            ],
            syscall_id: id,
        })
    }
}
