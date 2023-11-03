use std::ffi::OsString;

use aya::maps::Array;
use aya::programs::RawTracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use color_eyre::eyre::Result;
use log::warn;

use crate::types::TraceEvent;

pub async fn start_tracing(_pid: u32, tx: tokio::sync::mpsc::Sender<TraceEvent>) -> Result<()> {
    // collect trace events
    // send fake data here
    // for i in 0..10 {
    //     let t = TraceEvent {
    //         pid: 0,
    //         thread_id: 0,
    //         monotonic_timestamp: i,
    //         event: Event::Exit,
    //         event_type: crate::types::EventType::Open(crate::types::OpenData {
    //             filename: Some(OsString::new()),
    //             file_descriptor: Some(Ok(i as u32)),
    //             flags: 0,
    //         }),
    //     };

    //     tx.send(t).await?;
    // }
    use crate::types::EventType::*;
    use crate::types::*;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134346991, event_type: Unhandled(UnhandledSyscallData { syscall_id: 59, arg_0: 93915951929680, arg_1: 93915951911040, arg_2: 93915951927488, arg_3: 139633759975931, arg_4: 140735697625136, arg_5: 7, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134686481, event_type: Unhandled(UnhandledSyscallData { syscall_id: 59, arg_0: 0, arg_1: 0, arg_2: 0, arg_3: 0, arg_4: 0, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134706238, event_type: Unhandled(UnhandledSyscallData { syscall_id: 12, arg_0: 0, arg_1: 1320, arg_2: 0, arg_3: 139917457503179, arg_4: 0, arg_5: 140736231673465, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134710085, event_type: Unhandled(UnhandledSyscallData { syscall_id: 12, arg_0: 0, arg_1: 1320, arg_2: 0, arg_3: 139917457503179, arg_4: 0, arg_5: 140736231673465, return_val: Some(94268750663680) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134716177, event_type: Unhandled(UnhandledSyscallData { syscall_id: 158, arg_0: 12289, arg_1: 140736231672720, arg_2: 139917457480656, arg_3: 139917457462941, arg_4: 3, arg_5: 2048, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134718972, event_type: Unhandled(UnhandledSyscallData { syscall_id: 158, arg_0: 12289, arg_1: 140736231672720, arg_2: 139917457480656, arg_3: 139917457462941, arg_4: 3, arg_5: 2048, return_val: Some(18446744073709551594) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134738549, event_type: Unhandled(UnhandledSyscallData { syscall_id: 21, arg_0: 139917457543824, arg_1: 4, arg_2: 0, arg_3: 139917457506411, arg_4: 140736231998208, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134744049, event_type: Unhandled(UnhandledSyscallData { syscall_id: 21, arg_0: 139917457543824, arg_1: 4, arg_2: 0, arg_3: 139917457506411, arg_4: 140736231998208, arg_5: 0, return_val: Some(18446744073709551614) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134760751, event_type: Open(OpenData { filename: None, flags: 524288, file_descriptor: Some(Ok(3)) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134763526, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 3, arg_1: 139917457542319, arg_2: 140736231669184, arg_3: 139917457506510, arg_4: 0, arg_5: 94268742733017, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134767233, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 3, arg_1: 139917457542319, arg_2: 140736231669184, arg_3: 139917457506510, arg_4: 0, arg_5: 94268742733017, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134769888, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 249811, arg_2: 1, arg_3: 139917457507526, arg_4: 3, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134777062, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 249811, arg_2: 1, arg_3: 139917457507526, arg_4: 3, arg_5: 0, return_val: Some(139917457121280) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134779827, event_type: Close(CloseData { file_descriptor: 3, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134782462, event_type: Close(CloseData { file_descriptor: 3, return_val: Some(Ok(())) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134807359, event_type: Open(OpenData { filename: None, flags: 524288, file_descriptor: Some(Ok(3)) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134810395, event_type: Read(ReadData { file_descriptor: 3, count: 832, data_read: None, bytes_read: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134819311, event_type: Unhandled(UnhandledSyscallData { syscall_id: 17, arg_0: 3, arg_1: 140736231668544, arg_2: 784, arg_3: 139917457507182, arg_4: 140736231669511, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134822237, event_type: Unhandled(UnhandledSyscallData { syscall_id: 17, arg_0: 3, arg_1: 140736231668544, arg_2: 784, arg_3: 139917457507182, arg_4: 140736231669511, arg_5: 0, return_val: Some(784) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134824982, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 3, arg_1: 139917457542319, arg_2: 140736231669184, arg_3: 139917457506510, arg_4: 139917457588048, arg_5: 139917457584848, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134828449, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 3, arg_1: 139917457542319, arg_2: 140736231669184, arg_3: 139917457506510, arg_4: 139917457588048, arg_5: 139917457584848, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134831174, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 8192, arg_2: 3, arg_3: 139917457507526, arg_4: 4294967295, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134799684, event_type: Open(OpenData { filename: Some(OsString::from("/usr/lib/libc.so.6")), flags: 524288, file_descriptor: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134813951, event_type: Read(ReadData { file_descriptor: 3, count: 832, data_read: Some(vec![127, 69, 76, 70, 2, 1, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 62, 0, 1, 0, 0, 0, 144, 126, 2, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 224, 172, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 56, 0, 14, 0, 64, 0, 63, 0, 62, 0, 6, 0, 0, 0, 4, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 16, 3, 0, 0, 0, 0, 0, 0, 16, 3, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 94, 26, 0, 0, 0, 0, 0, 0, 94, 26, 0, 0, 0, 0, 0, 0, 94, 26, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 90, 2, 0, 0, 0, 0, 0, 144, 90, 2, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0, 96, 2, 0, 0, 0, 0, 0, 0, 96, 2, 0, 0, 0, 0, 0, 0, 96, 2, 0, 0, 0, 0, 0, 221, 144, 21, 0, 0, 0, 0, 0, 221, 144, 21, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 7, 59, 5, 0, 0, 0, 0, 0, 7, 59, 5, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 160, 60, 29, 0, 0, 0, 0, 0, 160, 76, 29, 0, 0, 0, 0, 0, 160, 76, 29, 0, 0, 0, 0, 0, 40, 74, 0, 0, 0, 0, 0, 0, 208, 206, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 6, 0, 0, 0, 128, 105, 29, 0, 0, 0, 0, 0, 128, 121, 29, 0, 0, 0, 0, 0, 128, 121, 29, 0, 0, 0, 0, 0, 16, 2, 0, 0, 0, 0, 0, 0, 16, 2, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 80, 3, 0, 0, 0, 0, 0, 0, 80, 3, 0, 0, 0, 0, 0, 0, 80, 3, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 160, 3, 0, 0, 0, 0, 0, 0, 160, 3, 0, 0, 0, 0, 0, 0, 160, 3, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 4, 0, 0, 0, 160, 60, 29, 0, 0, 0, 0, 0, 160, 76, 29, 0, 0, 0, 0, 0, 160, 76, 29, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 83, 229, 116, 100, 4, 0, 0, 0, 80, 3, 0, 0, 0, 0, 0, 0, 80, 3, 0, 0, 0, 0, 0, 0, 80, 3, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 80, 229, 116, 100, 4, 0, 0, 0, 32, 94, 26, 0, 0, 0, 0, 0, 32, 94, 26, 0, 0, 0, 0, 0, 32, 94, 26, 0, 0, 0, 0, 0, 60, 118, 0, 0, 0, 0, 0, 0, 60, 118, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 81, 229, 116, 100, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 82, 229, 116, 100, 4, 0, 0, 0, 160, 60, 29, 0, 0, 0, 0, 0, 160, 76, 29, 0, 0, 0, 0, 0, 160, 76, 29, 0, 0, 0, 0, 0, 96, 51, 0, 0, 0, 0, 0, 0]), bytes_read: Some(Ok(832)) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134837085, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 8192, arg_2: 3, arg_3: 139917457507526, arg_4: 4294967295, arg_5: 0, return_val: Some(139917457113088) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134842906, event_type: Unhandled(UnhandledSyscallData { syscall_id: 17, arg_0: 3, arg_1: 140736231668240, arg_2: 784, arg_3: 139917457507182, arg_4: 65535, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134846002, event_type: Unhandled(UnhandledSyscallData { syscall_id: 17, arg_0: 3, arg_1: 140736231668240, arg_2: 784, arg_3: 139917457507182, arg_4: 65535, arg_5: 0, return_val: Some(784) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134848757, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 1973104, arg_2: 1, arg_3: 139917457507526, arg_4: 3, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134856011, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 1973104, arg_2: 1, arg_3: 139917457507526, arg_4: 3, arg_5: 0, return_val: Some(139917455138816) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134859207, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917455294464, arg_1: 1417216, arg_2: 5, arg_3: 139917457507526, arg_4: 3, arg_5: 155648, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134873433, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917455294464, arg_1: 1417216, arg_2: 5, arg_3: 139917457507526, arg_4: 3, arg_5: 155648, return_val: Some(139917455294464) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134876770, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917456711680, arg_1: 344064, arg_2: 1, arg_3: 139917457507526, arg_4: 3, arg_5: 1572864, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134885556, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917456711680, arg_1: 344064, arg_2: 1, arg_3: 139917457507526, arg_4: 3, arg_5: 1572864, return_val: Some(139917456711680) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134888732, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917457055744, arg_1: 24576, arg_2: 3, arg_3: 139917457507526, arg_4: 3, arg_5: 1912832, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134899142, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917457055744, arg_1: 24576, arg_2: 3, arg_3: 139917457507526, arg_4: 3, arg_5: 1912832, return_val: Some(139917457055744) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134905704, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917457080320, arg_1: 31600, arg_2: 3, arg_3: 139917457507526, arg_4: 4294967295, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134912808, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 139917457080320, arg_1: 31600, arg_2: 3, arg_3: 139917457507526, arg_4: 4294967295, arg_5: 0, return_val: Some(139917457080320) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134923478, event_type: Close(CloseData { file_descriptor: 3, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134926373, event_type: Close(CloseData { file_descriptor: 3, return_val: Some(Ok(())) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134935320, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 12288, arg_2: 3, arg_3: 139917457507526, arg_4: 4294967295, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134940490, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 12288, arg_2: 3, arg_3: 139917457507526, arg_4: 4294967295, arg_5: 0, return_val: Some(139917455126528) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134947673, event_type: Unhandled(UnhandledSyscallData { syscall_id: 158, arg_0: 4098, arg_1: 139917455128384, arg_2: 18446604156254420784, arg_3: 139917457485429, arg_4: 4294967295, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134950409, event_type: Unhandled(UnhandledSyscallData { syscall_id: 158, arg_0: 4098, arg_1: 139917455128384, arg_2: 18446604156254420784, arg_3: 139917457485429, arg_4: 4294967295, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134952893, event_type: Unhandled(UnhandledSyscallData { syscall_id: 218, arg_0: 139917455129104, arg_1: 139917455128384, arg_2: 139917457584304, arg_3: 139917457446670, arg_4: 4294967295, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134955358, event_type: Unhandled(UnhandledSyscallData { syscall_id: 218, arg_0: 139917455129104, arg_1: 139917455128384, arg_2: 139917457584304, arg_3: 139917457446670, arg_4: 4294967295, arg_5: 0, return_val: Some(694062) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134957833, event_type: Unhandled(UnhandledSyscallData { syscall_id: 273, arg_0: 139917455129120, arg_1: 24, arg_2: 139917457584304, arg_3: 139917457446762, arg_4: 4294967295, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134960207, event_type: Unhandled(UnhandledSyscallData { syscall_id: 273, arg_0: 139917455129120, arg_1: 24, arg_2: 139917457584304, arg_3: 139917457446762, arg_4: 4294967295, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270134962782, event_type: Unhandled(UnhandledSyscallData { syscall_id: 334, arg_0: 139917455130720, arg_1: 32, arg_2: 0, arg_3: 139917457446878, arg_4: 0, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270134965267, event_type: Unhandled(UnhandledSyscallData { syscall_id: 334, arg_0: 139917455130720, arg_1: 32, arg_2: 0, arg_3: 139917457446878, arg_4: 0, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135016653, event_type: Unhandled(UnhandledSyscallData { syscall_id: 10, arg_0: 139917457055744, arg_1: 16384, arg_2: 1, arg_3: 139917457507675, arg_4: 0, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135023847, event_type: Unhandled(UnhandledSyscallData { syscall_id: 10, arg_0: 139917457055744, arg_1: 16384, arg_2: 1, arg_3: 139917457507675, arg_4: 0, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135040198, event_type: Unhandled(UnhandledSyscallData { syscall_id: 10, arg_0: 94268742762496, arg_1: 4096, arg_2: 1, arg_3: 139917457507675, arg_4: 0, arg_5: 139917457077920, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135047712, event_type: Unhandled(UnhandledSyscallData { syscall_id: 10, arg_0: 94268742762496, arg_1: 4096, arg_2: 1, arg_3: 139917457507675, arg_4: 0, arg_5: 139917457077920, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135052872, event_type: Unhandled(UnhandledSyscallData { syscall_id: 10, arg_0: 139917457571840, arg_1: 8192, arg_2: 1, arg_3: 139917457507675, arg_4: 0, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135059154, event_type: Unhandled(UnhandledSyscallData { syscall_id: 10, arg_0: 139917457571840, arg_1: 8192, arg_2: 1, arg_3: 139917457507675, arg_4: 0, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135071838, event_type: Unhandled(UnhandledSyscallData { syscall_id: 302, arg_0: 0, arg_1: 3, arg_2: 0, arg_3: 139917456206836, arg_4: 65535, arg_5: 8, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135074843, event_type: Unhandled(UnhandledSyscallData { syscall_id: 302, arg_0: 0, arg_1: 3, arg_2: 0, arg_3: 139917456206836, arg_4: 65535, arg_5: 8, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135084211, event_type: Unhandled(UnhandledSyscallData { syscall_id: 11, arg_0: 139917457121280, arg_1: 249811, arg_2: 139917457580032, arg_3: 139917457507723, arg_4: 0, arg_5: 8, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135097766, event_type: Unhandled(UnhandledSyscallData { syscall_id: 11, arg_0: 139917457121280, arg_1: 249811, arg_2: 139917457580032, arg_3: 139917457507723, arg_4: 0, arg_5: 8, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135120079, event_type: Unhandled(UnhandledSyscallData { syscall_id: 318, arg_0: 139917457101176, arg_1: 8, arg_2: 1, arg_3: 139917455766981, arg_4: 139917457078112, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135123715, event_type: Unhandled(UnhandledSyscallData { syscall_id: 318, arg_0: 139917457101176, arg_1: 8, arg_2: 1, arg_3: 139917455766981, arg_4: 139917457078112, arg_5: 0, return_val: Some(8) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135127172, event_type: Unhandled(UnhandledSyscallData { syscall_id: 12, arg_0: 0, arg_1: 139917457074880, arg_2: 0, arg_3: 139917456208139, arg_4: 0, arg_5: 1, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135129727, event_type: Unhandled(UnhandledSyscallData { syscall_id: 12, arg_0: 0, arg_1: 139917457074880, arg_2: 0, arg_3: 139917456208139, arg_4: 0, arg_5: 1, return_val: Some(94268750663680) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135132201, event_type: Unhandled(UnhandledSyscallData { syscall_id: 12, arg_0: 94268750798848, arg_1: 139917457074880, arg_2: 139917457105040, arg_3: 139917456208139, arg_4: 0, arg_5: 1, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135136329, event_type: Unhandled(UnhandledSyscallData { syscall_id: 12, arg_0: 94268750798848, arg_1: 139917457074880, arg_2: 139917457105040, arg_3: 139917456208139, arg_4: 0, arg_5: 1, return_val: Some(94268750798848) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135147290, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 1, arg_1: 139917456821205, arg_2: 140736231672192, arg_3: 139917456185086, arg_4: 0, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135151658, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 1, arg_1: 139917456821205, arg_2: 140736231672192, arg_3: 139917456185086, arg_4: 0, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135154513, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 0, arg_1: 139917456821205, arg_2: 140736231672192, arg_3: 139917456185086, arg_4: 0, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135157940, event_type: Unhandled(UnhandledSyscallData { syscall_id: 262, arg_0: 0, arg_1: 139917456821205, arg_2: 140736231672192, arg_3: 139917456185086, arg_4: 0, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135160545, event_type: Unhandled(UnhandledSyscallData { syscall_id: 221, arg_0: 0, arg_1: 0, arg_2: 0, arg_3: 139917456199630, arg_4: 0, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135163510, event_type: Unhandled(UnhandledSyscallData { syscall_id: 221, arg_0: 0, arg_1: 0, arg_2: 0, arg_3: 139917456199630, arg_4: 0, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135166286, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 139264, arg_2: 3, arg_3: 139917456238790, arg_4: 4294967295, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47270135172738, event_type: Unhandled(UnhandledSyscallData { syscall_id: 9, arg_0: 0, arg_1: 139264, arg_2: 3, arg_3: 139917456238790, arg_4: 4294967295, arg_5: 0, return_val: Some(139917457231872) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47270135177908, event_type: Read(ReadData { file_descriptor: 0, count: 131072, data_read: None, bytes_read: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47273552687741, event_type: Read(ReadData { file_descriptor: 0, count: 131072, data_read: Some(vec![104, 101, 108, 108, 111, 10]), bytes_read: Some(Ok(6)) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47273552701928, event_type: Write(WriteData { file_descriptor: 1, count: 6, data_written: Some(vec![104, 101, 108, 108, 111, 10]), bytes_written: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47273552787399, event_type: Write(WriteData { file_descriptor: 1, count: 6, data_written: None, bytes_written: Some(Ok(6)) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47273552791056, event_type: Read(ReadData { file_descriptor: 0, count: 131072, data_read: None, bytes_read: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47275566715078, event_type: Read(ReadData { file_descriptor: 0, count: 131072, data_read: None, bytes_read: Some(Ok(0)) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47275566726780, event_type: Unhandled(UnhandledSyscallData { syscall_id: 11, arg_0: 139917457231872, arg_1: 139264, arg_2: 0, arg_3: 139917456241259, arg_4: 135184, arg_5: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47275566744593, event_type: Unhandled(UnhandledSyscallData { syscall_id: 11, arg_0: 139917457231872, arg_1: 139264, arg_2: 0, arg_3: 139917456241259, arg_4: 135184, arg_5: 0, return_val: Some(0) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47275566748521, event_type: Close(CloseData { file_descriptor: 0, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47275566752358, event_type: Close(CloseData { file_descriptor: 0, return_val: Some(Ok(())) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47275566762196, event_type: Close(CloseData { file_descriptor: 1, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47275566765723, event_type: Close(CloseData { file_descriptor: 1, return_val: Some(Ok(())) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47275566769280, event_type: Close(CloseData { file_descriptor: 2, return_val: None }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Exit, monotonic_timestamp: 47275566772416, event_type: Close(CloseData { file_descriptor: 2, return_val: Some(Ok(())) }) }).await;
tx.send(TraceEvent { pid: 694062, thread_id: 694062, event: Event::Enter, monotonic_timestamp: 47275566783817, event_type: Exit(ExitData { status: 0 }) }).await;

    Ok(())
}

fn init_bpf(pid: u32) -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/blackbox"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/blackbox"
    ))?;

    #[cfg(debug_assertions)]
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // set up the sys_enter and sys_exit tracepoints
    let program: &mut RawTracePoint = bpf.program_mut("handle_sys_enter").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;
    let program: &mut RawTracePoint = bpf.program_mut("handle_sys_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_exit")?;

    // populate PID filter buffer
    let mut traced_pids: aya::maps::array::Array<_, u32> =
        Array::try_from(bpf.map_mut("PIDS").unwrap())?;

    traced_pids.set(0, pid, 0)?;

    Ok(bpf)
}
