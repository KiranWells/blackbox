use color_eyre::eyre::Result;
use nix::sys::socket::SockType;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::types::{
    AccessType, Alert, CloseData, Connection, ConnectionDomain, ExecveData, ExitData, 
    FileAccess, FileBehavior, ForkData, FileSummary, NetworkSummary, OpenData, 
    ProcessingData, ProcessSummary, ReadData, ShutdownData, SocketData, 
    SpawnEvent, SpawnType, TraceEvent, UnhandledSyscallData, WriteData,
};

use crate::types::SyscallData::*;

pub async fn start_processing(
    mut rx: tokio::sync::mpsc::Receiver<TraceEvent>,
    done_notifier: Arc<tokio::sync::Notify>,
    shared_state: Arc<Mutex<Option<ProcessingData>>>,
) -> Result<()> {
    // collect trace events into hashmap
    let mut file_hash: HashMap<i32, Vec<TraceEvent>> = HashMap::new(); //Map each event to their File_Descriptor (Same File)
    let mut data = ProcessingData::default();
    while let Some(i) = rx.recv().await {
        match i.clone().data {
            Open(OpenData {
                file_descriptor, ..
            }) => {
                if let Ok(fd) = file_descriptor {
                    let list = file_hash.entry(fd).or_insert(vec![]);
                    list.push(i);
                }
            }
            Read(ReadData {
                file_descriptor, ..
            }) => {
                let list = file_hash.entry(file_descriptor).or_insert(vec![]);
                list.push(i);
            }
            Write(WriteData {
                file_descriptor, ..
            }) => {
                let list = file_hash.entry(file_descriptor).or_insert(vec![]);
                list.push(i);
            }
            Close(CloseData {
                file_descriptor, ..
            }) => {
                let list = file_hash.entry(file_descriptor).or_insert(vec![]);
                list.push(i);
            }
            Socket(SocketData {
                file_descriptor, ..
            }) => {
                if let Ok(fd) = file_descriptor {
                    let list = file_hash.entry(fd).or_insert(vec![]);
                    list.push(i);
                }
            }
            Shutdown(ShutdownData {
                file_descriptor, ..
            }) => {
                let list = file_hash.entry(file_descriptor).or_insert(vec![]);
                list.push(i);
            }

            Fork(ForkData{
                pid
            }) => {
                if let Ok(fd) = pid {
                    let list = file_hash.entry(fd as i32).or_insert(vec![]);
                    list.push(i);
                }
            }
            Execve(ExecveData { directory_fd,..
            }) => {
                if let Some(fd) = directory_fd {
                    let list = file_hash.entry(fd).or_insert(vec![]);
                    list.push(i);
                }
            }
            Exit(ExitData { .. }) => {
                // the process is done
                // TODO: handle async events sent after this point
                break;
            }
            Unhandled(UnhandledSyscallData {
                syscall_id, ..
            }) => {
                data.unhandled_ids.push(syscall_id); //not associated with any summary, just tracking ids

            }
        }
    }
    for (_, mut value) in file_hash {
        //begin processing all events
        // sort value by monotonic time
        value.sort_by(|a, b| a.monotonic_exit_timestamp.cmp(&b.monotonic_exit_timestamp));

        let mut new_spawn: SpawnEvent = SpawnEvent {
            spawn_type: SpawnType::Fork,
            spawn_time: 0,
            process_id: 0,
            parent_id: 0,
            command: None,
        };

        let mut fa = FileAccess {
            file_name: None,
            file_descriptor: 0,
            data_length: 0,
            read_data: vec![],
            write_data: vec![],
            start_time: 0,
            end_time: 0,
            error_count: 0,
            access_type: AccessType::default(),
        };

        // group by open -> close event pairs
        for event in value {
            match event.clone().data {
                Open(OpenData {
                    filename,
                    file_descriptor,
                    flags,
                    ..
                }) => {
                    match file_descriptor {
                        Ok(fd) => {
                            fa.file_descriptor = fd;
                        }
                        Err(_) => {
                            fa.error_count += 1;
                        }
                    }
                    if filename.is_some() {
                        fa.file_name = filename;
                    }
                    match flags {
                        nix::fcntl::OFlag::O_RDONLY as i32 => fa.access_type.read = true,
                        nix::fcntl::OFlag::O_WRONLY => fa.access_type.write = true,
                        nix::fcntl::OFlag::O_RDWR => {fa.access_type.write = true; fa.access_type.read = true;},
                    }
                    fa.start_time = event.clone().monotonic_enter_timestamp;
                }
                Read(ReadData {
                    data_read,
                    bytes_read,
                    ..
                }) => {
                    if let Some(mut dr) = data_read {
                        fa.access_type.read = true;
                        fa.read_data.append(&mut dr);
                    }
                    match bytes_read {
                        Ok(br) => {
                            fa.data_length += br;
                            data.file_summary.bytes_read += br as u64;
                        }
                        Err(_) => {
                            fa.error_count += 1;
                        }
                    }
                }
                Write(WriteData {
                    data_written,
                    bytes_written,
                    ..
                }) => {
                    if let Some(mut dw) = data_written {
                        fa.access_type.write = true;
                        fa.write_data.append(&mut dw);
                    }
                    match bytes_written {
                        Ok(bw) => {
                            fa.data_length += bw;
                            data.file_summary.bytes_written += bw as u64;

                        }
                        Err(_) => {
                            fa.error_count += 1;
                        }
                    }
                }
                Socket(SocketData {
                    file_descriptor,
                    domain: _,
                    r#type,
                    protocol: _,
                }) => match file_descriptor {
                    Ok(fd) => {
                        fa.file_descriptor = fd;
                        match SockType::try_from(r#type).unwrap() {
                            SockType::Stream => todo!(),
                            SockType::Datagram => todo!(),
                            SockType::SeqPacket => todo!(),
                            SockType::Raw => todo!(),
                            SockType::Rdm => todo!(),
                            _ => todo!(),
                        }
                    }
                    Err(_) => {
                        fa.error_count += 1;
                    }
                },
                Fork(ForkData {
                    pid
                }) => {
                    fa.access_type.execute = true;
                    new_spawn.spawn_time = event.monotonic_enter_timestamp;
                    data.process_events.push(new_spawn.clone())
                }
                Execve(ExecveData { 
                    filename,
                    args,
                    environment,
                    directory_fd, 
                    flags,
                    ..}) => {
                        new_spawn.spawn_time = event.monotonic_enter_timestamp;
                        new_spawn.spawn_type = SpawnType::Exec;
                        fa.access_type.execute = true;
                        if filename.is_some() {
                            fa.file_name = filename;
                        }
                        data.process_events.push(new_spawn.clone())
                    }
                Exit(_) => {}
                Unhandled(_) => {
                    //Nothing to be done here, ids already collected
                }
                Shutdown(_) => {}
                Close(CloseData {
                    file_descriptor, ..
                }) => {
                    fa.file_descriptor = file_descriptor;
                    fa.end_time = event.clone().monotonic_exit_timestamp - fa.start_time;
                    // finalize fileaccess
                    // send to UI (in the future)
                    // clear fa data
                    data.file_events.push(fa.clone());
                    fa.data_length = 0;
                    fa.file_descriptor = -1;
                    fa.start_time = 0;
                    fa.end_time = 0;
                    fa.error_count = 0;
                    fa.file_name.take();
                    fa.read_data.clear();
                    fa.write_data.clear();
                    fa.access_type = AccessType::default();
                }
            }
        }
    }

    // determine behavior
    for fa in data.file_events.iter() {
        if fa.file_descriptor < 3 {
            // stdio
            data.file_summary.behavior.stdio
        }
    }

    *shared_state.lock().await = Some(data);
    done_notifier.notify_waiters(); 
    Ok(())
}
