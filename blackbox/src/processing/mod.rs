use color_eyre::eyre::Result;
use nix::sys::socket::{AddressFamily, SockProtocol};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::types::{
    AccessType, Alert, CloseData, Connection, ConnectionDomain, ConnectionProtocol, ExecveData,
    ExitData, FileAccess, FileBehavior, ForkData, OpenData, ProcessingData, ReadData, ShutdownData,
    SocketData, SpawnEvent, SpawnType, TraceEvent, UnhandledSyscallData, WriteData,
};

use crate::types::SyscallData::*;

pub async fn start_processing(
    mut rx: tokio::sync::mpsc::Receiver<TraceEvent>,
    done_notifier: Arc<tokio::sync::Notify>,
    shared_state: Arc<Mutex<Option<ProcessingData>>>,
) -> Result<()> {
    // collect trace events into hashmap
    let mut file_hash: HashMap<i32, Vec<TraceEvent>> = HashMap::new(); //Map each event to their File_Descriptor (Same File)
    let mut connection_hash: HashMap<i32, Vec<TraceEvent>> = HashMap::new(); // Map each connection to their fd
    let mut spawns: Vec<TraceEvent> = vec![];
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
                    let list = connection_hash.entry(fd).or_insert(vec![]);
                    list.push(i);
                }
            }
            Shutdown(ShutdownData {
                file_descriptor, ..
            }) => {
                let list = connection_hash.entry(file_descriptor).or_insert(vec![]);
                list.push(i);
            }
            Fork(ForkData { .. }) => spawns.push(i),
            Execve(ExecveData { .. }) => spawns.push(i),
            Exit(ExitData { .. }) => {
                // the process is done
                // TODO: handle async events sent after this point
                break;
            }
            Unhandled(UnhandledSyscallData { syscall_id, .. }) => {
                data.unhandled_ids.push(syscall_id); //not associated with any summary, just tracking ids
            }
        }
    }
    for (_, mut value) in file_hash {
        //begin processing all events
        // sort value by monotonic time
        value.sort_by(|a, b| a.monotonic_exit_timestamp.cmp(&b.monotonic_exit_timestamp));

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
                        r if r == nix::fcntl::OFlag::O_RDONLY.bits() => fa.access_type.read = true,
                        w if w == nix::fcntl::OFlag::O_WRONLY.bits() => fa.access_type.write = true,
                        rw if rw == nix::fcntl::OFlag::O_RDWR.bits() => {
                            fa.access_type.write = true;
                            fa.access_type.read = true;
                        }
                        _ => {}
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
                Close(CloseData {
                    file_descriptor, ..
                }) => {
                    fa.file_descriptor = file_descriptor;
                    fa.end_time = event.clone().monotonic_exit_timestamp - fa.start_time;
                    // finalize fileaccess
                    data.file_events.push(fa.clone());
                    // clear fa data
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
                _ => unreachable!(),
            }
        }
    }
    for (_, mut value) in connection_hash {
        // begin processing all events
        // sort value by monotonic time
        value.sort_by(|a, b| a.monotonic_exit_timestamp.cmp(&b.monotonic_exit_timestamp));

        let mut conn = Connection {
            domain: ConnectionDomain::Other,
            protocol: crate::types::ConnectionProtocol::Other,
            start_time: 0,
            end_time: 0,
        };

        for event in value {
            match event.clone().data {
                Socket(SocketData {
                    file_descriptor,
                    domain,
                    r#type: _,
                    protocol,
                }) => {
                    if file_descriptor.is_ok() {
                        // conn.protocol = match SockType::try_from(r#type) {
                        //     Ok(SockType::Stream) => ConnectionProtocol::TCP,
                        //     Ok(SockType::Datagram) => ConnectionProtocol::UDP,
                        //     _ => ConnectionProtocol::Other,
                        // };
                        conn.protocol = match protocol {
                            x if x == SockProtocol::Tcp as i32 => ConnectionProtocol::TCP,
                            x if x == SockProtocol::Udp as i32 => ConnectionProtocol::UDP,
                            _ => ConnectionProtocol::Other,
                        };
                        conn.domain = match domain {
                            x if x == AddressFamily::Inet as i32 => ConnectionDomain::IPv4,
                            x if x == AddressFamily::Inet6 as i32 => ConnectionDomain::IPv6,
                            _ => ConnectionDomain::Other,
                        };
                        conn.start_time = event.monotonic_enter_timestamp;
                    }
                }
                Shutdown(ShutdownData { .. }) => {
                    conn.end_time = event.monotonic_exit_timestamp;
                }
                _ => unreachable!(),
            }
        }
    }
    spawns.sort_by(|a, b| a.monotonic_exit_timestamp.cmp(&b.monotonic_exit_timestamp));

    for event in spawns {
        match event.clone().data {
            Fork(ForkData { pid }) => {
                if let Ok(pid) = pid {
                    data.process_events.push(SpawnEvent {
                        spawn_type: SpawnType::Fork,
                        spawn_time: event.monotonic_enter_timestamp,
                        process_id: pid,
                        parent_id: event.pid,
                        command: None,
                    })
                }
            }
            Execve(ExecveData { filename, .. }) => {
                data.process_summary.programs.push(filename.clone());
                if filename.is_some() {
                    update_behavior(
                        &mut data.file_summary.behavior,
                        &AccessType {
                            execute: true,
                            ..Default::default()
                        },
                        &filename.clone().unwrap(),
                    );
                }
                data.process_events.push(SpawnEvent {
                    spawn_type: SpawnType::Exec,
                    spawn_time: event.monotonic_enter_timestamp,
                    process_id: event.pid, // this does not spawn a new process, but overwrite the current one
                    parent_id: event.pid,
                    command: filename,
                })
            }
            _ => unreachable!(),
        }
    }

    // file summary
    for fa in data.file_events.iter() {
        if fa.file_descriptor < 3 {
            // stdio
            data.file_summary.behavior.stdio.update(&fa.access_type);
        } else {
            data.file_summary.access_count += 1;
        }
        let Some(name) = fa.file_name.clone() else {
            continue;
        };
        // directories first
        let path = Path::new(&name);
        if path.is_dir() {
            data.file_summary.directories.push(name.clone());
        } else if let Some(parent) = path.parent() {
            data.file_summary
                .directories
                .push(parent.to_owned().as_os_str().to_owned());
        }

        update_behavior(&mut data.file_summary.behavior, &fa.access_type, &name);
    }

    // process summary
    let mut fork_count = 0;
    if !data.process_events.is_empty() {
        for spawn in data.process_events.iter() {
            if spawn.spawn_type == SpawnType::Exec {
                fork_count -= 1;
            } else {
                fork_count += 1;
            }
            data.process_summary.processes_created += 1;
        }
        if fork_count < 0 {
            data.process_summary.most_common_spawn_type = SpawnType::Exec;
        }
    }

    // network summary
    for conn in data.network_events.iter() {
        data.network_summary.connection_count += 1;
        data.network_summary.domains.push(conn.domain);
        data.network_summary.protocols.push(conn.protocol);
    }

    // check for /root access
    for access in data.file_events.iter() {
        let Some(name) = &access.file_name else {
            continue;
        };
        let root_dir_regex = regex::Regex::new(r"^/root/").unwrap();
        if root_dir_regex.is_match(&name.to_string_lossy()) {
            data.alerts.push(Alert {
                severity: 0,
                message: String::from("Root infiltration detected!"),
            })
        }
    }
    if data.file_summary.behavior.system.write {
        data.alerts.push(Alert {
            severity: 1,
            message: String::from("Attempting to write into system"),
        });
    }
    if data.file_summary.behavior.current_dir.execute {
        data.alerts.push(Alert {
            severity: 1,
            message: String::from("Attempting to execute in current directory"),
        });
    }
    if data.file_summary.behavior.home_dir.execute || data.file_summary.behavior.runtime.execute {
        data.alerts.push(Alert {
            severity: 2,
            message: String::from("Attempting to execute from non-system directory"),
        });
    }
    if data.file_summary.behavior.runtime.write || data.file_summary.behavior.runtime.read {
        data.alerts.push(Alert {
            severity: 3,
            message: String::from("Unexpected access of runtime directories"),
        });
    }

    *shared_state.lock().await = Some(data);
    done_notifier.notify_waiters();
    Ok(())
}

fn update_behavior(behavior: &mut FileBehavior, access_type: &AccessType, name: &OsString) {
    let path = Path::new(&name);
    let name = name.to_string_lossy();
    if path.is_relative() {
        behavior.current_dir.update(access_type);
    }
    let home_dir_regex = regex::Regex::new(r"^(~/?|/home/?)").unwrap();
    if home_dir_regex.is_match(&name) {
        behavior.home_dir.update(access_type);
    }
    let system_files_regex =
        regex::Regex::new(r"^/(usr|bin|opt|boot|etc|lib|lib64|var|mnt|opt|root|sbin|srv|sys)")
            .unwrap();
    if system_files_regex.is_match(&name) {
        behavior.system.update(access_type);
    }
    let runtime_regex = regex::Regex::new(r"^/(tmp|run|proc|dev)").unwrap();
    if runtime_regex.is_match(&name) {
        behavior.runtime.update(access_type);
    }
}
