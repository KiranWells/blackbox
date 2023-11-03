use color_eyre::eyre::Result;
use std::collections::HashMap;
use std::ffi::OsString;

use crate::types::{
    CloseData, EventType, ExitData, ForkData, OpenData, ReadData, ShutdownData, SocketData,
    TraceEvent, UnhandledSyscallData, WriteData,
};

use crate::types::EventType::{Close, Exit, Fork, Open, Read, Shutdown, Socket, Unhandled, Write};

#[derive(Debug)]
struct FileAccess {
    file_name: OsString,
    file_descriptor: i32,
    data_length: usize,
    read_data: Vec<u8>,
    write_data: Vec<u8>,
    start_time: u64,
    end_time: u64,
    error_count: i32,
    unhandled_ids: Vec<u64>,
}
pub async fn start_processing(mut rx: tokio::sync::mpsc::Receiver<TraceEvent>) -> Result<()> {
    // collect trace events into hashmap
    let mut file_hash: HashMap<i32, Vec<TraceEvent>> = HashMap::new(); //Map each event to their File_Descriptor (Same File)
    while let Some(i) = rx.recv().await {
        match i.clone().event_type {
            Open(OpenData {
                filename,
                flags,
                file_descriptor,
                ..
            }) => {
                if let Some(Ok(fd)) = file_descriptor {
                    let list = file_hash.entry(fd as i32).or_insert(vec![]);
                    list.push(i);
                }
            }
            Read(ReadData {
                data_read,
                bytes_read,
                file_descriptor,
                ..
            }) => {
                if let fd = file_descriptor {
                    let list = file_hash.entry(fd as i32).or_insert(vec![]);
                    list.push(i);
                }
            }
            Write(WriteData {
                data_written,
                bytes_written,
                file_descriptor,
                ..
            }) => {
                if let fd = file_descriptor {
                    let list = file_hash.entry(fd as i32).or_insert(vec![]);
                    list.push(i);
                }
            }
            Close(CloseData {
                file_descriptor, ..
            }) => {
                let list = file_hash.entry(file_descriptor as i32).or_insert(vec![]);
                list.push(i);
            }
            Socket(SocketData {
                file_descriptor, ..
            }) => {
                if let Some(Ok(fd)) = file_descriptor {
                    let list = file_hash.entry(fd as i32).or_insert(vec![]);
                    list.push(i);
                }
            },
            Shutdown(ShutdownData {
                file_descriptor, ..
            }) => {
                let list = file_hash.entry(file_descriptor as i32).or_insert(vec![]);
                list.push(i);
            }

            Fork(data) => {}
            Exit(ExitData { .. }) => {
                //open_files.pop_front(); //The file descriptor for the first file is no longer needed
                break;
            }
            Unhandled(UnhandledSyscallData { syscall_id, .. }) => {
                //println!("Syscall_Id of Unhandled Event: {syscall_id}");
            }
        }
    }
    for (key, mut value) in file_hash {
        //begin processing all events
        // sort value by monotonic_time
        value.sort_by(|a, b| a.monotonic_timestamp.cmp(&b.monotonic_timestamp));

        let mut fa = FileAccess {
            file_name: OsString::new(),
            file_descriptor: 0,
            data_length: 0,
            read_data: vec![],
            write_data: vec![],
            start_time: 0,
            end_time: 0,
            error_count: 0,
            unhandled_ids: vec![],
        };
        // group by open -> close event pairs
        for event in value {
            match event.clone().event_type {
                Open(OpenData {
                    filename,
                    flags,
                    file_descriptor,
                }) => {
                    if let Some(Ok(fd)) = file_descriptor {
                        fa.file_descriptor = fd as i32;
                    }
                    else if let Some(Err(fd)) = file_descriptor {
                        fa.error_count+=1;
                    }
                    if let Some(fname) = filename {
                        fa.file_name = fname;
                    }
                    fa.start_time = event.clone().monotonic_timestamp;
                }
                Read(ReadData {
                    file_descriptor,
                    count,
                    data_read,
                    bytes_read,
                }) => { 
                    if let Some(mut dr) = data_read {
                        fa.read_data.append(&mut dr);
                    }      
                    if let Some(Ok(br)) = bytes_read {
                        fa.data_length+=br;
                    }
                    else if let Some(Err(br)) = bytes_read {
                        fa.error_count+=1;
                    }         
                }
                Write(WriteData {
                    file_descriptor,
                    count,
                    data_written,
                    bytes_written,
                }) => {
                    if let Some(mut dw) = data_written {
                        fa.write_data.append(&mut dw);
                    }      
                    if let Some(Ok(bw)) = bytes_written {
                        fa.data_length+=bw;
                    }       
                    else if let Some(Err(bw)) = bytes_written {
                        fa.error_count+=1;
                    }  
                }
                Socket(SocketData {
                    file_descriptor,
                    domain,
                    r#type,
                    protocol,
                }) => {
                    if let Some(Ok(fd)) = file_descriptor {
                        fa.file_descriptor = fd as i32;
                    }
                    else if let Some(Err(fd)) = file_descriptor {
                        fa.error_count+=1;
                    }
                }
                Fork(ForkData {
                    pid,
                }) => {
                 
                }
                Exit(ExitData {
                    status,
                }) => {
                 
                }
                Unhandled(UnhandledSyscallData {
                    syscall_id , 
                    arg_0 ,
                    arg_1 ,
                    arg_2 ,
                    arg_3 ,
                    arg_4 ,
                    arg_5 ,
                    return_val
                }) => {
                    fa.unhandled_ids.push(syscall_id);
                }
                Shutdown(ShutdownData{
                    file_descriptor,
                    how,
                    return_val,
                }) => {
                }
                Close(CloseData {
                    file_descriptor,
                    return_val,
                }) => {
                    fa.file_descriptor = file_descriptor;
                    fa.end_time = event.clone().monotonic_timestamp-fa.start_time;
                    if let Some(r_val) = return_val {
                        // finalize fileaccess
                        // send to UI (in the future)
                        //dbg!(&fa);
                        println!("File Access Complete");
                        if fa.file_name.is_empty(){
                           fa.file_name=OsString::from("Unknown"); 
                        }
                        println!("  File Name: {:?}",fa.file_name);
                        println!("  File Descriptor: {:?}", fa.file_descriptor);
                        if !fa.read_data.is_empty(){
                            println!("  Data Read: {:?}", fa.read_data);
                        }
                        if !fa.write_data.is_empty(){
                            println!("  Data Written: {:?}", fa.write_data);
                        }
                        println!("  Total Data Length: {:?}", fa.data_length);
                        println!("  Time Range: {:?} ns", fa.end_time);
                        println!("  Number of Errors when accessing: {:?}", fa.error_count);
                        if !fa.write_data.is_empty(){
                            println!("  Unhandled Process IDs: {:?}", fa.unhandled_ids);
                        }
                        fa.data_length=0;
                        fa.file_descriptor=-1;
                        fa.start_time=0;
                        fa.end_time=0;
                        fa.error_count=0;
                        fa.file_name.clear();
                        fa.read_data.clear();
                        fa.write_data.clear();
                        fa.unhandled_ids.clear();
                        // clear fa data
                    }
                }
            }
        }
        // open
        // read/write - duplicate from open
        //socket correspond to open with a socket
        //shutdown correspond to close (only works for socket)
        // read
        // write
        // close

        // file "filename" was opened on file descriptor N
        // and X bytes were written and X bytes read
        // X amount of errors occurred while accessing this file
        // struct FileAccess {
        //     file_name: OsString,
        //     file_descriptor: i32,
        //     data_written: Vec<u8>,
        //     ...
        // }

        // open
        // read
        // write
        // read

        // build a file access description for each group
        //TODO
        // _end_time = i.monotonic_timestamp;
    }
    Ok(())
}
