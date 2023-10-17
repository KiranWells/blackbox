#[derive(Debug)]
pub struct OpenData {
    pub filename: String,
    pub file_descriptor: i32,
}

#[derive(Debug)]
pub struct ReadData {
    pub file_descriptor: i32,
    pub bytes_read: usize,
    pub data_read: Option<String>,
}

#[derive(Debug)]
pub struct WriteData {
    pub file_descriptor: i32,
    pub bytes_read: usize,
    pub data_read: Option<String>,
}

#[derive(Debug)]
pub struct CloseData {
    pub file_descriptor: i32,
}

#[derive(Debug)]
pub enum EventType {
    Open(OpenData),
    Read(ReadData),
    Write(WriteData),
    Close(CloseData),
}

#[derive(Debug)]
pub struct TraceEvent {
    pub pid: u32,
    pub thread_id: u32,
    pub enter: bool,
    pub event_type: EventType,
}
