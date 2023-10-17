use aya::Bpf;
use color_eyre::eyre::Result;

use crate::types::TraceEvent;

pub async fn start_tracing(_bpf: Bpf, tx: tokio::sync::mpsc::Sender<TraceEvent>) -> Result<()> {
    // collect trace events
    // send fake data here
    for i in 0..10 {
        let t = TraceEvent {
            pid: 0,
            thread_id: 0,
            enter: true,
            event_type: crate::types::EventType::Open(crate::types::OpenData {
                filename: format!("file_{}", i),
                file_descriptor: i,
            }),
        };

        tx.send(t).await?;
    }
    Ok(())
}
