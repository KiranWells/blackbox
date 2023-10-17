use color_eyre::eyre::Result;

use crate::types::TraceEvent;

pub async fn start_processing(mut rx: tokio::sync::mpsc::Receiver<TraceEvent>) -> Result<()> {
    // process trace events
    while let Some(i) = rx.recv().await {
        println!("got = {:?}", i);
    }
    Ok(())
}
