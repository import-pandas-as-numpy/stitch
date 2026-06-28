mod discover;
mod evtx;

pub use discover::{DiscoveredInput, DiscoveryConfig, DiscoveryError, discover_inputs};
pub use evtx::{
    EvtxReadError, EvtxRecordError, read_evtx_events_with_errors, read_evtx_records_with_errors,
};
