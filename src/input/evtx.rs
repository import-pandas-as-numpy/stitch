use evtx::EvtxParser;
use thiserror::Error;

use crate::event::Event;
use crate::input::DiscoveredInput;

const MAX_ERROR_SAMPLES: usize = 5;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EvtxReadStats {
    pub records_seen: usize,
    pub records_failed: usize,
    pub error_samples: Vec<EvtxRecordError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvtxRecordError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum EvtxReadError {
    #[error("failed to open EVTX file {path}: {message}")]
    Open { path: String, message: String },
    #[error("failed to parse EVTX record in {path}: {message}")]
    Record { path: String, message: String },
}

pub fn read_evtx_events_with_errors(
    input: &DiscoveredInput,
    strict: bool,
    mut on_event: impl FnMut(Event),
    mut on_error: impl FnMut(&EvtxRecordError),
) -> Result<EvtxReadStats, EvtxReadError> {
    let mut parser = EvtxParser::from_path(&input.path).map_err(|error| EvtxReadError::Open {
        path: input.path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut stats = EvtxReadStats::default();

    for record in parser.records_json_value() {
        match record {
            Ok(record) => {
                stats.records_seen += 1;
                on_event(Event::from_raw(
                    input,
                    Some(record.event_record_id),
                    record.data,
                ));
            }
            Err(error) => {
                stats.records_failed += 1;

                if strict {
                    return Err(EvtxReadError::Record {
                        path: input.path.display().to_string(),
                        message: error.to_string(),
                    });
                }

                let error = EvtxRecordError {
                    path: input.path.display().to_string(),
                    message: error.to_string(),
                };
                on_error(&error);

                if stats.error_samples.len() < MAX_ERROR_SAMPLES {
                    stats.error_samples.push(error);
                }
            }
        }
    }

    Ok(stats)
}
