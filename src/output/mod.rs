use std::fmt::Write as _;

use serde_json::json;

use crate::cli::OutputFormat;
use crate::event::{Event, FieldValue};

pub fn render_search_match(event: &Event, fields: &[String], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => render_json(event, fields, JsonMode::Pretty),
        OutputFormat::Jsonl => render_json(event, fields, JsonMode::Compact),
        OutputFormat::Pretty
        | OutputFormat::Compact
        | OutputFormat::Csv
        | OutputFormat::Timeline => render_pretty(event, fields),
    }
}

fn render_pretty(event: &Event, fields: &[String]) -> String {
    let timestamp = event.metadata.timestamp.as_deref().unwrap_or("-");
    let channel = event.metadata.channel.as_deref().unwrap_or("-");
    let event_id = event
        .metadata
        .event_id
        .map_or_else(|| "-".to_owned(), |value| value.to_string());
    let computer = event.metadata.computer.as_deref().unwrap_or("-");
    let record_id = event
        .metadata
        .record_id
        .map_or_else(|| "-".to_owned(), |value| value.to_string());
    let file_path = event.source.file_path.display();

    let mut output = format!(
        "{timestamp}  {channel}  {event_id}  {computer}\n  file: {file_path}  record: {record_id}"
    );

    for field in fields {
        let value = event
            .field(field)
            .and_then(FieldValue::as_text)
            .unwrap_or_else(|| "-".to_owned());
        let _ = write!(output, "\n  {field}: {value}");
    }

    output
}

#[derive(Debug, Clone, Copy)]
enum JsonMode {
    Compact,
    Pretty,
}

fn render_json(event: &Event, fields: &[String], mode: JsonMode) -> String {
    let selected_fields = fields
        .iter()
        .map(|field| {
            let value = event
                .field(field)
                .and_then(FieldValue::as_text)
                .map_or(serde_json::Value::Null, serde_json::Value::String);
            (field.clone(), value)
        })
        .collect::<serde_json::Map<_, _>>();

    let value = json!({
        "timestamp": event.metadata.timestamp,
        "record_id": event.metadata.record_id,
        "channel": event.metadata.channel,
        "provider": event.metadata.provider,
        "event_id": event.metadata.event_id,
        "computer": event.metadata.computer,
        "source": {
            "file_path": event.source.file_path,
            "collection_root": event.source.collection_root,
        },
        "fields": selected_fields,
    });

    match mode {
        JsonMode::Compact => value.to_string(),
        JsonMode::Pretty => serde_json::to_string_pretty(&value)
            .expect("serializing a serde_json::Value should not fail"),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use crate::event::Event;
    use crate::input::DiscoveredInput;

    use super::*;

    #[test]
    fn pretty_output_includes_source_identity() {
        let event = test_event();
        let output = render_search_match(&event, &[], OutputFormat::Pretty);

        assert!(output.contains("Security"));
        assert!(output.contains("WIN-01"));
        assert!(output.contains("Security.evtx"));
    }

    #[test]
    fn json_output_is_pretty_printed() {
        let event = test_event();
        let output = render_search_match(&event, &[], OutputFormat::Json);

        assert!(
            output.contains('\n'),
            "json format should be pretty printed for direct inspection"
        );
    }

    fn test_event() -> Event {
        let input = DiscoveredInput {
            path: PathBuf::from("Security.evtx"),
            collection_root: PathBuf::from("."),
        };

        Event::from_raw(
            &input,
            Some(1),
            json!({
                "Event": {
                    "System": {
                        "EventID": 4625,
                        "Channel": "Security",
                        "Computer": "WIN-01"
                    }
                }
            }),
        )
    }
}
