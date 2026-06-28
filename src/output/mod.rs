use std::fmt::Write as _;

use serde_json::{Value, json};

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

pub fn dump_json_value(event: &Event, fields: &[String], raw: bool) -> serde_json::Value {
    if raw {
        return event.raw.clone();
    }

    if !fields.is_empty() {
        return json!({
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
            "fields": selected_event_fields(event, fields),
        });
    }

    json!({
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
        "raw": event.raw,
    })
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
        "{timestamp:<26}  {channel:<36}  {event_id:<6}  {computer}\n  file: {file_path}  record: {record_id}"
    );

    if fields.is_empty() {
        let record = yaml_like_value(&event.raw, 4);
        let _ = write!(output, "\n  record:\n{record}");
        return output;
    }

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
    let mut value = json!({
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
    });

    if fields.is_empty() {
        value["raw"] = event.raw.clone();
    } else {
        value["fields"] = json!(selected_event_fields(event, fields));
    }

    match mode {
        JsonMode::Compact => value.to_string(),
        JsonMode::Pretty => serde_json::to_string_pretty(&value)
            .expect("serializing a serde_json::Value should not fail"),
    }
}

fn selected_event_fields(
    event: &Event,
    fields: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    fields
        .iter()
        .map(|field| {
            let value = event
                .field(field)
                .and_then(FieldValue::as_text)
                .map_or(serde_json::Value::Null, serde_json::Value::String);
            (field.clone(), value)
        })
        .collect()
}

#[must_use]
pub fn render_event_payload(event: &Event, indent: usize) -> String {
    yaml_like_value(concise_payload_value(event), indent)
}

fn concise_payload_value(event: &Event) -> &Value {
    value_at(&event.raw, &["Event", "EventData"])
        .or_else(|| value_at(&event.raw, &["event_data"]))
        .unwrap_or(&event.raw)
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;

    for segment in path {
        current = current.get(segment)?;
    }

    Some(current)
}

fn yaml_like_value(value: &Value, indent: usize) -> String {
    let mut output = String::new();
    write_yaml_like(value, indent, &mut output);
    if output.ends_with('\n') {
        output.pop();
    }
    output
}

fn write_yaml_like(value: &Value, indent: usize, output: &mut String) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                write_indent(output, indent);

                if let Some(text) = scalar_value_text(value) {
                    let _ = writeln!(output, "{key}: {text}");
                } else {
                    let _ = writeln!(output, "{key}:");
                    write_yaml_like(value, indent + 2, output);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                write_indent(output, indent);

                if let Some(text) = scalar_value_text(value) {
                    let _ = writeln!(output, "- {text}");
                } else {
                    let _ = writeln!(output, "-");
                    write_yaml_like(value, indent + 2, output);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            if let Some(text) = scalar_value_text(value) {
                write_indent(output, indent);
                let _ = writeln!(output, "{text}");
            }
        }
    }
}

fn scalar_value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_owned()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.replace('\n', "\\n")),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn write_indent(output: &mut String, indent: usize) {
    for _ in 0..indent {
        output.push(' ');
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
        assert!(output.contains("record:"));
        assert!(output.contains("Event:"));
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

    #[test]
    fn projected_pretty_output_omits_full_record() {
        let event = test_event();
        let fields = vec!["event.id".to_owned()];
        let output = render_search_match(&event, &fields, OutputFormat::Pretty);

        assert!(output.contains("event.id: 4625"));
        assert!(
            !output.contains("\n  record:\n"),
            "projected search output should remain concise"
        );
    }

    fn test_event() -> Event {
        let input = DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from("."));

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
