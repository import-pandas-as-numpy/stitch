use std::path::PathBuf;

use serde_json::Value;

use crate::input::DiscoveredInput;

#[derive(Debug, Clone)]
pub struct Event {
    pub source: EventSource,
    pub metadata: EventMetadata,
    pub raw: Value,
}

#[derive(Debug, Clone)]
pub struct EventSource {
    pub file_path: PathBuf,
    pub collection_root: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventMetadata {
    pub timestamp: Option<String>,
    pub record_id: Option<u64>,
    pub channel: Option<String>,
    pub provider: Option<String>,
    pub event_id: Option<u64>,
    pub computer: Option<String>,
}

impl Event {
    #[must_use]
    pub fn from_raw(input: &DiscoveredInput, record_id: Option<u64>, raw: Value) -> Self {
        let metadata = EventMetadata {
            timestamp: string_field(&raw, &["Event", "System", "TimeCreated", "SystemTime"])
                .or_else(|| {
                    string_field(
                        &raw,
                        &[
                            "Event",
                            "System",
                            "TimeCreated",
                            "#attributes",
                            "SystemTime",
                        ],
                    )
                }),
            record_id: record_id
                .or_else(|| number_field(&raw, &["Event", "System", "EventRecordID"])),
            channel: string_field(&raw, &["Event", "System", "Channel"]),
            provider: provider_name(&raw),
            event_id: number_field(&raw, &["Event", "System", "EventID"]),
            computer: string_field(&raw, &["Event", "System", "Computer"]),
        };

        Self {
            source: EventSource {
                file_path: input.path.clone(),
                collection_root: input.collection_root.clone(),
            },
            metadata,
            raw,
        }
    }

    #[must_use]
    pub fn field(&self, path: &str) -> Option<FieldValue<'_>> {
        self.normalized_field(path)
            .or_else(|| raw_field(&self.raw, path).map(field_value_from_json))
    }

    fn normalized_field(&self, path: &str) -> Option<FieldValue<'_>> {
        match path {
            "timestamp" | "event.timestamp" | "winlog.timestamp" => {
                self.metadata.timestamp.as_deref().map(FieldValue::String)
            }
            "record_id" | "event.record_id" | "winlog.record_id" => {
                self.metadata.record_id.map(FieldValue::Number)
            }
            "channel" | "event.channel" | "winlog.channel" => {
                self.metadata.channel.as_deref().map(FieldValue::String)
            }
            "provider" | "event.provider" | "winlog.provider_name" => {
                self.metadata.provider.as_deref().map(FieldValue::String)
            }
            "event.id" | "event_id" | "winlog.event_id" => {
                self.metadata.event_id.map(FieldValue::Number)
            }
            "computer" | "host" | "host.name" | "source.computer" => {
                self.metadata.computer.as_deref().map(FieldValue::String)
            }
            "source.file_path" | "file_path" => {
                self.source.file_path.to_str().map(FieldValue::String)
            }
            "source.collection_root" => {
                self.source.collection_root.to_str().map(FieldValue::String)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FieldValue<'a> {
    String(&'a str),
    Number(u64),
    Bool(bool),
    Json(&'a Value),
}

impl FieldValue<'_> {
    #[must_use]
    pub fn as_text(self) -> Option<String> {
        match self {
            Self::String(value) => Some(value.to_owned()),
            Self::Number(value) => Some(value.to_string()),
            Self::Bool(value) => Some(value.to_string()),
            Self::Json(value) => json_as_text(value),
        }
    }

    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(value),
            Self::String(value) => value.parse().ok(),
            Self::Bool(_) | Self::Json(_) => None,
        }
    }
}

fn raw_field<'a>(raw: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = raw;

    for segment in path.split('.') {
        current = current.get(segment)?;
    }

    Some(current)
}

fn field_value_from_json(value: &Value) -> FieldValue<'_> {
    match value {
        Value::String(text) => FieldValue::String(text),
        Value::Number(number) => number
            .as_u64()
            .map_or(FieldValue::Json(value), FieldValue::Number),
        Value::Bool(boolean) => FieldValue::Bool(*boolean),
        Value::Null | Value::Array(_) | Value::Object(_) => FieldValue::Json(value),
    }
}

fn string_field(raw: &Value, path: &[&str]) -> Option<String> {
    value_at(raw, path).and_then(string_from_value)
}

fn number_field(raw: &Value, path: &[&str]) -> Option<u64> {
    value_at(raw, path).and_then(number_from_value)
}

fn string_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Object(object) => object.get("#text").and_then(string_from_value),
        _ => None,
    }
}

fn number_from_value(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.parse().ok(),
        Value::Object(object) => object.get("#text").and_then(number_from_value),
        _ => None,
    }
}

fn provider_name(raw: &Value) -> Option<String> {
    string_field(raw, &["Event", "System", "Provider", "Name"])
        .or_else(|| string_field(raw, &["Event", "System", "Provider", "#attributes", "Name"]))
}

fn value_at<'a>(raw: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = raw;

    for segment in path {
        current = current.get(segment)?;
    }

    Some(current)
}

fn json_as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests;
