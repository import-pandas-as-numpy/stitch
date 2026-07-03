use std::path::PathBuf;

use serde_json::json;

use super::*;

#[test]
fn extracts_normalized_metadata_from_evtx_json_shape() {
    let input = DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from("."));
    let event = Event::from_raw(
        &input,
        Some(42),
        json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Security",
                    "Computer": "WIN-01",
                    "Provider": { "Name": "Microsoft-Windows-Security-Auditing" },
                    "TimeCreated": { "SystemTime": "2026-06-27T00:00:00Z" }
                }
            }
        }),
    );

    assert_eq!(event.metadata.event_id, Some(4625));
    assert_eq!(event.metadata.channel.as_deref(), Some("Security"));
    assert_eq!(event.metadata.computer.as_deref(), Some("WIN-01"));
    assert_eq!(event.metadata.record_id, Some(42));
}

#[test]
fn resolves_normalized_and_raw_fields() {
    let input = DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from("."));
    let event = Event::from_raw(
        &input,
        None,
        json!({
            "Event": {
                "System": { "EventID": "4624" },
                "EventData": { "TargetUserName": "alice" }
            }
        }),
    );

    assert_eq!(
        event.field("event.id").and_then(FieldValue::as_u64),
        Some(4624)
    );
    assert_eq!(
        event
            .field("Event.EventData.TargetUserName")
            .and_then(FieldValue::as_text),
        Some("alice".to_owned())
    );
}

#[test]
fn normalizes_evtx_attribute_and_text_shapes() {
    let input = DiscoveredInput::new(PathBuf::from("System.evtx"), PathBuf::from("."));
    let event = Event::from_raw(
        &input,
        None,
        json!({
            "Event": {
                "System": {
                    "EventID": { "#text": 6005 },
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-03-21T06:41:16.550747Z"
                        }
                    }
                }
            }
        }),
    );

    assert_eq!(event.metadata.event_id, Some(6005));
    assert_eq!(
        event.metadata.timestamp.as_deref(),
        Some("2026-03-21T06:41:16.550747Z")
    );
}
