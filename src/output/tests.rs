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
