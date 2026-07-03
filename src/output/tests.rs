use std::path::PathBuf;

use serde_json::json;

use crate::event::Event;
use crate::input::DiscoveredInput;

use super::*;

#[test]
fn pretty_output_includes_source_identity() {
    let event = test_event();
    let output = render_search_match(&event, &[], OutputFormat::Pretty, DisplayStyle::Plain);

    assert!(output.contains("Security"));
    assert!(output.contains("WIN-01"));
    assert!(output.contains("Security.evtx"));
    assert!(output.contains("record:"));
    assert!(output.contains("Event:"));
}

#[test]
fn json_output_is_pretty_printed() {
    let event = test_event();
    let output = render_search_match(&event, &[], OutputFormat::Json, DisplayStyle::Plain);

    assert!(
        output.contains('\n'),
        "json format should be pretty printed for direct inspection"
    );
}

#[test]
fn projected_pretty_output_omits_full_record() {
    let event = test_event();
    let fields = vec!["event.id".to_owned()];
    let output = render_search_match(&event, &fields, OutputFormat::Pretty, DisplayStyle::Plain);

    assert!(output.contains("event.id: 4625"));
    assert!(
        !output.contains("\n  record:\n"),
        "projected search output should remain concise"
    );
}

#[test]
fn colored_pretty_output_distinguishes_fields_and_values() {
    let event = test_event();
    let fields = vec!["event.id".to_owned()];
    let output = render_search_match(&event, &fields, OutputFormat::Pretty, DisplayStyle::Color);

    assert!(
        output.contains("\u{1b}[2;36mevent.id\u{1b}[0m: \u{1b}[1m4625\u{1b}[0m"),
        "colored projected output should style field names and values, got:\n{output}"
    );
}

#[test]
fn pretty_search_delimiter_is_visible_and_colorable() {
    let plain = search_match_delimiter(OutputFormat::Pretty, DisplayStyle::Plain);
    let colored = search_match_delimiter(OutputFormat::Pretty, DisplayStyle::Color);

    assert!(
        plain.starts_with("--"),
        "plain pretty delimiter should be a visible rule, got: {plain}"
    );
    assert!(
        colored.starts_with("\u{1b}[2m"),
        "colored pretty delimiter should be dimmed, got: {colored:?}"
    );
    assert_eq!(
        search_match_delimiter(OutputFormat::Jsonl, DisplayStyle::Color),
        "",
        "machine formats should not add decorative delimiters"
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
