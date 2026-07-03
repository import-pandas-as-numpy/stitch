use std::{fs, path::PathBuf};

use serde_json::json;

use crate::cli::{CorrelationScope, HuntArgs, SearchArgs, SearchOutputFormat};
use crate::input::DiscoveredInput;

use super::*;

#[test]
fn reads_inline_query() {
    let args = SearchArgs {
        query: Some("event.id == 4625".to_owned()),
        query_file: None,
        fields: Vec::new(),
        format: SearchOutputFormat::Pretty,
        limit: None,
        errors: None,
        before_context: 0,
        after_context: 0,
        explain: false,
    };

    assert_eq!(
        read_query(&args).expect("inline query should be returned"),
        "event.id == 4625"
    );
}

#[test]
fn detects_reached_limit() {
    assert!(reached_limit(Some(2), 2));
    assert!(!reached_limit(Some(2), 1));
    assert!(!reached_limit(None, 100));
}

#[test]
fn cli_fields_override_keep_fields() {
    let args = SearchArgs {
        query: None,
        query_file: None,
        fields: vec!["provider".to_owned()],
        format: SearchOutputFormat::Pretty,
        limit: None,
        errors: None,
        before_context: 0,
        after_context: 0,
        explain: false,
    };
    let keep_fields = vec!["timestamp".to_owned()];

    assert_eq!(search_output_fields(&args, &keep_fields), ["provider"]);
}

#[test]
fn hunt_rule_filters_apply_level_status_tag_min_level_and_excludes() {
    let mut high_rule = SigmaRule::test_rule("High PowerShell Rule", Some("high".to_owned()));
    high_rule.path = PathBuf::from("rules/high.yml");
    high_rule.status = Some("test".to_owned());
    high_rule.tags = vec!["attack.execution".to_owned()];

    let mut medium_rule = SigmaRule::test_rule("Medium WMI Rule", Some("medium".to_owned()));
    medium_rule.path = PathBuf::from("rules/wmi.yml");
    medium_rule.status = Some("stable".to_owned());
    medium_rule.tags = vec!["attack.persistence".to_owned()];

    let mut low_rule = SigmaRule::test_rule("Low Noise Rule", Some("low".to_owned()));
    low_rule.path = PathBuf::from("rules/noise.yml");
    low_rule.status = Some("test".to_owned());
    low_rule.tags = vec!["attack.discovery".to_owned()];

    let rules = vec![high_rule, medium_rule, low_rule];
    let mut command = hunt_args();
    command.rule_status = vec!["test".to_owned()];
    command.min_level = Some("medium".to_owned());
    command.exclude_rule = vec!["*PowerShell*".to_owned()];

    let filtered = filter_hunt_rules(&command, &rules).expect("filters should be valid");

    assert!(
        filtered.is_empty(),
        "high test rule should be excluded by title glob, low test rule by min level"
    );

    command.rule_status.clear();
    command.tag = vec!["attack.persistence".to_owned()];

    let filtered = filter_hunt_rules(&command, &rules).expect("filters should be valid");

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].title, "Medium WMI Rule");
}

#[test]
fn hunt_plan_feeds_correlation_dependencies_even_when_alert_filtered() {
    let dependency_rule = SigmaRule::test_rule("Dependency Rule", Some("medium".to_owned()));
    let alert_rule = SigmaRule::test_rule("Alert Rule", Some("high".to_owned()));
    let rules = vec![dependency_rule, alert_rule];
    let correlations = vec![SigmaCorrelationRule {
        path: PathBuf::from("correlation.yml"),
        name: Some("dependency_correlation".to_owned()),
        title: "Dependency Correlation".to_owned(),
        id: None,
        status: Some("test".to_owned()),
        level: Some("high".to_owned()),
        tags: Vec::new(),
        correlation: crate::sigma::CorrelationDefinition {
            kind: crate::sigma::CorrelationKind::EventCount,
            referenced_rules: vec!["dependency_rule".to_owned()],
            group_by: Vec::new(),
            timespan: time::Duration::minutes(5),
            condition: Some(crate::sigma::CountCondition::test_gte(1)),
            value_fields: Vec::new(),
        },
    }];
    let mut command = hunt_args();
    command.min_level = Some("high".to_owned());

    let plan = build_hunt_plan(&command, &rules, &correlations).expect("plan should build");

    assert_eq!(plan.alert_rule_count, 1);
    assert_eq!(plan.rules.len(), 2);
    assert!(
        plan.rules
            .iter()
            .any(|rule| rule.rule.title == "Dependency Rule"
                && !rule.emit_alert
                && rule.feed_correlation),
        "filtered dependency rule should still feed correlation"
    );
    assert!(
        plan.rules.iter().any(|rule| rule.rule.title == "Alert Rule"
            && rule.emit_alert
            && !rule.feed_correlation),
        "non-referenced alert rule should not feed correlation"
    );
}

#[test]
fn hunt_plan_indexes_rules_by_required_event_id() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let event_rule = fixture.path().join("event-id.yml");
    let channel_rule = fixture.path().join("channel.yml");
    let channel_event_rule = fixture.path().join("channel-event-id.yml");
    let general_rule = fixture.path().join("general.yml");
    fs::write(
        &event_rule,
        r"
title: Event ID Rule
detection:
  selection:
    EventID: 4625
  condition: selection
",
    )
    .expect("event rule should be written");
    fs::write(
        &channel_rule,
        r"
title: Channel Rule
logsource:
  product: windows
  service: powershell
detection:
  selection:
    Event.EventData.ScriptBlockText|contains: admin
  condition: selection
",
    )
    .expect("channel rule should be written");
    fs::write(
        &channel_event_rule,
        r"
title: Channel And Event ID Rule
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
",
    )
    .expect("channel and event rule should be written");
    fs::write(
        &general_rule,
        r"
title: General Rule
detection:
  selection:
    Event.EventData.TargetUserName|contains: admin
  condition: selection
",
    )
    .expect("general rule should be written");
    let report = load_sigma_rules(&[fixture.path().to_path_buf()]).expect("rules should load");
    let command = hunt_args();

    let plan = build_hunt_plan(&command, &report.rules, &[]).expect("hunt plan should build");

    assert_eq!(plan.rules.len(), 4);
    assert_eq!(
        plan.event_id_rule_indices.get(&4625).map(Vec::len),
        Some(1),
        "event-id rule should be indexed by required EventID"
    );
    assert_eq!(
        plan.channel_rule_indices
            .get("microsoft-windows-powershell/operational")
            .map(Vec::len),
        Some(1),
        "channel-only rule should be indexed by normalized channel"
    );
    assert_eq!(
        plan.channel_event_id_rule_indices
            .get(&("security".to_owned(), 4624))
            .map(Vec::len),
        Some(1),
        "rule with channel and EventID constraints should use the combined index"
    );
    assert_eq!(
        plan.general_rule_indices.len(),
        1,
        "rule without required channel or EventID should remain in the general bucket"
    );
}

#[test]
fn hunt_plan_visits_only_matching_metadata_candidate_buckets() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let security_rule = fixture.path().join("security.yml");
    let sysmon_rule = fixture.path().join("sysmon.yml");
    let general_rule = fixture.path().join("general.yml");
    fs::write(
        &security_rule,
        r"
title: Security Logon Rule
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
",
    )
    .expect("security rule should be written");
    fs::write(
        &sysmon_rule,
        r"
title: Sysmon Rule
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
",
    )
    .expect("sysmon rule should be written");
    fs::write(
        &general_rule,
        r"
title: General Rule
detection:
  selection:
    Event.EventData.TargetUserName|contains: admin
  condition: selection
",
    )
    .expect("general rule should be written");
    let report = load_sigma_rules(&[fixture.path().to_path_buf()]).expect("rules should load");
    let command = hunt_args();
    let plan = build_hunt_plan(&command, &report.rules, &[]).expect("hunt plan should build");
    let event = hunt_test_event("Security", 4624);
    let mut visited = Vec::new();

    for_each_candidate_rule(&plan, &event, |planned_rule| {
        visited.push(planned_rule.rule.title.as_str());
    });

    assert_eq!(
        visited,
        ["General Rule", "Security Logon Rule"],
        "candidate loop should skip rules from other channel/EventID buckets"
    );
}

#[test]
fn stats_include_bounded_parse_error_samples() {
    let mut stats = SearchStats {
        scanned: 10,
        matched: 2,
        parse_errors: 10,
        parse_error_samples: Vec::new(),
    };
    let samples = (0..10)
        .map(|index| EvtxRecordError {
            path: format!("file-{index}.evtx"),
            message: "bad\nrecord".to_owned(),
        })
        .collect();

    stats.add_parse_error_samples(samples);

    let rendered = stats.render();
    assert!(
        rendered.contains("stats: scanned=10 matched=2 parse_errors=10"),
        "stats summary should include counts"
    );
    assert!(
        rendered.contains("parse_error: file=file-0.evtx error=bad record"),
        "stats should include a readable parse error sample"
    );
    assert!(
        !rendered.contains("file-5.evtx"),
        "stats should cap parse error samples"
    );
}

#[test]
fn search_error_writer_emits_jsonl() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let path = directory.path().join("parse-errors.jsonl");
    let mut writer = ErrorWriter::new(Some(&path)).expect("writer should be created");

    writer.write(&EvtxRecordError {
        path: "Security.evtx".to_owned(),
        message: "bad record".to_owned(),
    });
    writer.finish().expect("writer should flush");

    let output = fs::read_to_string(path).expect("error file should be readable");
    let value: serde_json::Value =
        serde_json::from_str(output.trim()).expect("error line should be JSON");
    assert_eq!(value["file_path"], "Security.evtx");
    assert_eq!(value["error"], "bad record");
}

#[test]
fn hunt_jsonl_output_includes_rule_and_event_identity() {
    let rule = SigmaRule::test_rule("Suspicious Process", Some("high".to_owned()));
    let event = Event::from_raw(
        &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
        Some(42),
        json!({
            "Event": {
                "System": {
                    "EventID": 4688,
                    "Channel": "Security",
                    "Computer": "WIN-01",
                    "Provider": { "Name": "Microsoft-Windows-Security-Auditing" },
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-06-27T12:00:00Z"
                        }
                    }
                }
            }
        }),
    );

    let output = render_hunt_match(&rule, &event, OutputFormat::Jsonl, false);
    let value: serde_json::Value =
        serde_json::from_str(&output).expect("hunt JSONL should be valid JSON");

    assert_eq!(value["rule"]["title"], "Suspicious Process");
    assert_eq!(value["rule"]["level"], "high");
    assert_eq!(value["event"]["event_id"], 4688);
    assert_eq!(value["event"]["computer"], "WIN-01");
    assert_eq!(value["event"]["source"]["file_path"], "Security.evtx");
}

#[test]
fn hunt_pretty_output_is_tabular_with_concise_payload() {
    let rule = SigmaRule::test_rule("Suspicious Process", Some("high".to_owned()));
    let event = Event::from_raw(
        &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
        Some(42),
        json!({
            "Event": {
                "System": {
                    "EventID": 4688,
                    "Channel": "Security",
                    "Computer": "WIN-01",
                    "Provider": { "Name": "Microsoft-Windows-Security-Auditing" },
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-06-27T12:00:00Z"
                        }
                    }
                },
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -NoProfile"
                }
            }
        }),
    );

    let output = render_hunt_match(&rule, &event, OutputFormat::Pretty, false);

    assert!(output.contains("│ Timestamp"));
    assert!(output.contains("│ Detections"));
    assert!(output.contains("│ Event"));
    assert!(output.contains("Suspicious Process"));
    assert!(output.contains("│ 4688/42"));
    assert!(!output.contains("│ Channel"));
    assert!(!output.contains("│ File"));
    assert!(output.contains("│ Payload"));
    assert!(output.contains("CommandLine:"));
    assert!(output.contains("powershell.exe -NoProfile"));
    assert!(
        !output.contains("SystemTime:"),
        "hunt payload should stay focused on event data"
    );
}

#[test]
fn hunt_full_pretty_output_includes_source_columns() {
    let rule = SigmaRule::test_rule("Suspicious Process", Some("high".to_owned()));
    let event = Event::from_raw(
        &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
        Some(42),
        json!({
            "Event": {
                "System": {
                    "EventID": 4688,
                    "Channel": "Security",
                    "Computer": "WIN-01",
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-06-27T12:00:00Z"
                        }
                    }
                },
                "EventData": {
                    "CommandLine": "powershell.exe -NoProfile"
                }
            }
        }),
    );

    let output = render_hunt_match(&rule, &event, OutputFormat::Pretty, true);

    assert!(output.contains("│ Channel"));
    assert!(output.contains("│ File"));
    assert!(output.contains("Security.evtx"));
    assert!(output.contains("│ 4688/42"));
}

#[test]
fn hunt_pretty_table_stays_aligned_with_embedded_newlines() {
    let rule = SigmaRule::test_rule("Suspicious Process With Unicode σ", Some("high".to_owned()));
    let event = Event::from_raw(
        &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
        Some(42),
        json!({
            "Event": {
                "System": {
                    "EventID": 4688,
                    "Channel": "Microsoft-Windows-Security-Auditing/Operational",
                    "Computer": "WIN-01",
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-06-27T12:00:00Z"
                        }
                    }
                },
                "EventData": {
                    "CommandLine": "first line\nsecond line with a veryveryveryveryveryverylongtoken",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                }
            }
        }),
    );

    let output = render_hunt_match(&rule, &event, OutputFormat::Pretty, false);
    let lines = output.lines().collect::<Vec<_>>();
    let expected_width = text_width(lines[0]);

    for line in lines {
        assert_eq!(
            text_width(line),
            expected_width,
            "table line should stay aligned after renderer-controlled wrapping:\n{output}"
        );
    }

    assert!(
        output.contains(r"first line\nsecond line"),
        "embedded payload newlines should be escaped inside the payload cell:\n{output}"
    );
}

fn hunt_args() -> HuntArgs {
    HuntArgs {
        rules: Vec::new(),
        mapping: None,
        rule_status: Vec::new(),
        level: Vec::new(),
        tag: Vec::new(),
        exclude_rule: Vec::new(),
        enable_correlation: false,
        disable_correlation: false,
        correlation_scope: CorrelationScope::Host,
        correlation_lateness: "2m".to_owned(),
        correlation_max_state: 100_000,
        correlation_event_fields: Vec::new(),
        correlation_event_limit: 3,
        format: OutputFormat::Pretty,
        full: false,
        output: None,
        min_level: None,
        summary: false,
    }
}

fn hunt_test_event(channel: &str, event_id: u64) -> Event {
    Event::from_raw(
        &DiscoveredInput::new(PathBuf::from("test.evtx"), PathBuf::from(".")),
        Some(1),
        json!({
            "Event": {
                "System": {
                    "EventID": event_id,
                    "Channel": channel,
                    "Computer": "WIN-01"
                }
            }
        }),
    )
}
