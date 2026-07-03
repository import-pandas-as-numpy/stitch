use serde_json::json;

use crate::input::DiscoveredInput;

use super::*;

#[test]
fn loads_regular_rules_and_correlation_documents() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        fixture.path().join("process_creation.yml"),
        r"
title: Suspicious Process
name: suspicious_process
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
tags:
  - attack.execution
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
",
    )
    .expect("regular rule should be written");
    fs::write(
        fixture.path().join("correlation.yml"),
        r"
---
title: Many Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - suspicious_process
  condition:
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation rule should be written");
    fs::write(fixture.path().join("ignored.txt"), "not yaml")
        .expect("ignored file should be written");

    let report = load_sigma_rules(&[fixture.path().to_path_buf()])
        .expect("rules should load from directory");

    assert_eq!(report.rules.len(), 1);
    assert_eq!(report.rules[0].title, "Suspicious Process");
    assert_eq!(report.rules[0].level.as_deref(), Some("high"));
    assert_eq!(report.rules[0].tags, ["attack.execution"]);
    assert_eq!(report.correlations.len(), 1);
    assert_eq!(report.correlations[0].title, "Many Failed Logons");
    assert_eq!(
        report.correlations[0].correlation.kind,
        CorrelationKind::EventCount
    );
    assert_eq!(
        report.correlations[0].correlation.referenced_rules,
        ["suspicious_process"]
    );
    assert_eq!(
        report.correlations[0].correlation.timespan,
        Duration::minutes(5)
    );
    assert_eq!(
        report.correlations[0].correlation.condition,
        Some(CountCondition {
            operator: CountOperator::GreaterThanOrEqual,
            threshold: 2
        })
    );
    assert!(report.correlations[0].correlation.value_fields.is_empty());
}

#[test]
fn loads_sigma_syntax_valid_fixtures() {
    let path = PathBuf::from("tests/fixtures/sigma-syntax/valid");
    let report = load_sigma_rules(&[path]).expect("valid Sigma syntax fixtures should load");

    assert_eq!(
        report.rules.len(),
        5,
        "valid syntax fixtures should include base Sigma rules"
    );
    assert_eq!(
        report.correlations.len(),
        4,
        "valid syntax fixtures should include correlation rules"
    );
    assert!(
        report
            .rules
            .iter()
            .any(|rule| rule.name.as_deref() == Some("syntax_base_modifiers")),
        "valid fixtures should load modifier-heavy base rule"
    );
    assert!(
        report
            .rules
            .iter()
            .any(|rule| rule.name.as_deref() == Some("syntax_alternatives_keywords")),
        "valid fixtures should load alternatives and keyword base rule"
    );
    assert!(
        report
            .correlations
            .iter()
            .any(|rule| rule.correlation.kind == CorrelationKind::EventCount),
        "valid fixtures should include event_count correlation"
    );
    assert!(
        report
            .correlations
            .iter()
            .any(|rule| rule.correlation.kind == CorrelationKind::ValueCount),
        "valid fixtures should include value_count correlation"
    );
    assert!(
        report
            .correlations
            .iter()
            .any(|rule| rule.correlation.kind == CorrelationKind::Temporal),
        "valid fixtures should include temporal correlation"
    );
    assert!(
        report
            .correlations
            .iter()
            .any(|rule| rule.correlation.kind == CorrelationKind::TemporalOrdered),
        "valid fixtures should include temporal_ordered correlation"
    );
}

#[test]
fn rejects_sigma_syntax_invalid_fixtures_with_readable_errors() {
    let cases = [
        ("base_missing_condition.yml", "missing detection condition"),
        ("base_unknown_selection.yml", "unknown selection"),
        (
            "base_unsupported_modifier_typo.yml",
            "unsupported Sigma modifier",
        ),
        (
            "base_bad_condition_pattern.yml",
            "does not match any selections",
        ),
        ("correlation_missing_rules.yml", "non-empty rules list"),
        (
            "correlation_bad_type_typo.yml",
            "unsupported correlation type",
        ),
        (
            "correlation_value_count_missing_field.yml",
            "condition field",
        ),
        (
            "correlation_bad_timespan.yml",
            "invalid correlation timespan",
        ),
        (
            "correlation_bad_condition_operator.yml",
            "unsupported correlation condition key",
        ),
    ];

    for (fixture, expected) in cases {
        let path = PathBuf::from("tests/fixtures/sigma-syntax/invalid").join(fixture);
        let error = load_sigma_rules(std::slice::from_ref(&path))
            .expect_err("invalid Sigma syntax fixture should fail");
        let message = error.to_string();

        assert!(
            matches!(error, SigmaLoadError::UnsupportedRule { .. }),
            "{fixture} should fail as an unsupported Sigma rule, got {error:?}"
        );
        assert!(
            message.contains(expected),
            "{fixture} should mention {expected:?}, got {message:?}"
        );
    }

    let malformed_path =
        PathBuf::from("tests/fixtures/sigma-syntax/invalid/base_malformed_yaml.yml");
    let malformed_error =
        load_sigma_rules(&[malformed_path]).expect_err("malformed Sigma YAML fixture should fail");

    assert!(
        matches!(malformed_error, SigmaLoadError::RuleParse { .. }),
        "malformed YAML should fail during YAML parsing, got {malformed_error:?}"
    );
}

#[test]
fn non_strict_loader_skips_invalid_rule_files_and_continues() {
    let path = PathBuf::from("tests/fixtures/sigma-syntax");
    let report =
        load_sigma_rules_non_strict(&[path]).expect("non-strict loading should skip bad rules");

    assert_eq!(
        report.rules.len(),
        5,
        "non-strict loading should keep valid base rules"
    );
    assert_eq!(
        report.correlations.len(),
        4,
        "non-strict loading should keep valid correlation rules"
    );
    assert_eq!(
        report.skipped_rules, 10,
        "non-strict loading should count invalid YAML rule files"
    );
}

#[test]
fn temporal_ordered_correlation_emits_when_references_match_in_order() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("ordered_sequence.yml");
    fs::write(
        &path,
        r"
---
title: Process Start
name: process_start
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Process Network
name: process_network
detection:
  selection:
    EventID: 3
  condition: selection
---
title: Process File Write
name: process_file_write
detection:
  selection:
    EventID: 11
  condition: selection
---
title: Process Network Then File Sequence
type: correlation
correlation:
  type: temporal_ordered
  rules:
    - process_start
    - process_network
    - process_file_write
  group-by:
    - ProcessGuid
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
    let start = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));
    let network = test_event(json!({
        "Event": {
            "System": {
                "EventID": 3,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));
    let file_write = test_event(json!({
        "Event": {
            "System": {
                "EventID": 11,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:02:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &start, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[1], &network, &[])
            .is_empty()
    );

    let matches = engine.observe_match(&report.rules[2], &file_write, &[]);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule.title, "Process Network Then File Sequence");
    assert_eq!(matches[0].matches.len(), 3);
    assert_eq!(matches[0].window_start, "2026-06-28T12:00:00Z");
    assert_eq!(matches[0].window_end, "2026-06-28T12:02:00Z");
}

#[test]
fn temporal_ordered_correlation_rejects_out_of_order_references() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("ordered_sequence.yml");
    fs::write(
        &path,
        r"
---
title: First Event
name: first_event
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Second Event
name: second_event
detection:
  selection:
    EventID: 3
  condition: selection
---
title: Ordered Sequence
type: correlation
correlation:
  type: temporal_ordered
  rules:
    - first_event
    - second_event
  group-by:
    - ProcessGuid
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
    let second = test_event(json!({
        "Event": {
            "System": {
                "EventID": 3,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));
    let first = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[1], &second, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[0], &first, &[])
            .is_empty()
    );
}

#[test]
fn temporal_correlation_matches_references_in_any_order() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("unordered_sequence.yml");
    fs::write(
        &path,
        r"
---
title: First Event
name: first_event
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Second Event
name: second_event
detection:
  selection:
    EventID: 3
  condition: selection
---
title: Unordered Sequence
type: correlation
correlation:
  type: temporal
  rules:
    - first_event
    - second_event
  group-by:
    - ProcessGuid
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
    let second = test_event(json!({
        "Event": {
            "System": {
                "EventID": 3,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));
    let first = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[1], &second, &[])
            .is_empty()
    );

    let matches = engine.observe_match(&report.rules[0], &first, &[]);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule.title, "Unordered Sequence");
}

#[test]
fn correlation_max_state_evicts_oldest_state_group() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("state_limit.yml");
    fs::write(
        &path,
        r"
---
title: Process Start
name: process_start
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Repeated Process Starts
type: correlation
correlation:
  type: event_count
  rules:
    - process_start
  group-by:
    - ProcessGuid
  condition:
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 1);
    let first_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));
    let second_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
            },
            "EventData": { "ProcessGuid": "{22222222-2222-2222-2222-222222222222}" }
        }
    }));
    let first_group_again = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:02:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &first_group, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[0], &second_group, &[])
            .is_empty()
    );
    assert_eq!(
        engine.stats(),
        SigmaCorrelationStats {
            state_entries: 1,
            evicted_state_entries: 1
        }
    );

    let matches = engine.observe_match(&report.rules[0], &first_group_again, &[]);

    assert!(
        matches.is_empty(),
        "oldest group should be evicted before it can reach threshold"
    );
    assert_eq!(
        engine.stats(),
        SigmaCorrelationStats {
            state_entries: 1,
            evicted_state_entries: 2
        }
    );
}

#[test]
fn host_scoped_correlation_does_not_mix_hosts() {
    let report = repeated_process_correlation_report();
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
    let first_host = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));
    let second_host = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-02",
                "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &first_host, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[0], &second_host, &[])
            .is_empty(),
        "host scope must not correlate matching group-by values across computers"
    );
    assert_eq!(
        engine.stats(),
        SigmaCorrelationStats {
            state_entries: 2,
            evicted_state_entries: 0
        }
    );
}

#[test]
fn global_scoped_correlation_can_match_across_hosts() {
    let report = repeated_process_correlation_report();
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Global, 100);
    let first_host = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));
    let second_host = test_event(json!({
        "Event": {
            "System": {
                "EventID": 1,
                "Computer": "WIN-02",
                "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
            },
            "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &first_host, &[])
            .is_empty()
    );

    let matches = engine.observe_match(&report.rules[0], &second_host, &[]);

    assert_eq!(
        matches.len(),
        1,
        "global scope should allow cross-host correlation when group-by fields match"
    );
    assert_eq!(
        matches[0].group,
        [(
            "ProcessGuid".to_owned(),
            "{11111111-1111-1111-1111-111111111111}".to_owned()
        )]
    );
}

#[test]
fn reports_invalid_yaml_with_rule_path() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("broken.yml");
    fs::write(&path, "title: [").expect("broken rule should be written");

    let error =
        load_sigma_rules(std::slice::from_ref(&path)).expect_err("invalid YAML should fail");

    assert!(
        matches!(error, SigmaLoadError::RuleParse { path: error_path, .. } if error_path == path),
        "invalid YAML should report the rule path"
    );
}

#[test]
fn evaluates_simple_selection_against_event() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("failed_logon.yml");
    fs::write(
        &path,
        r"
title: Failed Logon
detection:
  selection:
    EventID: 4625
    Event.EventData.TargetUserName: alice.admin
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let matching = test_event(json!({
        "Event": {
            "System": { "EventID": 4625 },
            "EventData": { "TargetUserName": "alice.admin" }
        }
    }));
    let non_matching = test_event(json!({
        "Event": {
            "System": { "EventID": 4625 },
            "EventData": { "TargetUserName": "bob.admin" }
        }
    }));

    assert!(report.rules[0].matches(&matching));
    assert!(!report.rules[0].matches(&non_matching));
}

#[test]
fn sigma_rules_extract_safe_metadata_prefilters() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("metadata_prefilter.yml");
    fs::write(
        &path,
        r"
title: Security Admin Logon
detection:
  selection:
    EventID: 4625
    Channel: Security
    Computer: WIN-01
    Event.EventData.TargetUserName|contains: admin
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let matching = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Channel": "Security",
                "Computer": "WIN-01"
            },
            "EventData": { "TargetUserName": "alice.admin" }
        }
    }));
    let wrong_metadata = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4624,
                "Channel": "Security",
                "Computer": "WIN-01"
            },
            "EventData": { "TargetUserName": "alice.admin" }
        }
    }));

    assert_eq!(
        report.rules[0].metadata_prefilter_count(),
        3,
        "EventID, Channel, and Computer should become safe metadata prefilters"
    );
    assert!(report.rules[0].matches(&matching));
    assert!(!report.rules[0].matches(&wrong_metadata));
}

#[test]
fn sigma_logsource_service_filters_events_by_channel() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("security_logsource.yml");
    fs::write(
        &path,
        r"
title: Security Failed Logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let security_event = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Channel": "Security"
            }
        }
    }));
    let sysmon_event = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Channel": "Microsoft-Windows-Sysmon/Operational"
            }
        }
    }));

    assert_eq!(
        report.rules[0].logsource_prefilter_count(),
        1,
        "security service should compile to one channel prefilter"
    );
    assert!(report.rules[0].matches(&security_event));
    assert!(
        !report.rules[0].matches(&sysmon_event),
        "same detection should not match events from a filtered-out channel"
    );
}

#[test]
fn sigma_logsource_unknown_service_does_not_filter() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("unknown_logsource.yml");
    fs::write(
        &path,
        r"
title: Unknown Service Rule
logsource:
  product: windows
  service: custom-service
detection:
  selection:
    EventID: 4625
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Channel": "Security"
            }
        }
    }));

    assert_eq!(
        report.rules[0].logsource_prefilter_count(),
        0,
        "unknown services should stay unfiltered instead of dropping possible matches"
    );
    assert!(report.rules[0].matches(&event));
}

#[test]
fn sigma_prefilters_skip_or_and_multi_alternative_selections() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("unsafe_prefilter.yml");
    fs::write(
        &path,
        r"
title: Multi Branch Rule
detection:
  selection_a:
    EventID: 4625
  selection_b:
    Channel: Security
  selection_c:
    - EventID: 4688
    - Computer: WIN-01
  condition: selection_a or selection_b or selection_c
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4624,
                "Channel": "Security",
                "Computer": "WIN-02"
            }
        }
    }));

    assert_eq!(
        report.rules[0].metadata_prefilter_count(),
        0,
        "or branches and multi-alternative selections should not become required prefilters"
    );
    assert!(
        report.rules[0].matches(&event),
        "full Sigma condition should still match through selection_b"
    );
}

#[test]
fn evaluates_selection_lists_against_event() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("logon_events.yml");
    fs::write(
        &path,
        r"
title: Logon Events
detection:
  selection:
    EventID:
      - 4624
      - 4625
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "System": { "EventID": 4624 }
        }
    }));

    assert!(report.rules[0].matches(&event));
}

#[test]
fn sigma_event_context_can_be_reused_across_keyword_rules() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("keyword_rules.yml");
    fs::write(
        &path,
        r"
---
title: PowerShell Keyword
detection:
  selection:
    - powershell.exe
  condition: selection
---
title: Command Line Keyword
detection:
  selection:
    - NoProfile
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let event = test_event(json!({
        "Event": {
            "System": { "EventID": 4688 },
            "EventData": {
                "CommandLine": "powershell.exe -NoProfile"
            }
        }
    }));
    let context = SigmaEventContext::new(&event);

    assert_eq!(report.rules.len(), 2);
    assert!(
        report
            .rules
            .iter()
            .all(|rule| rule.matches_context(&context)),
        "one event context should be reusable across keyword-heavy rule checks"
    );
}

#[test]
fn evaluates_boolean_detection_conditions() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("boolean_condition.yml");
    fs::write(
        &path,
        r"
title: Boolean Condition
detection:
  selection_logon:
    EventID: 4624
  selection_user:
    Event.EventData.TargetUserName: alice.admin
  filter_machine:
    Event.EventData.TargetUserName: machine$
  condition: selection_logon and (selection_user or not filter_machine)
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let matching_user = test_event(json!({
        "Event": {
            "System": { "EventID": 4624 },
            "EventData": { "TargetUserName": "alice.admin" }
        }
    }));
    let matching_non_machine = test_event(json!({
        "Event": {
            "System": { "EventID": 4624 },
            "EventData": { "TargetUserName": "bob.admin" }
        }
    }));
    let filtered_machine = test_event(json!({
        "Event": {
            "System": { "EventID": 4624 },
            "EventData": { "TargetUserName": "machine$" }
        }
    }));
    let wrong_event_id = test_event(json!({
        "Event": {
            "System": { "EventID": 4625 },
            "EventData": { "TargetUserName": "alice.admin" }
        }
    }));

    assert!(report.rules[0].matches(&matching_user));
    assert!(report.rules[0].matches(&matching_non_machine));
    assert!(!report.rules[0].matches(&filtered_machine));
    assert!(!report.rules[0].matches(&wrong_event_id));
}

#[test]
fn rejects_conditions_that_reference_unknown_selections() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("unknown_selection.yml");
    fs::write(
        &path,
        r"
title: Unknown Selection
detection:
  selection:
    EventID: 4624
  condition: selection and missing
",
    )
    .expect("rule should be written");

    let error = load_sigma_rules(&[path]).expect_err("unknown selection should fail");

    assert!(
        matches!(error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("unknown selection")),
        "unknown condition selections should be reported clearly"
    );
}

#[test]
fn evaluates_common_string_modifiers() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("modifiers.yml");
    fs::write(
        &path,
        r"
title: Modifier Rule
detection:
  selection:
    Event.EventData.CommandLine|contains|all:
      - powershell
      - encoded
    Event.EventData.Image|endswith: powershell.exe
    Event.EventData.ParentImage|startswith: C:\Windows
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let matching = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "powershell.exe -encodedcommand abc",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentImage": "C:\\Windows\\explorer.exe"
            }
        }
    }));
    let missing_all_value = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "powershell.exe",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentImage": "C:\\Windows\\explorer.exe"
            }
        }
    }));

    assert!(report.rules[0].matches(&matching));
    assert!(!report.rules[0].matches(&missing_all_value));
}

#[test]
fn sigma_string_matching_is_case_insensitive_unless_cased() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("case.yml");
    fs::write(
        &path,
        r"
title: Case Matching
detection:
  selection_default:
    EventID: 4688
    Image|endswith: POWERSHELL.EXE
    CommandLine|contains: noprofile
  selection_cased:
    EventID: 4688
    Image|endswith|cased: POWERSHELL.EXE
  condition: selection_default and not selection_cased
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "System": { "EventID": 4688 },
            "EventData": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile"
            }
        }
    }));

    assert!(report.rules[0].matches(&event));
}

#[test]
fn evaluates_condition_lists_as_or_expressions() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("condition_list.yml");
    fs::write(
        &path,
        r"
title: Condition List
detection:
  selection_process:
    EventID: 4688
  selection_dns:
    EventID: 22
  condition:
    - selection_process
    - selection_dns
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "System": { "EventID": 22 }
        }
    }));

    assert!(report.rules[0].matches(&event));
}

#[test]
fn evaluates_lists_of_maps_as_or_alternatives() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("map_list.yml");
    fs::write(
        &path,
        r"
title: Map List
detection:
  selection:
    - EventID: 1
      Image|endswith: powershell.exe
    - EventID: 11
      TargetFilename|endswith: payload.bin
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "System": { "EventID": 11 },
            "EventData": {
                "TargetFilename": "C:\\ProgramData\\Example\\payload.bin"
            }
        }
    }));

    assert!(report.rules[0].matches(&event));
}

#[test]
fn evaluates_keyword_searches_and_all_keyword_lists() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("keywords.yml");
    fs::write(
        &path,
        r"
title: Keywords
detection:
  keywords_any:
    - Invoke-WebRequest
    - encodedcommand
  keywords_all:
    '|all':
      - powershell.exe
      - NoProfile
  condition: keywords_any and keywords_all
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "System": { "EventID": 4104 },
            "EventData": {
                "ScriptBlockText": "powershell.exe -NoProfile; Invoke-WebRequest -Uri http://example.invalid"
            }
        }
    }));
    let missing_all = test_event(json!({
        "Event": {
            "System": { "EventID": 4104 },
            "EventData": {
                "ScriptBlockText": "Invoke-WebRequest -Uri http://example.invalid"
            }
        }
    }));

    assert!(report.rules[0].matches(&event));
    assert!(!report.rules[0].matches(&missing_all));
}

#[test]
fn evaluates_null_values_and_wildcard_string_patterns() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("null_wildcards.yml");
    fs::write(
        &path,
        r"
title: Null Wildcards
detection:
  selection:
    CommandLine: '*-NoProfile*'
    MissingField: null
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "powershell.exe -NoProfile"
            }
        }
    }));
    let non_matching = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "powershell.exe -File collect.ps1",
                "MissingField": "present"
            }
        }
    }));

    assert!(report.rules[0].matches(&event));
    assert!(!report.rules[0].matches(&non_matching));
}

#[test]
fn evaluates_exists_neq_numeric_and_fieldref_modifiers() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("generic_modifiers.yml");
    fs::write(
        &path,
        r"
title: Generic Modifiers
detection:
  selection:
    OptionalField|exists: false
    CommandLine|neq: cmd.exe
    ProcessId|gte: 1000
    ProcessId|lt: 6000
    SubjectUserName|fieldref: TargetUserName
    ParentProcessId|fieldref|neq: ProcessId
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "powershell.exe -NoProfile",
                "ProcessId": "5104",
                "ParentProcessId": "3888",
                "SubjectUserName": "operator",
                "TargetUserName": "operator"
            }
        }
    }));
    let wrong = test_event(json!({
        "Event": {
            "EventData": {
                "OptionalField": "present",
                "CommandLine": "cmd.exe",
                "ProcessId": "7000",
                "ParentProcessId": "7000",
                "SubjectUserName": "operator",
                "TargetUserName": "admin"
            }
        }
    }));

    assert!(report.rules[0].matches(&event));
    assert!(!report.rules[0].matches(&wrong));
}

#[test]
fn evaluates_regex_flags_time_and_windash_modifiers() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("regex_time_windash.yml");
    fs::write(
        &path,
        r"
title: Regex Time Windash
detection:
  selection:
    CommandLine|windash|contains: -NoProfile
    ScriptBlockText|re|i|s: invoke-webrequest.+payload\.bin
    TimeCreated|hour: 10
    TimeCreated|minute: 6
    TimeCreated|year: 2026
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "powershell.exe /NoProfile",
                "ScriptBlockText": "Invoke-WebRequest\n-OutFile payload.bin",
                "TimeCreated": "2026-01-15T10:06:04Z"
            }
        }
    }));

    assert!(report.rules[0].matches(&event));
}

#[test]
fn evaluates_encoding_modifiers() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("encoding.yml");
    fs::write(
        &path,
        r"
title: Encoding
detection:
  selection:
    EncodedCommand|contains|base64: powershell
    Utf16Hex|contains|utf16le: cmd
    Utf16BomHex|contains|utf16: cmd
    OffsetEncoded|contains|base64offset: cmd
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let event = test_event(json!({
        "Event": {
            "EventData": {
                "EncodedCommand": "cG93ZXJzaGVsbA==",
                "Utf16Hex": "63006d006400",
                "Utf16BomHex": "fffe63006d006400",
                "OffsetEncoded": "AGN DBA== Y21k"
            }
        }
    }));

    assert!(report.rules[0].matches(&event));
}

#[test]
fn rejects_unsupported_modifiers() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("unsupported_modifier.yml");
    fs::write(
        &path,
        r"
title: Unsupported Modifier
detection:
  selection:
    Event.EventData.CommandLine|unknownmodifier: powershell
  condition: selection
",
    )
    .expect("rule should be written");

    let error = load_sigma_rules(&[path]).expect_err("unsupported modifier should fail");

    assert!(
        matches!(error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("unsupported Sigma modifier")),
        "unsupported modifiers should be reported clearly"
    );
}

#[test]
fn evaluates_regex_and_cidr_modifiers() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("regex_cidr.yml");
    fs::write(
        &path,
        r"
title: Regex Cidr
detection:
  selection:
    Event.EventData.CommandLine|re: (?i)powershell(\.exe)?
    Event.EventData.SourceIp|cidr:
      - 10.0.0.0/8
      - 192.168.0.0/16
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let matching = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "PowerShell.exe -NoProfile",
                "SourceIp": "10.1.2.3"
            }
        }
    }));
    let non_matching = test_event(json!({
        "Event": {
            "EventData": {
                "CommandLine": "cmd.exe",
                "SourceIp": "10.1.2.3"
            }
        }
    }));

    assert!(report.rules[0].matches(&matching));
    assert!(!report.rules[0].matches(&non_matching));
}

#[test]
fn maps_common_windows_sigma_fields_to_evtx_event_data() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("windows_fields.yml");
    fs::write(
        &path,
        r"
title: Windows Field Aliases
detection:
  selection:
    EventID: 3
    Image|endswith: powershell.exe
    CommandLine|contains: NoProfile
    DestinationIp|cidr: 203.0.113.0/24
  condition: selection
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let matching = test_event(json!({
        "Event": {
            "System": { "EventID": 3 },
            "EventData": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile",
                "DestinationIp": "203.0.113.55"
            }
        }
    }));
    let wrong_network = test_event(json!({
        "Event": {
            "System": { "EventID": 3 },
            "EventData": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile",
                "DestinationIp": "198.51.100.55"
            }
        }
    }));

    assert!(report.rules[0].matches(&matching));
    assert!(!report.rules[0].matches(&wrong_network));
}

#[test]
fn rejects_invalid_regex_and_cidr_modifier_values() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let regex_path = fixture.path().join("invalid_regex.yml");
    fs::write(
        &regex_path,
        r"
title: Invalid Regex
detection:
  selection:
    Event.EventData.CommandLine|re: (
  condition: selection
",
    )
    .expect("rule should be written");
    let cidr_path = fixture.path().join("invalid_cidr.yml");
    fs::write(
        &cidr_path,
        r"
title: Invalid Cidr
detection:
  selection:
    Event.EventData.SourceIp|cidr: 10.0.0.0/33
  condition: selection
",
    )
    .expect("rule should be written");

    let regex_error = load_sigma_rules(&[regex_path]).expect_err("invalid regex should fail");
    let cidr_error = load_sigma_rules(&[cidr_path]).expect_err("invalid CIDR should fail");

    assert!(
        matches!(regex_error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("invalid Sigma regex")),
        "invalid regex modifier values should be reported clearly"
    );
    assert!(
        matches!(cidr_error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("invalid Sigma CIDR")),
        "invalid CIDR modifier values should be reported clearly"
    );
}

#[test]
fn evaluates_one_of_selection_patterns() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("one_of.yml");
    fs::write(
        &path,
        r"
title: One Of
detection:
  selection_a:
    EventID: 4624
  selection_b:
    EventID: 4625
  filter:
    Event.EventData.TargetUserName: machine$
  condition: 1 of selection_*
",
    )
    .expect("rule should be written");
    let report = load_sigma_rules(&[path]).expect("rule should load");
    let matching = test_event(json!({
        "Event": {
            "System": { "EventID": 4625 }
        }
    }));
    let non_matching = test_event(json!({
        "Event": {
            "System": { "EventID": 4672 }
        }
    }));

    assert!(report.rules[0].matches(&matching));
    assert!(!report.rules[0].matches(&non_matching));
}

#[test]
fn evaluates_all_of_selection_patterns_and_them() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let all_path = fixture.path().join("all_of.yml");
    fs::write(
        &all_path,
        r"
title: All Of
detection:
  selection_event:
    EventID: 4624
  selection_user:
    Event.EventData.TargetUserName: alice.admin
  condition: all of selection_*
",
    )
    .expect("all-of rule should be written");
    let them_path = fixture.path().join("them.yml");
    fs::write(
        &them_path,
        r"
title: Them
detection:
  first:
    EventID: 4624
  second:
    Event.EventData.TargetUserName: alice.admin
  condition: 1 of them
",
    )
    .expect("them rule should be written");
    let report = load_sigma_rules(&[fixture.path().to_path_buf()]).expect("rules should load");
    let all_rule = report
        .rules
        .iter()
        .find(|rule| rule.title == "All Of")
        .expect("all-of rule should be loaded");
    let them_rule = report
        .rules
        .iter()
        .find(|rule| rule.title == "Them")
        .expect("them rule should be loaded");
    let matching = test_event(json!({
        "Event": {
            "System": { "EventID": 4624 },
            "EventData": { "TargetUserName": "alice.admin" }
        }
    }));
    let partial = test_event(json!({
        "Event": {
            "System": { "EventID": 4624 },
            "EventData": { "TargetUserName": "bob.admin" }
        }
    }));

    assert!(all_rule.matches(&matching));
    assert!(!all_rule.matches(&partial));
    assert!(them_rule.matches(&partial));
}

#[test]
fn rejects_condition_patterns_that_match_no_selections() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("missing_pattern.yml");
    fs::write(
        &path,
        r"
title: Missing Pattern
detection:
  selection:
    EventID: 4624
  condition: 1 of missing_*
",
    )
    .expect("rule should be written");

    let error = load_sigma_rules(&[path]).expect_err("missing pattern should fail");

    assert!(
        matches!(error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("does not match any selections")),
        "missing selection patterns should be reported clearly"
    );
}

#[test]
fn event_count_correlation_emits_when_grouped_window_reaches_threshold() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("failed_logon_correlation.yml");
    fs::write(
        &path,
        r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
    let first = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));
    let second = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));

    assert!(report.rules[0].matches(&first));
    assert!(
        engine
            .observe_match(&report.rules[0], &first, &[])
            .is_empty()
    );

    let matches = engine.observe_match(&report.rules[0], &second, &[]);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule.title, "Repeated Failed Logons");
    assert_eq!(
        matches[0].group,
        [
            ("scope.host".to_owned(), "WIN-01".to_owned()),
            ("TargetUserName".to_owned(), "alice".to_owned())
        ]
    );
    assert_eq!(matches[0].matches.len(), 2);
    assert_eq!(matches[0].window_start, "2026-06-28T12:00:00Z");
    assert_eq!(matches[0].window_end, "2026-06-28T12:04:00Z");
}

#[test]
fn correlation_lateness_allows_bounded_out_of_order_matches() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("bounded_lateness.yml");
    fs::write(
        &path,
        r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine = SigmaCorrelationEngine::new_with_lateness(
        &report.correlations,
        CorrelationRuntimeScope::Host,
        100,
        Duration::minutes(3),
    );
    let first = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));
    let future_other_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:07:00Z" }
            },
            "EventData": { "TargetUserName": "bob" }
        }
    }));
    let late_same_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &first, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[0], &future_other_group, &[])
            .is_empty()
    );

    let matches = engine.observe_match(&report.rules[0], &late_same_group, &[]);

    assert_eq!(
        matches.len(),
        1,
        "late event within allowed lateness should still complete the correlation"
    );
    assert_eq!(matches[0].window_start, "2026-06-28T12:00:00Z");
    assert_eq!(matches[0].window_end, "2026-06-28T12:04:00Z");
}

#[test]
fn correlation_lateness_drops_events_older_than_watermark() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("late_drop.yml");
    fs::write(
        &path,
        r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine = SigmaCorrelationEngine::new_with_lateness(
        &report.correlations,
        CorrelationRuntimeScope::Host,
        100,
        Duration::minutes(1),
    );
    let first = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));
    let future_other_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:07:00Z" }
            },
            "EventData": { "TargetUserName": "bob" }
        }
    }));
    let too_late_same_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &first, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[0], &future_other_group, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[0], &too_late_same_group, &[])
            .is_empty(),
        "event older than the lateness watermark should not complete correlation"
    );
}

#[test]
fn correlation_lateness_prunes_stale_state_across_groups() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("stale_prune.yml");
    fs::write(
        &path,
        r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine = SigmaCorrelationEngine::new_with_lateness(
        &report.correlations,
        CorrelationRuntimeScope::Host,
        100,
        Duration::seconds(0),
    );
    let first_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));
    let future_other_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:10:00Z" }
            },
            "EventData": { "TargetUserName": "bob" }
        }
    }));
    let stale_first_group = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
            },
            "EventData": { "TargetUserName": "alice" }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &first_group, &[])
            .is_empty()
    );
    assert_eq!(engine.stats().state_entries, 1);
    assert!(
        engine
            .observe_match(&report.rules[0], &future_other_group, &[])
            .is_empty()
    );
    assert_eq!(
        engine.stats().state_entries,
        1,
        "future event in another group should prune stale alice state and keep only bob"
    );

    let matches = engine.observe_match(&report.rules[0], &stale_first_group, &[]);

    assert!(
        matches.is_empty(),
        "stale event older than watermark must not complete an already-pruned group"
    );
    assert_eq!(engine.stats().state_entries, 1);
}

#[test]
fn value_count_correlation_counts_distinct_values_in_grouped_window() {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("failed_logon_value_count.yml");
    fs::write(
        &path,
        r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Failed Logons From Multiple Addresses
type: correlation
correlation:
  type: value_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    field: IpAddress
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");
    let report = load_sigma_rules(&[path]).expect("rules should load");
    let mut engine =
        SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
    let first = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
            },
            "EventData": {
                "TargetUserName": "alice",
                "IpAddress": "198.51.100.10"
            }
        }
    }));
    let duplicate_value = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
            },
            "EventData": {
                "TargetUserName": "alice",
                "IpAddress": "198.51.100.10"
            }
        }
    }));
    let second_value = test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "WIN-01",
                "TimeCreated": { "SystemTime": "2026-06-28T12:02:00Z" }
            },
            "EventData": {
                "TargetUserName": "alice",
                "IpAddress": "198.51.100.11"
            }
        }
    }));

    assert!(
        engine
            .observe_match(&report.rules[0], &first, &[])
            .is_empty()
    );
    assert!(
        engine
            .observe_match(&report.rules[0], &duplicate_value, &[])
            .is_empty()
    );

    let matches = engine.observe_match(&report.rules[0], &second_value, &[]);

    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0].rule.title,
        "Failed Logons From Multiple Addresses"
    );
    assert_eq!(matches[0].matches.len(), 3);
    assert_eq!(
        report.correlations[0].correlation.value_fields,
        ["IpAddress"]
    );
}

fn test_event(raw: serde_json::Value) -> Event {
    let input = DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from("."));

    Event::from_raw(&input, Some(1), raw)
}

fn repeated_process_correlation_report() -> SigmaLoadReport {
    let fixture = tempfile::tempdir().expect("tempdir should be created");
    let path = fixture.path().join("repeated_process.yml");
    fs::write(
        &path,
        r"
---
title: Process Start
name: process_start
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Repeated Process Starts
type: correlation
correlation:
  type: event_count
  rules:
    - process_start
  group-by:
    - ProcessGuid
  condition:
    gte: 2
  timespan: 5m
",
    )
    .expect("correlation fixture should be written");

    load_sigma_rules(&[path]).expect("rules should load")
}
