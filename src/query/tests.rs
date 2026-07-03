use std::path::PathBuf;

use serde_json::json;

use crate::event::Event;
use crate::input::DiscoveredInput;

use super::*;

#[test]
fn parses_boolean_precedence() {
    let expression =
        parse_query("event.id == 4625 or event.id == 4624 and channel == \"Security\"")
            .expect("query should parse");

    assert!(matches!(expression, Expr::Or(_, _)));
}

#[test]
fn tokenizes_complete_stql_lexicon() {
    let tokens = tokenize(
        "Event.System.TimeCreated.#attributes.SystemTime >= \"2026-06-27T00:00:00Z\" \
             and provider =~ /power\\/shell/i | keep event.id, source.file_path",
    )
    .expect("query should tokenize");

    assert_eq!(
        tokens,
        vec![
            Token::Ident("Event.System.TimeCreated.#attributes.SystemTime".to_owned()),
            Token::Operator(Operator::Gte),
            Token::String("2026-06-27T00:00:00Z".to_owned()),
            Token::Ident("and".to_owned()),
            Token::Ident("provider".to_owned()),
            Token::Operator(Operator::Regex),
            Token::Regex(RegexPattern {
                value: "power/shell".to_owned(),
                case_insensitive: true,
            }),
            Token::Symbol(Symbol::Pipe),
            Token::Ident("keep".to_owned()),
            Token::Ident("event.id".to_owned()),
            Token::Symbol(Symbol::Comma),
            Token::Ident("source.file_path".to_owned()),
        ],
        "lexer should recognize identifiers, operators, strings, regex literals, and pipeline symbols"
    );
}

#[test]
fn parses_documented_stql_statements() {
    let statements = [
        "event.id == 4625 and channel == \"Security\"",
        "event.id == 4625 or event.id == 4624",
        "not exists(Event.EventData.TargetUserName)",
        "record_id > 1000",
        "Event.EventData.TargetUserName contains \"admin\"",
        "Event.EventData.CommandLine contains_ci \"powershell\"",
        "event.id in (4624, 4625)",
        "provider =~ \"(?i)powershell\"",
        "provider !~ \"(?i)defender\"",
        "timestamp >= \"2026-06-27T00:00:00Z\"",
        "timestamp >= \"2026-03-21T06:00:00Z\" and timestamp < \"2026-03-21T07:00:00Z\"",
        "timestamp >= \"2026-03-21T01:00:00-05:00\"",
        "timestamp >= \"2026-03-21T06:00:00\"",
        "provider =~ /powershell/i",
        r"Event.EventData.CommandLine =~ /cmd\.exe \/c/",
        "channel in (\"Security\", \"System\")",
        "exists(field.name)",
        "event.id == 4624 | keep timestamp, event.id, computer, Event.EventData.TargetUserName",
    ];

    for statement in statements {
        parse_search_query(statement)
            .unwrap_or_else(|error| panic!("documented STQL should parse: {statement}: {error}"));
    }
}

#[test]
fn search_query_extracts_safe_metadata_prefilters() {
    let query = parse_search_query(
        "timestamp >= \"2026-06-27T00:00:00Z\" and event.id in (4624, 4625) \
             and channel == \"Security\" and Event.EventData.TargetUserName contains \"admin\"",
    )
    .expect("query should parse");

    assert_eq!(
        query.prefilter_count(),
        3,
        "timestamp, event id, and channel should become metadata prefilters"
    );
    assert!(
        query.matches(&rich_test_event()),
        "metadata prefilters should preserve matching query behavior"
    );
}

#[test]
fn search_query_does_not_prefilter_or_or_not_branches() {
    let or_query =
        parse_search_query("event.id == 1 or Event.EventData.TargetUserName == \"alice.admin\"")
            .expect("query should parse");
    let not_query = parse_search_query("not event.id == 1 and channel == \"Security\"")
        .expect("query should parse");

    assert_eq!(
        or_query.prefilter_count(),
        0,
        "or metadata branches should not be extracted because they are not required globally"
    );
    assert_eq!(
        not_query.prefilter_count(),
        1,
        "safe sibling metadata predicates can still be extracted beside a not branch"
    );
    assert!(
        or_query.matches(&rich_test_event()),
        "query with skipped or prefilter should still match through full evaluation"
    );
    assert!(
        not_query.matches(&rich_test_event()),
        "query with a skipped not branch should still match through full evaluation"
    );
}

#[test]
fn evaluates_all_comparison_operators_and_literal_forms() {
    let event = rich_test_event();
    let matching_statements = [
        "event.id == 4625",
        "event.id != 4624",
        "record_id < 2000",
        "record_id <= 1234",
        "record_id > 1000",
        "record_id >= 1234",
        "Event.EventData.TargetUserName contains \"admin\"",
        "Event.EventData.CommandLine contains_ci \"POWERSHELL\"",
        "channel in (\"Security\", \"System\")",
        "event.id in (4624, 4625)",
        "Event.EventData.Enabled == true",
        "Event.EventData.Enabled != false",
        "Event.EventData.Enabled in (false, true)",
        "provider =~ \"(?i)powershell\"",
        "provider !~ /defender/i",
        "timestamp >= \"2026-06-27T11:59:59Z\"",
        "timestamp <= \"2026-06-27T12:00:00Z\"",
        "Event.System.TimeCreated.#attributes.SystemTime == \"2026-06-27T12:00:00Z\"",
    ];

    for statement in matching_statements {
        let expression = parse_query(statement)
            .unwrap_or_else(|error| panic!("STQL should parse: {statement}: {error}"));
        assert!(
            expression.evaluate(&event),
            "STQL should match fixture: {statement}"
        );
    }
}

#[test]
fn evaluates_cidr_helper_functions() {
    let event = rich_test_event();
    let matching = [
        "cidr_contains(Event.EventData.SourceIp, \"10.12.34.0/24\")",
        "ip_in_cidr(Event.EventData.SourceIp, \"10.0.0.0/8\")",
        "cidr_contains(Event.EventData.SourceIpV6, \"2001:db8::/32\")",
    ];
    let non_matching = [
        "cidr_contains(Event.EventData.SourceIp, \"192.168.0.0/16\")",
        "cidr_contains(Event.EventData.SourceIpV6, \"2001:db9::/32\")",
        "cidr_contains(Event.EventData.TargetUserName, \"10.0.0.0/8\")",
    ];

    for statement in matching {
        let expression = parse_query(statement)
            .unwrap_or_else(|error| panic!("CIDR STQL should parse: {statement}: {error}"));
        assert!(
            expression.evaluate(&event),
            "CIDR STQL should match fixture: {statement}"
        );
    }

    for statement in non_matching {
        let expression = parse_query(statement)
            .unwrap_or_else(|error| panic!("CIDR STQL should parse: {statement}: {error}"));
        assert!(
            !expression.evaluate(&event),
            "CIDR STQL should not match fixture: {statement}"
        );
    }
}

#[test]
fn rejects_invalid_cidr_helpers() {
    let invalid = [
        (
            "cidr_contains(Event.EventData.SourceIp, \"10.0.0.0\")",
            QueryError::InvalidCidr {
                value: "10.0.0.0".to_owned(),
            },
        ),
        (
            "cidr_contains(Event.EventData.SourceIp, \"10.0.0.0/33\")",
            QueryError::InvalidCidrPrefix {
                prefix: 33,
                family: "IPv4",
            },
        ),
        (
            "cidr_contains(Event.EventData.SourceIpV6, \"2001:db8::/129\")",
            QueryError::InvalidCidrPrefix {
                prefix: 129,
                family: "IPv6",
            },
        ),
    ];

    for (statement, expected) in invalid {
        let error = parse_query(statement).expect_err("invalid CIDR query should fail");
        assert_eq!(error, expected, "unexpected CIDR error for {statement}");
    }
}

#[test]
fn evaluates_boolean_precedence_parentheses_and_not() {
    let event = rich_test_event();
    let matching = [
        "event.id == 1 or event.id == 4625 and channel == \"Security\"",
        "(event.id == 1 or event.id == 4625) and channel == \"Security\"",
        "not exists(Event.EventData.Missing)",
        "not (event.id == 1)",
    ];
    let non_matching = [
        "(event.id == 1 or event.id == 4625) and channel == \"System\"",
        "not (event.id == 4625)",
    ];

    for statement in matching {
        let expression = parse_query(statement)
            .unwrap_or_else(|error| panic!("STQL should parse: {statement}: {error}"));
        assert!(
            expression.evaluate(&event),
            "STQL should match fixture: {statement}"
        );
    }

    for statement in non_matching {
        let expression = parse_query(statement)
            .unwrap_or_else(|error| panic!("STQL should parse: {statement}: {error}"));
        assert!(
            !expression.evaluate(&event),
            "STQL should not match fixture: {statement}"
        );
    }
}

#[test]
fn evaluates_chained_and_or_with_documented_precedence() {
    let alice_logon = rich_test_event();
    let bob_logon = test_event(json!({
        "Event": {
            "System": {
                "EventID": 456,
                "EventRecordID": 1234,
                "Channel": "Security",
                "Provider": { "Name": "Microsoft-Windows-Security-Auditing" }
            },
            "EventData": {
                "TargetUserName": "bob.admin"
            }
        }
    }));
    let expression = parse_query(
        "event.id == 123 or event.id == 4625 and Event.EventData.TargetUserName == \"alice.admin\"",
    )
    .expect("query should parse");

    assert!(
        expression.evaluate(&alice_logon),
        "and should bind tighter than or for matching right branch"
    );
    assert!(
        !expression.evaluate(&bob_logon),
        "right branch should require both event id and user match"
    );
}

#[test]
fn evaluates_arbitrarily_nested_parentheses_for_grouping() {
    let event = rich_test_event();
    let matching = [
        "((((event.id == 4625))))",
        "((event.id == 1 or (event.id == 4625 and (channel == \"Security\"))))",
        "(((event.id == 1 or event.id == 2) or ((event.id == 4625)))) and (((Event.EventData.TargetUserName == \"alice.admin\")))",
    ];
    let non_matching = [
        "((event.id == 1 or event.id == 4625) and (channel == \"System\" or Event.EventData.TargetUserName == \"bob.admin\"))",
        "(((event.id == 4625 and channel == \"System\") or (Event.EventData.TargetUserName == \"bob.admin\")))",
    ];

    for statement in matching {
        let expression = parse_query(statement)
            .unwrap_or_else(|error| panic!("nested STQL should parse: {statement}: {error}"));
        assert!(
            expression.evaluate(&event),
            "nested STQL should match fixture: {statement}"
        );
    }

    for statement in non_matching {
        let expression = parse_query(statement)
            .unwrap_or_else(|error| panic!("nested STQL should parse: {statement}: {error}"));
        assert!(
            !expression.evaluate(&event),
            "nested STQL should not match fixture: {statement}"
        );
    }
}

#[test]
fn rejects_invalid_stql_syntax() {
    let invalid = [
        ("", QueryError::Empty),
        (
            "event.id = 4625",
            QueryError::UnexpectedToken {
                token: "=".to_owned(),
            },
        ),
        ("event.id == \"unterminated", QueryError::UnterminatedString),
        ("provider =~ /unterminated", QueryError::UnterminatedRegex),
        (
            "provider =~ /powershell/x",
            QueryError::UnsupportedRegexFlag { flag: 'x' },
        ),
        (
            "event.id == 4625 extra",
            QueryError::UnexpectedToken {
                token: "extra".to_owned(),
            },
        ),
        (
            "event.id in ()",
            QueryError::Expected {
                expected: "literal".to_owned(),
                found: "RightParen".to_owned(),
            },
        ),
        ("event.id == 4625 | keep", QueryError::EmptyKeep),
        (
            "event.id == 4625 | table timestamp",
            QueryError::UnsupportedPipeline {
                command: "table".to_owned(),
            },
        ),
    ];

    for (statement, expected) in invalid {
        let error =
            parse_search_query(statement).expect_err(&format!("STQL should fail: {statement}"));
        assert_eq!(error, expected, "unexpected error for STQL: {statement}");
    }
}

#[test]
fn rejects_invalid_regex_patterns() {
    let error = parse_search_query("provider =~ \"(\"").expect_err("regex should fail");

    assert!(
        matches!(
            error,
            QueryError::InvalidRegex {
                ref pattern,
                message: _
            } if pattern == "("
        ),
        "invalid regex should report the rejected pattern"
    );
}

#[test]
fn evaluates_numeric_and_string_predicates() {
    let event = test_event(json!({
        "Event": {
            "System": { "EventID": 4625, "Channel": "Security" },
            "EventData": { "TargetUserName": "alice.admin" }
        }
    }));
    let expression =
        parse_query("event.id == 4625 and Event.EventData.TargetUserName contains_ci \"ADMIN\"")
            .expect("query should parse");

    assert!(expression.evaluate(&event));
}

#[test]
fn evaluates_exists_and_not() {
    let event = test_event(json!({ "Event": { "System": { "EventID": 1 } } }));
    let expression =
        parse_query("exists(event.id) and not exists(channel)").expect("query should parse");

    assert!(expression.evaluate(&event));
}

#[test]
fn evaluates_in_lists() {
    let event = test_event(json!({ "Event": { "System": { "EventID": 6005 } } }));
    let expression = parse_query("event.id in (6005, 6006, 6008)").expect("query should parse");

    assert!(expression.evaluate(&event));
}

#[test]
fn evaluates_quoted_regex_matches() {
    let event = test_event(json!({
        "Event": {
            "System": { "Provider": { "Name": "Microsoft-Windows-PowerShell" } }
        }
    }));
    let expression = parse_query("provider =~ \"(?i)powershell\"").expect("query should parse");

    assert!(expression.evaluate(&event));
}

#[test]
fn evaluates_slash_delimited_regex_matches() {
    let event = test_event(json!({
        "Event": {
            "System": { "Provider": { "Name": "Microsoft-Windows-PowerShell" } }
        }
    }));
    let expression = parse_query("provider =~ /powershell/i").expect("query should parse");

    assert!(expression.evaluate(&event));
}

#[test]
fn preserves_regex_escapes_and_escaped_delimiters() {
    let event = test_event(json!({
        "Event": {
            "EventData": { "CommandLine": "cmd.exe /c whoami" }
        }
    }));
    let expression =
        parse_query(r"Event.EventData.CommandLine =~ /cmd\.exe \/c/").expect("query should parse");

    assert!(expression.evaluate(&event));
}

#[test]
fn rejects_unsupported_regex_flags() {
    let error = parse_query("provider =~ /powershell/x").expect_err("query should fail");

    assert_eq!(error, QueryError::UnsupportedRegexFlag { flag: 'x' });
}

#[test]
fn evaluates_typed_timestamp_comparisons() {
    let event = test_event(json!({
        "Event": {
            "System": {
                "TimeCreated": {
                    "#attributes": {
                        "SystemTime": "2026-06-27T12:00:00Z"
                    }
                }
            }
        }
    }));
    let expression =
        parse_query("timestamp >= \"2026-06-27T07:00:00-05:00\"").expect("query should parse");

    assert!(expression.evaluate(&event));
}

#[test]
fn parses_keep_pipeline_fields() {
    let query = parse_search_query(
        "event.id == 4624 | keep timestamp, event.id, Event.EventData.TargetUserName",
    )
    .expect("search query should parse");

    assert_eq!(
        query.keep_fields,
        vec!["timestamp", "event.id", "Event.EventData.TargetUserName"]
    );
}

#[test]
fn rejects_unknown_pipeline_commands() {
    let error =
        parse_search_query("event.id == 4624 | table timestamp").expect_err("query should fail");

    assert_eq!(
        error,
        QueryError::UnsupportedPipeline {
            command: "table".to_owned()
        }
    );
}

#[test]
fn treats_offsetless_timestamps_as_utc() {
    let event = test_event(json!({
        "Event": {
            "System": {
                "TimeCreated": {
                    "#attributes": {
                        "SystemTime": "2026-06-27T12:00:00Z"
                    }
                }
            }
        }
    }));
    let expression =
        parse_query("timestamp >= \"2026-06-27T12:00:00\"").expect("query should parse");

    assert!(expression.evaluate(&event));
}

fn test_event(raw: serde_json::Value) -> Event {
    let input = DiscoveredInput::new(PathBuf::from("fixture.evtx"), PathBuf::from("."));

    Event::from_raw(&input, None, raw)
}

fn rich_test_event() -> Event {
    test_event(json!({
        "Event": {
            "System": {
                "EventID": 4625,
                "EventRecordID": 1234,
                "Channel": "Security",
                "Computer": "WIN-01",
                "Provider": {
                    "#attributes": {
                        "Name": "Microsoft-Windows-PowerShell"
                    }
                },
                "TimeCreated": {
                    "#attributes": {
                        "SystemTime": "2026-06-27T12:00:00Z"
                    }
                }
            },
            "EventData": {
                "TargetUserName": "alice.admin",
                "CommandLine": "cmd.exe /c powershell.exe",
                "SourceIp": "10.12.34.56",
                "SourceIpV6": "2001:db8::10",
                "Enabled": true
            }
        }
    }))
}
