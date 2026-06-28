use std::process::Command;

fn stitch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stitch"))
}

#[test]
fn hunt_matches_generated_evtx_with_windows_sigma_field_aliases() {
    let output = stitch()
        .args([
            "hunt",
            "-i",
            "tests/fixtures/evtx",
            "--rules",
            "tests/fixtures/sigma",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch hunt should run against generated EVTX fixtures");

    assert!(
        output.status.success(),
        "stitch hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch hunt output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains("Synthetic Sysmon PowerShell Network Connection"),
        "expected Sysmon network Sigma rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic WMI Permanent Consumer"),
        "expected WMI Sigma rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Scheduled PowerShell Task Action"),
        "expected Task Scheduler Sigma rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Defender Payload Detection"),
        "expected Defender Sigma rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":3"#),
        "expected Sysmon event identity in hunt output, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":5861"#),
        "expected WMI event identity in hunt output, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":200"#),
        "expected Task Scheduler event identity in hunt output, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":1116"#),
        "expected Defender event identity in hunt output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=31 matched=4 rules=4 skipped_correlation=0 inputs=7"),
        "expected generated hunt stats to stay stable, got:\n{stdout}"
    );
}

#[test]
fn hunt_cli_filters_generated_sigma_rules() {
    let output = stitch()
        .args([
            "hunt",
            "-i",
            "tests/fixtures/evtx",
            "--rules",
            "tests/fixtures/sigma",
            "--format",
            "jsonl",
            "--min-level",
            "high",
            "--stats",
        ])
        .output()
        .expect("stitch hunt should run with a Sigma minimum level filter");

    assert!(
        output.status.success(),
        "stitch hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch hunt output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains("Synthetic Sysmon PowerShell Network Connection"),
        "expected high Sysmon rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Defender Payload Detection"),
        "expected high Defender rule to match, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Synthetic WMI Permanent Consumer"),
        "medium WMI rule should be filtered by --min-level high, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=31 matched=2 rules=2 skipped_correlation=0 inputs=7"),
        "expected filtered hunt stats, got:\n{stdout}"
    );
}

#[test]
fn hunt_cli_excludes_generated_sigma_rules_by_title_glob() {
    let output = stitch()
        .args([
            "hunt",
            "-i",
            "tests/fixtures/evtx",
            "--rules",
            "tests/fixtures/sigma",
            "--format",
            "jsonl",
            "--exclude-rule",
            "*Defender*",
            "--stats",
        ])
        .output()
        .expect("stitch hunt should run with a Sigma exclude-rule filter");

    assert!(
        output.status.success(),
        "stitch hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch hunt output should be valid UTF-8 for JSONL results");

    assert!(
        !stdout.contains("Synthetic Defender Payload Detection"),
        "Defender rule should be excluded by title glob, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Sysmon PowerShell Network Connection"),
        "non-excluded Sysmon rule should still match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=31 matched=3 rules=3 skipped_correlation=0 inputs=7"),
        "expected exclude-rule hunt stats, got:\n{stdout}"
    );
}

#[test]
fn hunt_matches_generated_evtx_with_broader_sigma_grammar() {
    let output = stitch()
        .args([
            "hunt",
            "-i",
            "tests/fixtures/evtx",
            "--rules",
            "tests/fixtures/sigma-grammar",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch hunt should run broader Sigma grammar rules");

    assert!(
        output.status.success(),
        "stitch hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch hunt output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains("Synthetic PowerShell Keyword Grammar Rule"),
        "expected keyword/all Sigma grammar rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Sysmon Alternative Map Grammar Rule"),
        "expected map-list alternative Sigma grammar rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Defender Null Condition List Grammar Rule"),
        "expected null/condition-list Sigma grammar rule to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=31 matched=4 rules=3 skipped_correlation=0 inputs=7"),
        "expected broader grammar hunt stats, got:\n{stdout}"
    );
}

#[test]
fn hunt_emits_event_count_correlation_matches_from_generated_evtx() {
    let output = stitch()
        .args([
            "hunt",
            "-i",
            "tests/fixtures/correlation-evtx/sysmon-correlation.evtx",
            "--rules",
            "tests/fixtures/sigma-correlation",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch hunt should run correlation rules against generated EVTX fixtures");

    assert!(
        output.status.success(),
        "stitch hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch hunt output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""type":"sigma_correlation_match""#),
        "expected a Sigma correlation match, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Sysmon Repeated Process Activity Correlation"),
        "expected synthetic correlation rule title, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Sysmon Distinct Process Event Types Correlation"),
        "expected synthetic value-count correlation rule title, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Sysmon Ordered Process Activity Correlation"),
        "expected synthetic temporal ordered correlation rule title, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""ProcessGuid":"{22222222-3333-4444-5555-000000000001}""#),
        "expected ProcessGuid group in correlation output, got:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "stats: scanned=4 matched=8 correlation_matched=3 rules=4 correlation_rules=3 correlation_state=6 correlation_evicted=0 skipped_correlation=0 inputs=1"
        ),
        "expected correlation stats, got:\n{stdout}"
    );
}

#[test]
fn hunt_correlation_output_can_include_bounded_contributing_event_details() {
    let jsonl_output = stitch()
        .args([
            "hunt",
            "-i",
            "tests/fixtures/correlation-evtx/sysmon-correlation.evtx",
            "--rules",
            "tests/fixtures/sigma-correlation",
            "--format",
            "jsonl",
            "--correlation-event-field",
            "Image",
            "--correlation-event-field",
            "DestinationIp",
            "--correlation-event-field",
            "TargetFilename",
        ])
        .output()
        .expect("stitch hunt should render selected correlation event fields");

    assert!(
        jsonl_output.status.success(),
        "stitch hunt failed: {}",
        String::from_utf8_lossy(&jsonl_output.stderr)
    );

    let jsonl_stdout = String::from_utf8(jsonl_output.stdout)
        .expect("stitch hunt output should be valid UTF-8 for JSONL results");

    assert!(
        jsonl_stdout.contains(r#""fields":{"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","DestinationIp":"203.0.113.77","TargetFilename":null}"#),
        "expected selected contributing-event fields in JSONL correlation output, got:\n{jsonl_stdout}"
    );
    assert!(
        jsonl_stdout.contains(r#""TargetFilename":"C:\\ProgramData\\Example\\stage.bin""#),
        "expected file-write contributing-event detail in JSONL correlation output, got:\n{jsonl_stdout}"
    );

    let pretty_output = stitch()
        .args([
            "hunt",
            "-i",
            "tests/fixtures/correlation-evtx/sysmon-correlation.evtx",
            "--rules",
            "tests/fixtures/sigma-correlation",
            "--format",
            "pretty",
            "--correlation-event-field",
            "Image",
            "--correlation-event-field",
            "DestinationIp",
            "--correlation-event-limit",
            "1",
        ])
        .output()
        .expect("stitch hunt should render bounded pretty correlation event details");

    assert!(
        pretty_output.status.success(),
        "stitch hunt failed: {}",
        String::from_utf8_lossy(&pretty_output.stderr)
    );

    let pretty_stdout = String::from_utf8(pretty_output.stdout)
        .expect("stitch hunt output should be valid UTF-8 for pretty results");

    assert!(
        pretty_stdout.contains("contributing events:"),
        "expected pretty correlation output to include contributing-event section, got:\n{pretty_stdout}"
    );
    assert!(
        pretty_stdout
            .contains("Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        "expected selected Image field in pretty correlation output, got:\n{pretty_stdout}"
    );
    assert!(
        pretty_stdout.contains(
            "... 2 more contributing event(s); increase --correlation-event-limit to show more"
        ),
        "expected pretty correlation output to bound event details, got:\n{pretty_stdout}"
    );
}

#[test]
fn search_cli_still_handles_ad_hoc_fixture_queries() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx",
            "--query",
            r#"provider =~ /wmi/i and Event.EventData.Query contains "Win32_Process" | keep timestamp, provider, event.id, computer, Event.EventData.Query"#,
            "--format",
            "jsonl",
            "--limit",
            "1",
            "--stats",
        ])
        .output()
        .expect("stitch search should run an ad hoc query against generated fixtures");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""provider":"Microsoft-Windows-WMI-Activity""#),
        "expected WMI provider match for ad hoc CLI query, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.Query":"SELECT * FROM Win32_Process""#),
        "expected projected WMI query text from keep pipeline, got:\n{stdout}"
    );
    assert!(
        stdout.contains("matched=1"),
        "expected limit-constrained ad hoc query to match one event, got:\n{stdout}"
    );
}
