use std::process::Command;

fn stitch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stitch"))
}

#[test]
fn generated_evtx_fixtures_are_searchable_by_normalized_fields() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx",
            "--query",
            "event.id in (4624, 4104, 7036, 22, 1116, 5861, 200)",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search should run against generated EVTX fixtures");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""event_id":4624"#),
        "expected the Security logon fixture to match event.id 4624, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":4104"#),
        "expected the PowerShell script block fixture to match event.id 4104, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":7036"#),
        "expected the System service-control fixture to match event.id 7036, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":22"#),
        "expected the Sysmon DNS query fixture to match event.id 22, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":1116"#),
        "expected the Defender detection fixture to match event.id 1116, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":5861"#),
        "expected the WMI permanent consumer fixture to match event.id 5861, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""event_id":200"#),
        "expected the Task Scheduler action-start fixture to match event.id 200, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=31 matched=10 parse_errors=0"),
        "expected all generated fixture records to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn generated_evtx_fixture_event_data_is_queryable() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--query",
            r#"Event.EventData.TargetUserName == "service-build""#,
            "--fields",
            "Event.EventData.IpAddress",
            "--fields",
            "computer",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search should run against generated Security EVTX fixture");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""event_id":4625"#),
        "expected the failed-logon event to match by TargetUserName, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.IpAddress":"198.51.100.25""#),
        "expected the documentation-range source IP field to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""computer":"LAB-WKS-001""#),
        "expected the synthetic computer identity to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=5 matched=1 parse_errors=0"),
        "expected the generated Security fixture to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn generated_sysmon_fixture_supports_cidr_and_command_line_queries() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/sysmon-activity.evtx",
            "--query",
            r#"event.id == 3 and cidr_contains(Event.EventData.DestinationIp, "203.0.113.0/24") and Event.EventData.Image =~ /powershell\.exe$/i"#,
            "--fields",
            "Event.EventData.DestinationIp",
            "--fields",
            "Event.EventData.DestinationHostname",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search should run against generated Sysmon EVTX fixture");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""event_id":3"#),
        "expected the Sysmon network connection event to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.DestinationIp":"203.0.113.55""#),
        "expected the documentation-range destination IP to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.DestinationHostname":"updates.example.invalid""#),
        "expected the synthetic destination hostname to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=5 matched=1 parse_errors=0"),
        "expected the generated Sysmon fixture to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn generated_defender_fixture_exposes_detection_context() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/defender-operational.evtx",
            "--query",
            r#"event.id == 1116 and Event.EventData.Path contains "payload.bin""#,
            "--fields",
            "Event.EventData.Path",
            "--fields",
            "channel",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search should run against generated Defender EVTX fixture");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""event_id":1116"#),
        "expected the Defender detection event to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.Path":"file:_C:\\ProgramData\\Example\\payload.bin""#),
        "expected the detected file path to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""channel":"Microsoft-Windows-Windows Defender/Operational""#),
        "expected the Defender Operational channel to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=3 matched=1 parse_errors=0"),
        "expected the generated Defender fixture to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn generated_wmi_fixture_exposes_query_and_consumer_events() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/wmi-activity.evtx",
            "--query",
            r#"event.id == 5861 and Event.EventData.CONSUMER contains "ExampleInventoryConsumer""#,
            "--fields",
            "Event.EventData.Namespace",
            "--fields",
            "Event.EventData.CONSUMER",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search should run against generated WMI EVTX fixture");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""event_id":5861"#),
        "expected the WMI permanent consumer event to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.Namespace":"root\\subscription""#),
        "expected the WMI namespace to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains("ExampleInventoryConsumer"),
        "expected the synthetic WMI consumer name to be present, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=4 matched=1 parse_errors=0"),
        "expected the generated WMI fixture to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn generated_task_scheduler_fixture_exposes_action_context() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/task-scheduler-operational.evtx",
            "--query",
            r#"event.id == 200 and Event.EventData.ActionName contains_ci "powershell.exe""#,
            "--fields",
            "Event.EventData.TaskName",
            "--fields",
            "Event.EventData.EnginePID",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search should run against generated Task Scheduler EVTX fixture");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""event_id":200"#),
        "expected the scheduled-task action-start event to match, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.TaskName":"\\Example\\Collect Inventory""#),
        "expected the synthetic task name to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""Event.EventData.EnginePID":"5104""#),
        "expected the task engine PID to be projected, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=5 matched=1 parse_errors=0"),
        "expected the generated Task Scheduler fixture to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn generated_nested_collection_is_discovered_recursively() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/collections/example-case",
            "--query",
            r#"event.id == 7036 and computer == "LAB-SRV-002""#,
            "--fields",
            "source.collection_root",
            "--fields",
            "source.file_path",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search should run against nested generated EVTX collection");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .expect("stitch search output should be valid UTF-8 for JSONL results");

    assert!(
        stdout.contains(r#""computer":"LAB-SRV-002""#),
        "expected event-provided computer identity to be preserved, got:\n{stdout}"
    );
    assert!(
        stdout.contains("tests/fixtures/collections/example-case"),
        "expected the nested collection root to be reported, got:\n{stdout}"
    );
    assert!(
        stdout.contains("LAB-SRV-001/System.evtx"),
        "expected the nested source file path to be reported, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=15 matched=1 parse_errors=0"),
        "expected the nested generated collection to parse cleanly, got:\n{stdout}"
    );
}
