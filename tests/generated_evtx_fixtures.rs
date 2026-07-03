use std::{
    fs,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn stitch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stitch"))
}

fn run_with_timeout(mut command: Command, timeout: Duration) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("stitch process should spawn");
    let started = Instant::now();

    loop {
        if child
            .try_wait()
            .expect("stitch process status should be readable")
            .is_some()
        {
            return child
                .wait_with_output()
                .expect("stitch output should be readable");
        }

        if started.elapsed() >= timeout {
            child
                .kill()
                .expect("timed out stitch process should be killed");
            let output = child
                .wait_with_output()
                .expect("timed out stitch output should be readable");
            panic!(
                "stitch command timed out after {timeout:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        thread::sleep(Duration::from_millis(25));
    }
}

fn repeated_paths_file(paths: &[&str], repetitions: usize) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("path list file should be created");
    let body = (0..repetitions)
        .flat_map(|_| paths.iter().copied())
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(file.path(), format!("{body}\n")).expect("path list should be written");
    file
}

#[test]
fn search_defaults_to_current_directory_when_input_is_omitted() {
    let mut command = stitch();
    command.current_dir("tests/fixtures/evtx").args([
        "search",
        "--query",
        "event.id == 4625",
        "--format",
        "jsonl",
        "--limit",
        "1",
    ]);

    let output = run_with_timeout(command, Duration::from_secs(10));

    assert!(
        output.status.success(),
        "search without explicit input should scan the current directory\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("search output should be UTF-8");
    assert!(
        stdout.contains(r#""event_id":4625"#),
        "expected omitted-input search to find failed logon event, got:\n{stdout}"
    );
}

#[test]
fn search_parallel_jobs_match_single_worker_with_timeout() {
    let paths = repeated_paths_file(
        &[
            "tests/fixtures/evtx/security-auth.evtx",
            "tests/fixtures/evtx/sysmon-activity.evtx",
            "tests/fixtures/evtx/wmi-activity.evtx",
            "tests/fixtures/evtx/task-scheduler-operational.evtx",
        ],
        12,
    );

    let mut single = stitch();
    single.args([
        "-j",
        "1",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "search",
        "--query",
        "event.id in (4624, 4104, 4688, 5861, 200)",
        "--fields",
        "timestamp",
        "--fields",
        "event.id",
        "--fields",
        "computer",
        "--format",
        "jsonl",
        "--stats",
    ]);
    let single_output = run_with_timeout(single, Duration::from_secs(10));

    assert!(
        single_output.status.success(),
        "single-worker search failed: {}",
        String::from_utf8_lossy(&single_output.stderr)
    );

    let mut parallel = stitch();
    parallel.args([
        "-j",
        "4",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "search",
        "--query",
        "event.id in (4624, 4104, 4688, 5861, 200)",
        "--fields",
        "timestamp",
        "--fields",
        "event.id",
        "--fields",
        "computer",
        "--format",
        "jsonl",
        "--stats",
    ]);
    let parallel_output = run_with_timeout(parallel, Duration::from_secs(10));

    assert!(
        parallel_output.status.success(),
        "parallel search failed: {}",
        String::from_utf8_lossy(&parallel_output.stderr)
    );
    assert_eq!(
        String::from_utf8(single_output.stdout).expect("single output should be UTF-8"),
        String::from_utf8(parallel_output.stdout).expect("parallel output should be UTF-8"),
        "parallel search output should match single-worker output"
    );
}

#[test]
fn dump_parallel_jobs_match_single_worker_with_timeout() {
    let paths = repeated_paths_file(
        &[
            "tests/fixtures/evtx/security-auth.evtx",
            "tests/fixtures/evtx/sysmon-activity.evtx",
            "tests/fixtures/evtx/defender-operational.evtx",
        ],
        16,
    );

    let mut single = stitch();
    single.args([
        "-j",
        "1",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "dump",
        "--format",
        "csv",
        "--fields",
        "timestamp",
        "--fields",
        "event.id",
        "--fields",
        "computer",
        "--stats",
    ]);
    let single_output = run_with_timeout(single, Duration::from_secs(10));

    assert!(
        single_output.status.success(),
        "single-worker dump failed: {}",
        String::from_utf8_lossy(&single_output.stderr)
    );

    let mut parallel = stitch();
    parallel.args([
        "-j",
        "4",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "dump",
        "--format",
        "csv",
        "--fields",
        "timestamp",
        "--fields",
        "event.id",
        "--fields",
        "computer",
        "--stats",
    ]);
    let parallel_output = run_with_timeout(parallel, Duration::from_secs(10));

    assert!(
        parallel_output.status.success(),
        "parallel dump failed: {}",
        String::from_utf8_lossy(&parallel_output.stderr)
    );
    assert_eq!(
        String::from_utf8(single_output.stdout).expect("single output should be UTF-8"),
        String::from_utf8(parallel_output.stdout).expect("parallel output should be UTF-8"),
        "parallel dump output should match single-worker output"
    );
}

#[test]
fn dump_reports_output_file_create_errors() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let output_path = directory.path().join("missing-parent").join("dump.jsonl");
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--output",
            output_path.to_str().expect("temp path should be UTF-8"),
        ])
        .output()
        .expect("stitch dump should run");

    assert!(
        !output.status.success(),
        "dump should fail when output parent directory does not exist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to create dump output file") && stderr.contains("missing-parent"),
        "dump should report output create path and cause, got:\n{stderr}"
    );
}

#[test]
fn search_reports_error_file_create_errors() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let errors_path = directory.path().join("missing-parent").join("errors.jsonl");
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--query",
            "event.id == 4625",
            "--errors",
            errors_path.to_str().expect("temp path should be UTF-8"),
        ])
        .output()
        .expect("stitch search should run");

    assert!(
        !output.status.success(),
        "search should fail when errors-file parent directory does not exist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to create parse errors file") && stderr.contains("missing-parent"),
        "search should report errors-file create path and cause, got:\n{stderr}"
    );
}

#[test]
fn parallel_search_reports_malformed_evtx_without_hanging() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let bad_evtx = directory.path().join("bad.evtx");
    fs::write(&bad_evtx, b"not an evtx file").expect("bad EVTX fixture should be written");
    let paths = repeated_paths_file(
        &[
            "tests/fixtures/evtx/security-auth.evtx",
            bad_evtx.to_str().expect("temp path should be UTF-8"),
            "tests/fixtures/evtx/sysmon-activity.evtx",
        ],
        4,
    );
    let mut command = stitch();
    command.args([
        "-j",
        "4",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "search",
        "--query",
        "event.id >= 0",
        "--format",
        "jsonl",
        "--stats",
    ]);

    let output = run_with_timeout(command, Duration::from_secs(10));

    assert!(
        !output.status.success(),
        "parallel search should fail on malformed EVTX input"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to open EVTX file") && stderr.contains("bad.evtx"),
        "parallel malformed EVTX failure should include path context, got:\n{stderr}"
    );
}

#[test]
fn dump_jsonl_streams_generated_evtx_records() {
    let output = stitch()
        .args(["dump", "-i", "tests/fixtures/evtx/security-auth.evtx"])
        .output()
        .expect("stitch dump should run against generated Security EVTX fixture");

    assert!(
        output.status.success(),
        "stitch dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("dump output should be valid UTF-8 JSONL");
    let lines = stdout.lines().collect::<Vec<_>>();

    assert_eq!(lines.len(), 5, "expected one JSONL row per EVTX record");

    let first: serde_json::Value =
        serde_json::from_str(lines[0]).expect("dump line should be valid JSON");
    assert_eq!(first["event_id"], 4624);
    assert_eq!(first["computer"], "LAB-WKS-001");
    assert!(
        first.get("raw").is_some(),
        "default dump shape should include the raw event"
    );
}

#[test]
fn dump_jsonl_supports_field_projection_and_raw_output() {
    let projected = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--fields",
            "Event.EventData.TargetUserName",
            "--fields",
            "computer",
        ])
        .output()
        .expect("stitch dump should run with field projection");

    assert!(
        projected.status.success(),
        "projected dump failed: {}",
        String::from_utf8_lossy(&projected.stderr)
    );

    let projected_stdout =
        String::from_utf8(projected.stdout).expect("projected dump should be UTF-8");
    let first_projected: serde_json::Value = serde_json::from_str(
        projected_stdout
            .lines()
            .next()
            .expect("dump should emit a row"),
    )
    .expect("projected dump line should be JSON");

    assert_eq!(first_projected["fields"]["computer"], "LAB-WKS-001");
    assert!(
        first_projected.get("raw").is_none(),
        "projected dump should omit raw event payloads"
    );

    let raw = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--raw",
        ])
        .output()
        .expect("stitch dump should run with raw output");

    assert!(
        raw.status.success(),
        "raw dump failed: {}",
        String::from_utf8_lossy(&raw.stderr)
    );

    let raw_stdout = String::from_utf8(raw.stdout).expect("raw dump should be UTF-8");
    let first_raw: serde_json::Value =
        serde_json::from_str(raw_stdout.lines().next().expect("dump should emit a row"))
            .expect("raw dump line should be JSON");

    assert!(first_raw.get("Event").is_some());
    assert!(
        first_raw.get("source").is_none(),
        "raw dump should preserve only the parsed raw EVTX shape"
    );
}

#[test]
fn dump_jsonl_can_write_to_output_file() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let output_path = directory.path().join("security-auth.jsonl");
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--output",
            output_path.to_str().expect("temp path should be UTF-8"),
            "--stats",
        ])
        .output()
        .expect("stitch dump should write JSONL to a file");

    assert!(
        output.status.success(),
        "file dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stats output should be UTF-8");
    assert!(
        stdout.contains("stats: dumped=5 parse_errors=0 inputs=1"),
        "expected dump stats on stdout, got:\n{stdout}"
    );

    let file_output = fs::read_to_string(output_path).expect("dump output file should be readable");
    assert_eq!(
        file_output.lines().count(),
        5,
        "output file should contain one JSONL row per EVTX record"
    );
}

#[test]
fn dump_json_emits_array_output() {
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--format",
            "json",
            "--fields",
            "computer",
            "--compact",
        ])
        .output()
        .expect("stitch dump should emit JSON array output");

    assert!(
        output.status.success(),
        "JSON dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("JSON dump should be UTF-8");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("dump --format json should emit valid JSON");
    let records = value
        .as_array()
        .expect("JSON dump output should be an array");

    assert_eq!(records.len(), 5);
    assert_eq!(records[0]["event_id"], 4624);
    assert_eq!(records[0]["fields"]["computer"], "LAB-WKS-001");
}

#[test]
fn dump_json_can_write_pretty_array_to_output_file() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let output_path = directory.path().join("security-auth.json");
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--format",
            "json",
            "--pretty",
            "--raw",
            "--output",
            output_path.to_str().expect("temp path should be UTF-8"),
            "--stats",
        ])
        .output()
        .expect("stitch dump should write JSON array output to a file");

    assert!(
        output.status.success(),
        "JSON file dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stats output should be UTF-8");
    assert!(
        stdout.contains("stats: dumped=5 parse_errors=0 inputs=1"),
        "expected dump stats on stdout, got:\n{stdout}"
    );

    let file_output = fs::read_to_string(output_path).expect("JSON output file should be readable");
    assert!(
        file_output.contains('\n'),
        "pretty JSON output should contain newlines"
    );

    let value: serde_json::Value =
        serde_json::from_str(&file_output).expect("output file should contain valid JSON");
    assert_eq!(
        value
            .as_array()
            .expect("JSON output should be an array")
            .len(),
        5
    );
}

#[test]
fn dump_csv_requires_explicit_fields() {
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--format",
            "csv",
        ])
        .output()
        .expect("stitch dump should reject CSV without fields");

    assert!(
        !output.status.success(),
        "CSV dump without fields should fail"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(
        stderr.contains("dump --format csv requires at least one --fields value"),
        "expected clear CSV projection error, got:\n{stderr}"
    );
}

#[test]
fn dump_csv_rejects_raw_mode() {
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--format",
            "csv",
            "--fields",
            "computer",
            "--raw",
        ])
        .output()
        .expect("stitch dump should reject CSV raw mode");

    assert!(!output.status.success(), "CSV raw dump should fail");

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(
        stderr.contains("dump --format csv does not support --raw"),
        "expected clear CSV raw-mode error, got:\n{stderr}"
    );
}

#[test]
fn dump_csv_emits_projected_rows() {
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--format",
            "csv",
            "--fields",
            "timestamp",
            "--fields",
            "event.id",
            "--fields",
            "computer",
        ])
        .output()
        .expect("stitch dump should emit projected CSV");

    assert!(
        output.status.success(),
        "CSV dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("CSV output should be UTF-8");
    let lines = stdout.lines().collect::<Vec<_>>();

    assert_eq!(
        lines.len(),
        6,
        "CSV should include one header and five rows"
    );
    assert_eq!(lines[0], "timestamp,event.id,computer");
    assert!(
        lines[1].contains("2026-01-15T10:00:00.000000Z,4624,LAB-WKS-001"),
        "expected projected CSV row, got:\n{stdout}"
    );
}

#[test]
fn dump_csv_escapes_quoted_fields_and_writes_to_output_file() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let output_path = directory.path().join("security-auth.csv");
    let output = stitch()
        .args([
            "dump",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--format",
            "csv",
            "--fields",
            "Event.EventData.ProcessName",
            "--fields",
            "missing,field",
            "--output",
            output_path.to_str().expect("temp path should be UTF-8"),
            "--stats",
        ])
        .output()
        .expect("stitch dump should write projected CSV to a file");

    assert!(
        output.status.success(),
        "CSV file dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stats output should be UTF-8");
    assert!(
        stdout.contains("stats: dumped=5 parse_errors=0 inputs=1"),
        "expected dump stats on stdout, got:\n{stdout}"
    );

    let file_output = fs::read_to_string(output_path).expect("CSV output file should be readable");
    assert!(
        file_output.starts_with("Event.EventData.ProcessName,\"missing,field\""),
        "expected CSV header quoting for comma-containing field names, got:\n{file_output}"
    );
    assert!(
        file_output.contains("C:\\Windows\\System32\\runas.exe,"),
        "expected projected CSV row with missing fields as empty values, got:\n{file_output}"
    );
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
        stdout.contains("stats: scanned=39 matched=14 parse_errors=0"),
        "expected all generated fixture records to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn search_summarize_groups_logons_and_collects_distinct_values() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/aggregation-lateral-logons.evtx",
            "--query",
            "event.id in (4624, 4625) | summarize \
             logon_types=make_set(Event.EventData.LogonType), \
             users=make_set(Event.EventData.TargetUserName), \
             target_hosts=make_set(computer), \
             total=count() \
             by source_ip=Event.EventData.IpAddress",
            "--format",
            "jsonl",
            "--stats",
        ])
        .output()
        .expect("stitch search summarize should run against generated fixtures");

    assert!(
        output.status.success(),
        "stitch search summarize failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("summarize output should be valid UTF-8");

    assert!(
        stdout.contains(r#""source_ip":"198.51.100.77""#),
        "expected lateral source IP group, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""users":["admin-review","alice.admin","bob.admin","svc-deploy"]"#),
        "expected multiple distinct users to be collected into the lateral source IP group, got:\n{stdout}"
    );
    assert!(
        stdout
            .contains(r#""target_hosts":["LAB-DC-001","LAB-SRV-001","LAB-SRV-002","LAB-WKS-003"]"#),
        "expected lateral source to touch several target hosts, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""logon_types":["10","3"]"#),
        "expected mixed remote interactive and network logon types, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""total":5"#),
        "expected repeated lateral source logons to increase count, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""source_ip":"203.0.113.44""#),
        "expected noisy service-account source IP group, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""users":["svc-backup","svc-sql"]"#),
        "expected repeated service-account attempts to collapse in make_set, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=8 matched=8 parse_errors=0"),
        "expected aggregation EVTX fixture to parse cleanly, got:\n{stdout}"
    );
}

#[test]
fn search_summarize_parallel_jobs_match_single_worker_with_timeout() {
    let paths = repeated_paths_file(
        &[
            "tests/fixtures/evtx/security-auth.evtx",
            "tests/fixtures/evtx/security-auth.evtx",
        ],
        8,
    );
    let query = "event.id in (4624, 4625) | summarize \
         logon_types=make_set(Event.EventData.LogonType), \
         users=make_set(Event.EventData.TargetUserName), \
         total=count() \
         by source_ip=Event.EventData.IpAddress";

    let mut single = stitch();
    single.args([
        "-j",
        "1",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "search",
        "--query",
        query,
        "--format",
        "jsonl",
    ]);
    let single_output = run_with_timeout(single, Duration::from_secs(10));

    assert!(
        single_output.status.success(),
        "single-worker summarize failed: {}",
        String::from_utf8_lossy(&single_output.stderr)
    );

    let mut parallel = stitch();
    parallel.args([
        "-j",
        "4",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "search",
        "--query",
        query,
        "--format",
        "jsonl",
    ]);
    let parallel_output = run_with_timeout(parallel, Duration::from_secs(10));

    assert!(
        parallel_output.status.success(),
        "parallel summarize failed: {}",
        String::from_utf8_lossy(&parallel_output.stderr)
    );
    assert_eq!(
        String::from_utf8(single_output.stdout).expect("single output should be UTF-8"),
        String::from_utf8(parallel_output.stdout).expect("parallel output should be UTF-8"),
        "parallel summarize should merge groups deterministically"
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

#[test]
fn search_quiet_still_emits_jsonl_results() {
    let output = stitch()
        .args([
            "search",
            "-i",
            "tests/fixtures/evtx/security-auth.evtx",
            "--query",
            "event.id == 4625",
            "--format",
            "jsonl",
            "--quiet",
        ])
        .output()
        .expect("stitch search should run with quiet JSONL output");

    assert!(
        output.status.success(),
        "stitch search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout =
        String::from_utf8(output.stdout).expect("stitch search quiet output should be valid UTF-8");
    let lines = stdout.lines().collect::<Vec<_>>();

    assert_eq!(
        lines.len(),
        1,
        "quiet search should emit the matching JSONL row, got:\n{stdout}"
    );

    let value: serde_json::Value =
        serde_json::from_str(lines[0]).expect("quiet search output line should be JSON");
    assert_eq!(value["event_id"], 4625);
}
