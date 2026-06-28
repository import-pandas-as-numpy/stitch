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
fn hunt_parallel_jobs_match_single_worker_without_correlation() {
    let paths = repeated_paths_file(
        &[
            "tests/fixtures/evtx/security-auth.evtx",
            "tests/fixtures/evtx/sysmon-activity.evtx",
            "tests/fixtures/evtx/wmi-activity.evtx",
            "tests/fixtures/evtx/task-scheduler-operational.evtx",
            "tests/fixtures/evtx/defender-operational.evtx",
        ],
        10,
    );

    let mut single = stitch();
    single.args([
        "-j",
        "1",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "hunt",
        "--rules",
        "tests/fixtures/sigma",
        "--format",
        "jsonl",
        "--stats",
    ]);
    let single_output = run_with_timeout(single, Duration::from_secs(10));

    assert!(
        single_output.status.success(),
        "single-worker hunt failed: {}",
        String::from_utf8_lossy(&single_output.stderr)
    );

    let mut parallel = stitch();
    parallel.args([
        "-j",
        "4",
        "--paths-from",
        paths.path().to_str().expect("temp path should be UTF-8"),
        "hunt",
        "--rules",
        "tests/fixtures/sigma",
        "--format",
        "jsonl",
        "--stats",
    ]);
    let parallel_output = run_with_timeout(parallel, Duration::from_secs(10));

    assert!(
        parallel_output.status.success(),
        "parallel hunt failed: {}",
        String::from_utf8_lossy(&parallel_output.stderr)
    );
    assert_eq!(
        String::from_utf8(single_output.stdout).expect("single output should be UTF-8"),
        String::from_utf8(parallel_output.stdout).expect("parallel output should be UTF-8"),
        "parallel hunt output should match single-worker output"
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
fn hunt_correlation_with_jobs_stays_ordered_and_completes() {
    let mut command = stitch();
    command.args([
        "-j",
        "4",
        "hunt",
        "-i",
        "tests/fixtures/correlation-evtx/sysmon-correlation.evtx",
        "--rules",
        "tests/fixtures/sigma-correlation",
        "--format",
        "jsonl",
        "--stats",
    ]);
    let output = run_with_timeout(command, Duration::from_secs(10));

    assert!(
        output.status.success(),
        "correlation hunt with jobs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("correlation hunt output should be UTF-8");
    assert!(
        stdout.contains(r#""type":"sigma_correlation_match""#),
        "expected correlation match with --jobs 4, got:\n{stdout}"
    );
    assert!(
        stdout.contains("stats: scanned=4 matched=8 correlation_matched=3"),
        "expected stable correlation stats with --jobs 4, got:\n{stdout}"
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
        pretty_stdout.contains("│ Payload"),
        "expected pretty correlation output to include an in-table payload column, got:\n{pretty_stdout}"
    );
    assert!(
        pretty_stdout.contains("DestinationIp: null"),
        "expected pretty correlation output to include selected contributing-event data in the payload column, got:\n{pretty_stdout}"
    );
    assert!(
        pretty_stdout.contains("Image:") && pretty_stdout.contains("WindowsPowerShell"),
        "expected selected Image field in pretty correlation output, got:\n{pretty_stdout}"
    );
    assert!(
        pretty_stdout.contains("... 2 more")
            && pretty_stdout.contains("contributing event(s)")
            && pretty_stdout.contains("correlation-event-limit"),
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
