use std::path::PathBuf;

use clap::{CommandFactory as _, Parser as _};

use super::{Cli, Command};

#[test]
fn accepts_common_options_before_subcommand() {
    let cli = Cli::try_parse_from([
        "stitch",
        "-i",
        "Security.evtx",
        "--stats",
        "search",
        "-q",
        "event.id == 4625",
    ])
    .expect("CLI should parse common options before subcommand");

    assert_eq!(cli.common.input, [PathBuf::from("Security.evtx")]);
    assert!(cli.common.stats);
    assert!(matches!(cli.command, Command::Search(_)));
}

#[test]
fn accepts_common_options_after_subcommand() {
    let cli = Cli::try_parse_from([
        "stitch",
        "search",
        "-q",
        "event.id == 4625",
        "-i",
        "Security.evtx",
        "--stats",
    ])
    .expect("CLI should parse common options after subcommand");

    assert_eq!(cli.common.input, [PathBuf::from("Security.evtx")]);
    assert!(cli.common.stats);
    assert!(matches!(cli.command, Command::Search(_)));
}

#[test]
fn search_help_lists_only_supported_formats() {
    let help = Cli::command()
        .find_subcommand_mut("search")
        .expect("search subcommand should exist")
        .render_help()
        .to_string();

    assert!(
        help.contains("[possible values: pretty, json, jsonl]"),
        "search help should list only supported formats:\n{help}"
    );
    assert!(!help.contains("csv"));
    assert!(!help.contains("timeline"));
}

#[test]
fn search_rejects_unsupported_formats_at_parse_time() {
    let error = Cli::try_parse_from([
        "stitch",
        "search",
        "-q",
        "event.id == 4625",
        "--format",
        "csv",
    ])
    .expect_err("search --format csv should be rejected by the parser");

    assert!(
        error.to_string().contains("invalid value 'csv'"),
        "unsupported search format should fail as an invalid value, got:\n{error}"
    );
}

#[test]
fn dump_help_does_not_advertise_flatten() {
    let help = Cli::command()
        .find_subcommand_mut("dump")
        .expect("dump subcommand should exist")
        .render_help()
        .to_string();

    assert!(
        !help.contains("--flatten"),
        "dump help should not list unimplemented --flatten flag:\n{help}"
    );
}

#[test]
fn dump_rejects_flatten_at_parse_time() {
    let error = Cli::try_parse_from([
        "stitch",
        "dump",
        "-i",
        "Security.evtx",
        "--format",
        "csv",
        "--flatten",
        "--fields",
        "event.id",
    ])
    .expect_err("dump --flatten should be rejected by the parser");

    assert!(
        error
            .to_string()
            .contains("unexpected argument '--flatten'"),
        "unimplemented dump flag should fail as an unexpected argument, got:\n{error}"
    );
}

#[test]
fn global_help_does_not_advertise_timezone() {
    let help = Cli::command().render_help().to_string();

    assert!(
        !help.contains("--timezone"),
        "global help should not list unimplemented --timezone flag:\n{help}"
    );
}

#[test]
fn timezone_is_rejected_at_parse_time() {
    let error = Cli::try_parse_from([
        "stitch",
        "search",
        "-i",
        "Security.evtx",
        "-q",
        "event.id == 4625",
        "--timezone",
        "America/New_York",
    ])
    .expect_err("unimplemented --timezone should be rejected by the parser");

    assert!(
        error
            .to_string()
            .contains("unexpected argument '--timezone'"),
        "unimplemented timezone flag should fail as an unexpected argument, got:\n{error}"
    );
}
