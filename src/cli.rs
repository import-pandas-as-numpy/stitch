use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "stitch",
    version,
    about = "Parse, search, hunt, and convert Windows EVTX logs",
    long_about = "stitch is a CLI-first Windows Event Log analysis tool for fast EVTX search, Sigma hunting, and format conversion."
)]
pub struct Cli {
    #[command(flatten)]
    pub common: CommonArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args, Clone)]
// Clap argument structs naturally collect independent CLI switches.
#[allow(clippy::struct_excessive_bools)]
pub struct CommonArgs {
    #[arg(
        short,
        long,
        value_name = "PATH",
        global = true,
        help = "File or directory input"
    )]
    pub input: Vec<PathBuf>,

    #[arg(
        long,
        value_name = "FILE",
        global = true,
        help = "Read additional input paths from a newline-delimited file"
    )]
    pub paths_from: Option<PathBuf>,

    #[arg(long, global = true, help = "Do not recurse through input directories")]
    pub no_recursive: bool,

    #[arg(
        short,
        long,
        value_name = "N",
        default_value_t = 0,
        global = true,
        help = "Worker count; 0 uses logical CPU count"
    )]
    pub jobs: usize,

    #[arg(long, global = true, help = "Disable progress output")]
    pub no_progress: bool,

    #[arg(long, global = true, help = "Suppress non-result messages")]
    pub quiet: bool,

    #[arg(
        long,
        global = true,
        help = "Treat recoverable parse, query, or rule issues as errors"
    )]
    pub strict: bool,

    #[arg(long, value_name = "TZ", global = true, help = "Display timezone")]
    pub timezone: Option<String>,

    #[arg(
        long,
        value_name = "TIMESTAMP",
        global = true,
        help = "Inclusive lower timestamp bound"
    )]
    pub from: Option<String>,

    #[arg(
        long,
        value_name = "TIMESTAMP",
        global = true,
        help = "Exclusive upper timestamp bound"
    )]
    pub to: Option<String>,

    #[arg(long, value_name = "GLOB", global = true, help = "Include path glob")]
    pub include: Vec<String>,

    #[arg(long, value_name = "GLOB", global = true, help = "Exclude path glob")]
    pub exclude: Vec<String>,

    #[arg(long, global = true, help = "Print processing stats")]
    pub stats: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Run Sigma rules against EVTX input")]
    Hunt(HuntArgs),
    #[command(about = "Run an ad hoc query against EVTX input")]
    Search(SearchArgs),
    #[command(about = "Serialize EVTX input into another format")]
    Dump(DumpArgs),
}

#[derive(Debug, Args)]
pub struct HuntArgs {
    #[arg(
        long,
        value_name = "PATH",
        required = true,
        help = "Sigma rule file or directory"
    )]
    pub rules: Vec<PathBuf>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Chainsaw-compatible field mapping file"
    )]
    pub mapping: Option<PathBuf>,

    #[arg(
        long = "rule-status",
        value_name = "STATUS",
        help = "Include Sigma rule status"
    )]
    pub rule_status: Vec<String>,

    #[arg(long, value_name = "LEVEL", help = "Include Sigma level")]
    pub level: Vec<String>,

    #[arg(long, value_name = "TAG", help = "Include Sigma tag")]
    pub tag: Vec<String>,

    #[arg(
        long = "exclude-rule",
        value_name = "GLOB",
        help = "Exclude rule path or title glob"
    )]
    pub exclude_rule: Vec<String>,

    #[arg(long, help = "Enable Sigma correlation rules")]
    pub enable_correlation: bool,

    #[arg(long, help = "Disable Sigma correlation rules")]
    pub disable_correlation: bool,

    #[arg(long, value_enum, default_value_t = CorrelationScope::Host)]
    pub correlation_scope: CorrelationScope,

    #[arg(long, value_name = "DURATION", default_value = "2m")]
    pub correlation_lateness: String,

    #[arg(long, value_name = "N", default_value_t = 100_000)]
    pub correlation_max_state: usize,

    #[arg(
        long = "correlation-event-field",
        value_name = "FIELD",
        help = "Include selected contributing-event field in correlation output"
    )]
    pub correlation_event_fields: Vec<String>,

    #[arg(
        long = "correlation-event-limit",
        value_name = "N",
        default_value_t = 3,
        help = "Maximum contributing events to print for each pretty correlation match; 0 hides them"
    )]
    pub correlation_event_limit: usize,

    #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    #[arg(long, value_name = "FILE", help = "Write results to file")]
    pub output: Option<PathBuf>,

    #[arg(long, value_name = "LEVEL", help = "Minimum Sigma level")]
    pub min_level: Option<String>,

    #[arg(long, help = "Print rule and file summary after results")]
    pub summary: bool,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    #[arg(short, long, value_name = "QUERY", conflicts_with = "query_file")]
    pub query: Option<String>,

    #[arg(long, value_name = "FILE", conflicts_with = "query")]
    pub query_file: Option<PathBuf>,

    #[arg(long, value_name = "FIELD", help = "Fields to display")]
    pub fields: Vec<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    #[arg(long, value_name = "N", help = "Stop after N matches")]
    pub limit: Option<usize>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Write skipped parse errors as JSONL"
    )]
    pub errors: Option<PathBuf>,

    #[arg(long, value_name = "N", default_value_t = 0)]
    pub before_context: usize,

    #[arg(long, value_name = "N", default_value_t = 0)]
    pub after_context: usize,

    #[arg(long, help = "Print query plan")]
    pub explain: bool,
}

#[derive(Debug, Args)]
// Dump exposes independent format switches that map directly to CLI flags.
#[allow(clippy::struct_excessive_bools)]
pub struct DumpArgs {
    #[arg(long, value_enum, default_value_t = DumpFormat::Jsonl)]
    pub format: DumpFormat,

    #[arg(long, value_name = "PATH", help = "Output file or directory")]
    pub output: Option<PathBuf>,

    #[arg(long, value_name = "FIELD", help = "Field projection")]
    pub fields: Vec<String>,

    #[arg(long, help = "Flatten nested fields for CSV")]
    pub flatten: bool,

    #[arg(long, help = "Preserve raw parsed event shape")]
    pub raw: bool,

    #[arg(long, help = "Compact JSON output")]
    pub compact: bool,

    #[arg(long, help = "Pretty JSON output")]
    pub pretty: bool,

    #[arg(long, help = "Stop on first parse error")]
    pub fail_fast: bool,

    #[arg(long, value_name = "PATH", help = "Write parse errors as JSONL")]
    pub errors: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Compact,
    Json,
    Jsonl,
    Csv,
    Timeline,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DumpFormat {
    Jsonl,
    Json,
    Csv,
    Xml,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CorrelationScope {
    File,
    Host,
    Global,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser as _;

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
}
