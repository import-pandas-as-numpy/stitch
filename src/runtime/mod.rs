use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{BufWriter, Write as _},
};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::json;
use thiserror::Error;

use crate::cli::{CommonArgs, CorrelationScope, DumpArgs, HuntArgs, OutputFormat, SearchArgs};
use crate::event::Event;
use crate::input::{
    DiscoveryConfig, DiscoveryError, EvtxReadError, EvtxRecordError, discover_inputs,
    read_evtx_events_with_errors,
};
use crate::output::render_search_match;
use crate::query::{QueryError, parse_search_query};
use crate::sigma::{
    CorrelationRuntimeScope, SigmaCorrelationEngine, SigmaCorrelationMatch, SigmaCorrelationRule,
    SigmaLoadError, SigmaRule, load_sigma_rules,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    pub message: Option<String>,
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Evtx(#[from] EvtxReadError),
    #[error(transparent)]
    SigmaLoad(#[from] SigmaLoadError),
    #[error("failed to read query file {path}: {source}")]
    QueryFileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse query: {0}")]
    Query(#[from] QueryError),
    #[error("failed to create search errors file {path}: {source}")]
    SearchErrorsCreate {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write search parse error to {path}: {source}")]
    SearchErrorsWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("search requires --query or --query-file")]
    MissingQuery,
    #[error("search output format {format:?} is not supported yet")]
    UnsupportedSearchFormat { format: OutputFormat },
    #[error(
        "invalid Sigma level {level:?}; expected informational, low, medium, high, or critical"
    )]
    InvalidSigmaLevel { level: String },
    #[error("invalid Sigma rule exclude glob {glob:?}: {message}")]
    InvalidExcludeRuleGlob { glob: String, message: String },
    #[error("{command} is not implemented yet; discovered {input_count} EVTX input(s)")]
    NotImplemented {
        command: &'static str,
        input_count: usize,
    },
}

impl CommandOutcome {
    #[must_use]
    pub fn message(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
        }
    }
}

pub fn run_hunt(
    command: &HuntArgs,
    discovery: &DiscoveryConfig,
    common: &CommonArgs,
) -> Result<CommandOutcome, RunError> {
    let inputs = discover_inputs(discovery)?;
    let rules = load_sigma_rules(&command.rules)?;
    let correlation_rules = rules.correlations.len();
    let skipped_correlation = 0usize;
    let hunt_plan = build_hunt_plan(command, &rules.rules, &rules.correlations)?;
    let mut correlation_engine = if command.disable_correlation {
        SigmaCorrelationEngine::new(&[], runtime_correlation_scope(command.correlation_scope), 0)
    } else {
        SigmaCorrelationEngine::new(
            &rules.correlations,
            runtime_correlation_scope(command.correlation_scope),
            command.correlation_max_state,
        )
    };
    let mut output = Vec::new();
    let mut scanned = 0usize;
    let mut matched = 0usize;
    let mut correlation_matched = 0usize;

    for input in &inputs {
        let _read_stats = read_evtx_events_with_errors(
            input,
            common.strict,
            |event| {
                scanned += 1;

                for planned_rule in &hunt_plan.rules {
                    let rule = planned_rule.rule;
                    if rule.matches(&event) {
                        if planned_rule.emit_alert {
                            matched += 1;
                        }

                        if planned_rule.emit_alert && !common.quiet {
                            output.push(render_hunt_match(rule, &event, command.format));
                        }

                        if planned_rule.feed_correlation && !correlation_engine.is_empty() {
                            for correlation_match in correlation_engine.observe_match(
                                rule,
                                &event,
                                &command.correlation_event_fields,
                            ) {
                                correlation_matched += 1;

                                if !common.quiet {
                                    output.push(render_correlation_match(
                                        &correlation_match,
                                        command.format,
                                        command.correlation_event_limit,
                                    ));
                                }
                            }
                        }
                    }
                }
            },
            |_| {},
        )?;
    }

    if common.quiet {
        return Ok(CommandOutcome { message: None });
    }

    if common.stats {
        if correlation_rules == 0 {
            output.push(format!(
                "stats: scanned={} matched={} rules={} skipped_correlation={} inputs={}",
                scanned,
                matched,
                hunt_plan.alert_rule_count,
                skipped_correlation,
                inputs.len()
            ));
        } else {
            let correlation_stats = correlation_engine.stats();
            output.push(format!(
                "stats: scanned={} matched={} correlation_matched={} rules={} correlation_rules={} correlation_state={} correlation_evicted={} skipped_correlation={} inputs={}",
                scanned,
                matched,
                correlation_matched,
                hunt_plan.alert_rule_count,
                correlation_rules,
                correlation_stats.state_entries,
                correlation_stats.evicted_state_entries,
                skipped_correlation,
                inputs.len()
            ));
        }
    } else if output.is_empty() {
        output.push(format!(
            "hunt loaded {} Sigma rule(s), loaded {} correlation rule(s), skipped {} rule(s), discovered {} EVTX input(s), matched 0 event(s)",
            hunt_plan.alert_rule_count,
            correlation_rules,
            skipped_correlation,
            inputs.len()
        ));
    }

    Ok(CommandOutcome {
        message: (!output.is_empty()).then(|| output.join("\n\n")),
    })
}

fn runtime_correlation_scope(scope: CorrelationScope) -> CorrelationRuntimeScope {
    match scope {
        CorrelationScope::File => CorrelationRuntimeScope::File,
        CorrelationScope::Host => CorrelationRuntimeScope::Host,
        CorrelationScope::Global => CorrelationRuntimeScope::Global,
    }
}

#[derive(Debug)]
struct HuntPlan<'a> {
    rules: Vec<PlannedRule<'a>>,
    alert_rule_count: usize,
}

#[derive(Debug)]
struct PlannedRule<'a> {
    rule: &'a SigmaRule,
    emit_alert: bool,
    feed_correlation: bool,
}

fn build_hunt_plan<'a>(
    command: &HuntArgs,
    rules: &'a [SigmaRule],
    correlations: &[SigmaCorrelationRule],
) -> Result<HuntPlan<'a>, RunError> {
    let alert_rules = filter_hunt_rules(command, rules)?;
    let alert_rule_count = alert_rules.len();
    let correlation_enabled = !command.disable_correlation && !correlations.is_empty();

    let planned = rules
        .iter()
        .filter_map(|rule| {
            let emit_alert = alert_rules
                .iter()
                .any(|alert_rule| std::ptr::eq(*alert_rule, rule));
            let feed_correlation = correlation_enabled
                && correlations.iter().any(|correlation| {
                    rule.is_referenced_by(&correlation.correlation.referenced_rules)
                });

            (emit_alert || feed_correlation).then_some(PlannedRule {
                rule,
                emit_alert,
                feed_correlation,
            })
        })
        .collect();

    Ok(HuntPlan {
        rules: planned,
        alert_rule_count,
    })
}

fn filter_hunt_rules<'a>(
    command: &HuntArgs,
    rules: &'a [SigmaRule],
) -> Result<Vec<&'a SigmaRule>, RunError> {
    let min_level = command
        .min_level
        .as_deref()
        .map(parse_sigma_level)
        .transpose()?;
    let exclude_rules = build_exclude_rule_globs(&command.exclude_rule)?;

    Ok(rules
        .iter()
        .filter(|rule| rule_matches_hunt_filters(rule, command, min_level, exclude_rules.as_ref()))
        .collect())
}

fn rule_matches_hunt_filters(
    rule: &SigmaRule,
    command: &HuntArgs,
    min_level: Option<u8>,
    exclude_rules: Option<&GlobSet>,
) -> bool {
    if !matches_text_filter(rule.status.as_deref(), &command.rule_status) {
        return false;
    }

    if !matches_text_filter(rule.level.as_deref(), &command.level) {
        return false;
    }

    if !matches_tag_filter(&rule.tags, &command.tag) {
        return false;
    }

    if !matches_min_level(rule.level.as_deref(), min_level) {
        return false;
    }

    if exclude_rules.is_some_and(|exclude_rules| {
        exclude_rules.is_match(&rule.path) || exclude_rules.is_match(rule.title.as_str())
    }) {
        return false;
    }

    true
}

fn matches_text_filter(value: Option<&str>, filters: &[String]) -> bool {
    filters.is_empty()
        || value.is_some_and(|value| {
            filters
                .iter()
                .any(|filter| value.eq_ignore_ascii_case(filter))
        })
}

fn matches_tag_filter(tags: &[String], filters: &[String]) -> bool {
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| tags.iter().any(|tag| tag.eq_ignore_ascii_case(filter)))
}

fn matches_min_level(level: Option<&str>, minimum: Option<u8>) -> bool {
    let Some(minimum) = minimum else {
        return true;
    };

    level
        .and_then(|level| parse_sigma_level(level).ok())
        .is_some_and(|level| level >= minimum)
}

fn parse_sigma_level(level: &str) -> Result<u8, RunError> {
    match level.to_ascii_lowercase().as_str() {
        "informational" | "info" => Ok(0),
        "low" => Ok(1),
        "medium" => Ok(2),
        "high" => Ok(3),
        "critical" => Ok(4),
        _ => Err(RunError::InvalidSigmaLevel {
            level: level.to_owned(),
        }),
    }
}

fn build_exclude_rule_globs(patterns: &[String]) -> Result<Option<GlobSet>, RunError> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();

    for pattern in patterns {
        let glob = Glob::new(pattern).map_err(|error| RunError::InvalidExcludeRuleGlob {
            glob: pattern.clone(),
            message: error.to_string(),
        })?;
        builder.add(glob);
    }

    let globset = builder
        .build()
        .map_err(|error| RunError::InvalidExcludeRuleGlob {
            glob: patterns.join(", "),
            message: error.to_string(),
        })?;

    Ok(Some(globset))
}

pub fn run_search(
    command: &SearchArgs,
    discovery: &DiscoveryConfig,
    common: &CommonArgs,
) -> Result<CommandOutcome, RunError> {
    if matches!(
        command.format,
        OutputFormat::Csv | OutputFormat::Compact | OutputFormat::Timeline
    ) {
        return Err(RunError::UnsupportedSearchFormat {
            format: command.format,
        });
    }

    let query = read_query(command)?;
    let query = parse_search_query(&query)?;

    if command.explain {
        return Ok(CommandOutcome::message(format!("{query:#?}")));
    }

    let output_fields = search_output_fields(command, &query.keep_fields);
    let inputs = discover_inputs(discovery)?;
    let mut output = Vec::new();
    let mut stats = SearchStats::default();
    let mut error_writer = SearchErrorWriter::new(command)?;

    for input in &inputs {
        if reached_limit(command.limit, stats.matched) {
            break;
        }

        let read_stats = read_evtx_events_with_errors(
            input,
            common.strict,
            |event| {
                if reached_limit(command.limit, stats.matched) {
                    return;
                }

                stats.scanned += 1;

                if query.filter.evaluate(&event) {
                    stats.matched += 1;

                    if !common.quiet {
                        output.push(render_search_match(&event, output_fields, command.format));
                    }
                }
            },
            |error| error_writer.write(error),
        )?;

        stats.parse_errors += read_stats.records_failed;
        stats.add_parse_error_samples(read_stats.error_samples);
    }

    error_writer.finish()?;

    if common.stats && !common.quiet {
        output.push(stats.render());
    }

    Ok(CommandOutcome {
        message: (!output.is_empty()).then(|| output.join("\n\n")),
    })
}

pub fn run_dump(
    _command: &DumpArgs,
    discovery: &DiscoveryConfig,
    common: &CommonArgs,
) -> Result<CommandOutcome, RunError> {
    let input_count = discover_inputs(discovery)?.len();

    if common.quiet {
        return Err(RunError::NotImplemented {
            command: "dump",
            input_count,
        });
    }

    Err(RunError::NotImplemented {
        command: "dump",
        input_count,
    })
}

fn read_query(command: &SearchArgs) -> Result<String, RunError> {
    if let Some(query) = &command.query {
        return Ok(query.clone());
    }

    if let Some(path) = &command.query_file {
        return fs::read_to_string(path).map_err(|source| RunError::QueryFileRead {
            path: path.display().to_string(),
            source,
        });
    }

    Err(RunError::MissingQuery)
}

fn reached_limit(limit: Option<usize>, matched: usize) -> bool {
    limit.is_some_and(|limit| matched >= limit)
}

fn search_output_fields<'a>(command: &'a SearchArgs, keep_fields: &'a [String]) -> &'a [String] {
    if command.fields.is_empty() {
        keep_fields
    } else {
        &command.fields
    }
}

fn render_hunt_match(rule: &SigmaRule, event: &Event, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => render_hunt_json(rule, event, format),
        OutputFormat::Pretty
        | OutputFormat::Compact
        | OutputFormat::Csv
        | OutputFormat::Timeline => render_hunt_pretty(rule, event),
    }
}

fn render_hunt_pretty(rule: &SigmaRule, event: &Event) -> String {
    let timestamp = event.metadata.timestamp.as_deref().unwrap_or("-");
    let level = rule.level.as_deref().unwrap_or("-");
    let channel = event.metadata.channel.as_deref().unwrap_or("-");
    let event_id = event
        .metadata
        .event_id
        .map_or_else(|| "-".to_owned(), |value| value.to_string());
    let computer = event.metadata.computer.as_deref().unwrap_or("-");
    let record_id = event
        .metadata
        .record_id
        .map_or_else(|| "-".to_owned(), |value| value.to_string());

    format!(
        "{timestamp}  {level}  {channel}  {event_id}  {}\n  host: {computer}  file: {}  record: {record_id}",
        rule.title,
        event.source.file_path.display()
    )
}

fn render_hunt_json(rule: &SigmaRule, event: &Event, format: OutputFormat) -> String {
    let value = json!({
        "type": "sigma_match",
        "rule": {
            "title": rule.title,
            "id": rule.id,
            "level": rule.level,
            "status": rule.status,
            "tags": rule.tags,
            "path": rule.path,
        },
        "event": {
            "timestamp": event.metadata.timestamp,
            "record_id": event.metadata.record_id,
            "channel": event.metadata.channel,
            "provider": event.metadata.provider,
            "event_id": event.metadata.event_id,
            "computer": event.metadata.computer,
            "source": {
                "file_path": event.source.file_path,
                "collection_root": event.source.collection_root,
            }
        }
    });

    if matches!(format, OutputFormat::Json) {
        serde_json::to_string_pretty(&value)
            .expect("serializing a serde_json::Value should not fail")
    } else {
        value.to_string()
    }
}

fn render_correlation_match(
    correlation_match: &SigmaCorrelationMatch,
    format: OutputFormat,
    event_limit: usize,
) -> String {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            render_correlation_json(correlation_match, format)
        }
        OutputFormat::Pretty
        | OutputFormat::Compact
        | OutputFormat::Csv
        | OutputFormat::Timeline => render_correlation_pretty(correlation_match, event_limit),
    }
}

fn render_correlation_pretty(
    correlation_match: &SigmaCorrelationMatch,
    event_limit: usize,
) -> String {
    let level = correlation_match.rule.level.as_deref().unwrap_or("-");
    let group = if correlation_match.group.is_empty() {
        "global".to_owned()
    } else {
        correlation_match
            .group
            .iter()
            .map(|(field, value)| format!("{field}={value}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut output = format!(
        "{}  {level}  correlation  {}  count={}\n  group: {group}  window: {}..{}",
        correlation_match.window_end,
        correlation_match.rule.title,
        correlation_match.matches.len(),
        correlation_match.window_start,
        correlation_match.window_end
    );

    if event_limit > 0
        && correlation_match
            .matches
            .iter()
            .any(|source| !source.fields.is_empty())
    {
        let shown = correlation_match.matches.len().min(event_limit);
        let _ = write!(output, "\n  contributing events:");

        for source_match in correlation_match.matches.iter().take(event_limit) {
            let event_id = source_match
                .event_id
                .map_or_else(|| "-".to_owned(), |value| value.to_string());
            let record_id = source_match
                .record_id
                .map_or_else(|| "-".to_owned(), |value| value.to_string());
            let channel = source_match.channel.as_deref().unwrap_or("-");
            let _ = write!(
                output,
                "\n    {}  {}  event_id={}  record={}  rule={}",
                source_match.timestamp, channel, event_id, record_id, source_match.rule_title
            );

            for (field, value) in &source_match.fields {
                let value = value.as_deref().unwrap_or("-");
                let _ = write!(output, "\n      {field}: {value}");
            }
        }

        if correlation_match.matches.len() > shown {
            let remaining = correlation_match.matches.len() - shown;
            let _ = write!(
                output,
                "\n    ... {remaining} more contributing event(s); increase --correlation-event-limit to show more"
            );
        }
    }

    output
}

fn render_correlation_json(
    correlation_match: &SigmaCorrelationMatch,
    format: OutputFormat,
) -> String {
    let group = correlation_match
        .group
        .iter()
        .map(|(field, value)| (field.clone(), json!(value)))
        .collect::<serde_json::Map<_, _>>();
    let matches = correlation_match
        .matches
        .iter()
        .map(|source_match| {
            let fields = source_match
                .fields
                .iter()
                .map(|(field, value)| {
                    let value = value
                        .as_ref()
                        .map_or(serde_json::Value::Null, |value| json!(value));
                    (field.clone(), value)
                })
                .collect::<serde_json::Map<_, _>>();

            json!({
                "rule": {
                    "title": source_match.rule_title,
                    "id": source_match.rule_id,
                    "name": source_match.rule_name,
                },
                "event": {
                    "timestamp": source_match.timestamp,
                    "record_id": source_match.record_id,
                    "channel": source_match.channel,
                    "event_id": source_match.event_id,
                    "computer": source_match.computer,
                    "source": {
                        "file_path": source_match.file_path,
                    },
                    "fields": fields,
                }
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "type": "sigma_correlation_match",
        "timestamp": correlation_match.window_end,
        "rule": {
            "title": correlation_match.rule.title,
            "id": correlation_match.rule.id,
            "name": correlation_match.rule.name,
            "level": correlation_match.rule.level,
            "status": correlation_match.rule.status,
            "tags": correlation_match.rule.tags,
            "path": correlation_match.rule.path,
        },
        "group": group,
        "window": {
            "start": correlation_match.window_start,
            "end": correlation_match.window_end,
        },
        "matches": matches,
    });

    if matches!(format, OutputFormat::Json) {
        serde_json::to_string_pretty(&value)
            .expect("serializing a serde_json::Value should not fail")
    } else {
        value.to_string()
    }
}

struct SearchErrorWriter {
    path: Option<String>,
    writer: Option<BufWriter<File>>,
    error: Option<std::io::Error>,
}

impl SearchErrorWriter {
    fn new(command: &SearchArgs) -> Result<Self, RunError> {
        let Some(path) = &command.errors else {
            return Ok(Self {
                path: None,
                writer: None,
                error: None,
            });
        };
        let path_label = path.display().to_string();
        let file = File::create(path).map_err(|source| RunError::SearchErrorsCreate {
            path: path_label.clone(),
            source,
        })?;

        Ok(Self {
            path: Some(path_label),
            writer: Some(BufWriter::new(file)),
            error: None,
        })
    }

    fn write(&mut self, error: &EvtxRecordError) {
        if self.error.is_some() {
            return;
        }

        let Some(writer) = &mut self.writer else {
            return;
        };

        let line = json!({
            "file_path": error.path,
            "error": error.message,
        })
        .to_string();

        if let Err(source) = writeln!(writer, "{line}") {
            self.error = Some(source);
        }
    }

    fn finish(self) -> Result<(), RunError> {
        let Some(path) = self.path else {
            return Ok(());
        };

        if let Some(source) = self.error {
            return Err(RunError::SearchErrorsWrite { path, source });
        }

        let Some(mut writer) = self.writer else {
            return Ok(());
        };

        writer
            .flush()
            .map_err(|source| RunError::SearchErrorsWrite { path, source })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SearchStats {
    scanned: usize,
    matched: usize,
    parse_errors: usize,
    parse_error_samples: Vec<EvtxRecordError>,
}

impl SearchStats {
    const MAX_PARSE_ERROR_SAMPLES: usize = 5;

    fn add_parse_error_samples(&mut self, samples: Vec<EvtxRecordError>) {
        let remaining =
            Self::MAX_PARSE_ERROR_SAMPLES.saturating_sub(self.parse_error_samples.len());

        self.parse_error_samples
            .extend(samples.into_iter().take(remaining));
    }

    fn render(self) -> String {
        let mut output = format!(
            "stats: scanned={} matched={} parse_errors={}",
            self.scanned, self.matched, self.parse_errors
        );

        for sample in self.parse_error_samples {
            let _ = write!(
                output,
                "\n  parse_error: file={} error={}",
                sample.path,
                one_line_error(&sample.message)
            );
        }

        output
    }
}

fn one_line_error(message: &str) -> String {
    message
        .split_whitespace()
        .fold(String::new(), |mut output, word| {
            if !output.is_empty() {
                output.push(' ');
            }

            output.push_str(word);
            output
        })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use crate::cli::{CorrelationScope, HuntArgs, SearchArgs};
    use crate::input::DiscoveredInput;

    use super::*;

    #[test]
    fn reads_inline_query() {
        let args = SearchArgs {
            query: Some("event.id == 4625".to_owned()),
            query_file: None,
            fields: Vec::new(),
            format: crate::cli::OutputFormat::Pretty,
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
            format: crate::cli::OutputFormat::Pretty,
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
        let args = SearchArgs {
            query: Some("event.id == 4625".to_owned()),
            query_file: None,
            fields: Vec::new(),
            format: crate::cli::OutputFormat::Pretty,
            limit: None,
            errors: Some(path.clone()),
            before_context: 0,
            after_context: 0,
            explain: false,
        };
        let mut writer = SearchErrorWriter::new(&args).expect("writer should be created");

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
            &DiscoveredInput {
                path: PathBuf::from("Security.evtx"),
                collection_root: PathBuf::from("."),
            },
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

        let output = render_hunt_match(&rule, &event, OutputFormat::Jsonl);
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("hunt JSONL should be valid JSON");

        assert_eq!(value["rule"]["title"], "Suspicious Process");
        assert_eq!(value["rule"]["level"], "high");
        assert_eq!(value["event"]["event_id"], 4688);
        assert_eq!(value["event"]["computer"], "WIN-01");
        assert_eq!(value["event"]["source"]["file_path"], "Security.evtx");
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
            output: None,
            min_level: None,
            summary: false,
        }
    }
}
