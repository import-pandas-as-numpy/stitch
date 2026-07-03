use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    fs::{self, File},
    io::{BufWriter, IsTerminal as _, Stdout, Write as _},
};

use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use serde_json::json;
use thiserror::Error;

use crate::cli::{
    CommonArgs, CorrelationScope, DumpArgs, DumpFormat, HuntArgs, OutputFormat, SearchArgs,
};
use crate::event::Event;
use crate::input::{
    DiscoveredInput, DiscoveryConfig, DiscoveryError, EvtxReadError, EvtxRecordError,
    discover_inputs, read_evtx_events_with_errors, read_evtx_records_with_errors,
};
use crate::output::{
    DisplayStyle, dump_json_value, render_event_payload, render_search_match,
    search_match_delimiter,
};
use crate::query::{AggregateFunction, QueryError, SearchQuery, Summarize, parse_search_query};
use crate::sigma::{
    CorrelationRuntimeScope, SigmaCorrelationEngine, SigmaCorrelationMatch, SigmaCorrelationRule,
    SigmaEventContext, SigmaLoadError, SigmaRule, load_sigma_rules, load_sigma_rules_non_strict,
    parse_sigma_duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    pub message: Option<String>,
    pub diagnostic: Option<String>,
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
    #[error("failed to create parse errors file {path}: {source}")]
    ParseErrorsCreate {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write parse error to {path}: {source}")]
    ParseErrorsWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("search requires --query or --query-file")]
    MissingQuery,
    #[error("failed to write output to stdout: {0}")]
    StdoutWrite(std::io::Error),
    #[error(
        "invalid Sigma level {level:?}; expected informational, low, medium, high, or critical"
    )]
    InvalidSigmaLevel { level: String },
    #[error("invalid Sigma rule exclude glob {glob:?}: {message}")]
    InvalidExcludeRuleGlob { glob: String, message: String },
    #[error("invalid correlation lateness {value:?}; expected values like 30s, 5m, 2h, or 1d")]
    InvalidCorrelationLateness { value: String },
    #[error("dump output format {format:?} is not supported yet")]
    UnsupportedDumpFormat { format: DumpFormat },
    #[error("dump --format csv requires at least one --fields value")]
    DumpCsvRequiresFields,
    #[error("dump --format csv does not support --raw; use --fields to choose CSV columns")]
    DumpCsvRawUnsupported,
    #[error("failed to create dump output file {path}: {source}")]
    DumpOutputCreate {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write dump output to {path}: {source}")]
    DumpOutputWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to build worker pool: {0}")]
    WorkerPoolBuild(#[from] rayon::ThreadPoolBuildError),
}

impl CommandOutcome {
    #[must_use]
    pub fn message(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            diagnostic: None,
        }
    }
}

pub fn run_hunt(
    command: &HuntArgs,
    discovery: &DiscoveryConfig,
    common: &CommonArgs,
) -> Result<CommandOutcome, RunError> {
    let inputs = discover_inputs(discovery)?;
    let rules = if common.strict {
        load_sigma_rules(&command.rules)?
    } else {
        load_sigma_rules_non_strict(&command.rules)?
    };
    let correlation_rules = rules.correlations.len();
    let skipped_rules = rules.skipped_rules;
    let hunt_plan = build_hunt_plan(command, &rules.rules, &rules.correlations)?;
    let mut correlation_engine = build_correlation_engine(command, &rules.correlations)?;
    let HuntRunResult {
        mut output,
        scanned,
        matched,
        correlation_matched,
    } = run_hunt_inputs(
        &inputs,
        &hunt_plan,
        command,
        common,
        &mut correlation_engine,
    )?;

    if common.stats {
        if correlation_rules == 0 {
            output.push(HuntRenderedOutput::Text(format!(
                "stats: scanned={} matched={} rules={} skipped_rules={} inputs={}",
                scanned,
                matched,
                hunt_plan.alert_rule_count,
                skipped_rules,
                inputs.len()
            )));
        } else {
            let correlation_stats = correlation_engine.stats();
            output.push(HuntRenderedOutput::Text(format!(
                "stats: scanned={} matched={} correlation_matched={} rules={} correlation_rules={} correlation_state={} correlation_evicted={} skipped_rules={} inputs={}",
                scanned,
                matched,
                correlation_matched,
                hunt_plan.alert_rule_count,
                correlation_rules,
                correlation_stats.state_entries,
                correlation_stats.evicted_state_entries,
                skipped_rules,
                inputs.len()
            )));
        }
    }

    let diagnostic = (!common.quiet && (command.summary || skipped_rules > 0)).then(|| {
        let mut message = format!(
            "hunt loaded {} Sigma rule(s), loaded {} correlation rule(s), skipped {} rule(s), discovered {} EVTX input(s), matched {} event(s)",
            hunt_plan.alert_rule_count,
            correlation_rules,
            skipped_rules,
            inputs.len(),
            matched + correlation_matched
        );
        if skipped_rules > 0 && !command.summary {
            message.insert_str(0, "warning: ");
        }
        message
    });

    let output = render_hunt_outputs(output);

    Ok(CommandOutcome {
        message: (!output.is_empty()).then(|| output.join("\n\n")),
        diagnostic,
    })
}

fn run_parallel_by_input<T: Send>(
    inputs: &[DiscoveredInput],
    common: &CommonArgs,
    work: impl Fn(&DiscoveredInput) -> Result<T, RunError> + Sync + Send,
) -> Result<Vec<T>, RunError> {
    let mut builder = rayon::ThreadPoolBuilder::new();

    if common.jobs > 0 {
        builder = builder.num_threads(common.jobs);
    }

    let pool = builder.build()?;
    pool.install(|| inputs.par_iter().map(work).collect())
}

#[derive(Debug, Default)]
struct HuntRunResult {
    output: Vec<HuntRenderedOutput>,
    scanned: usize,
    matched: usize,
    correlation_matched: usize,
}

#[derive(Debug)]
enum HuntRenderedOutput {
    Text(String),
    PrettyMatch { full_output: bool, row: Vec<String> },
}

fn render_hunt_outputs(items: Vec<HuntRenderedOutput>) -> Vec<String> {
    let mut output = Vec::new();
    let mut pending_rows = Vec::new();
    let mut pending_full_output = false;

    for item in items {
        match item {
            HuntRenderedOutput::PrettyMatch { full_output, row } => {
                if !pending_rows.is_empty() && pending_full_output != full_output {
                    output.push(render_hunt_pretty_table(&pending_rows, pending_full_output));
                    pending_rows.clear();
                }
                pending_full_output = full_output;
                pending_rows.push(row);
            }
            HuntRenderedOutput::Text(text) => {
                if !pending_rows.is_empty() {
                    output.push(render_hunt_pretty_table(&pending_rows, pending_full_output));
                    pending_rows.clear();
                }
                output.push(text);
            }
        }
    }

    if !pending_rows.is_empty() {
        output.push(render_hunt_pretty_table(&pending_rows, pending_full_output));
    }

    output
}

fn run_hunt_inputs(
    inputs: &[DiscoveredInput],
    hunt_plan: &HuntPlan<'_>,
    command: &HuntArgs,
    common: &CommonArgs,
    correlation_engine: &mut SigmaCorrelationEngine,
) -> Result<HuntRunResult, RunError> {
    if correlation_engine.is_empty() {
        return run_hunt_inputs_without_correlation(inputs, hunt_plan, command, common);
    }

    run_hunt_inputs_with_correlation(inputs, hunt_plan, command, common, correlation_engine)
}

fn run_hunt_inputs_without_correlation(
    inputs: &[DiscoveredInput],
    hunt_plan: &HuntPlan<'_>,
    command: &HuntArgs,
    common: &CommonArgs,
) -> Result<HuntRunResult, RunError> {
    let mut run = HuntRunResult::default();
    let results = if should_parallelize(inputs, common) {
        run_parallel_by_input(inputs, common, |input| {
            process_hunt_input_without_correlation(input, hunt_plan, command, common)
        })?
    } else {
        inputs
            .iter()
            .map(|input| process_hunt_input_without_correlation(input, hunt_plan, command, common))
            .collect::<Result<Vec<_>, _>>()?
    };

    for result in results {
        run.scanned += result.scanned;
        run.matched += result.matched;

        if !common.quiet {
            run.output.extend(result.output);
        }
    }

    Ok(run)
}

fn run_hunt_inputs_with_correlation(
    inputs: &[DiscoveredInput],
    hunt_plan: &HuntPlan<'_>,
    command: &HuntArgs,
    common: &CommonArgs,
    correlation_engine: &mut SigmaCorrelationEngine,
) -> Result<HuntRunResult, RunError> {
    let mut run = HuntRunResult::default();

    for input in inputs {
        read_evtx_events_with_errors(
            input,
            common.strict,
            |event| {
                process_hunt_event_with_correlation(
                    &event,
                    hunt_plan,
                    command,
                    common,
                    correlation_engine,
                    &mut run,
                );
            },
            |_| {},
        )?;
    }

    Ok(run)
}

fn process_hunt_event_with_correlation(
    event: &Event,
    hunt_plan: &HuntPlan<'_>,
    command: &HuntArgs,
    common: &CommonArgs,
    correlation_engine: &mut SigmaCorrelationEngine,
    run: &mut HuntRunResult,
) {
    run.scanned += 1;
    let context = SigmaEventContext::new(event);

    for_each_candidate_rule(hunt_plan, event, |planned_rule| {
        let rule = planned_rule.rule;

        if !rule.matches_context(&context) {
            return;
        }

        if planned_rule.emit_alert {
            run.matched += 1;

            if !common.quiet {
                run.output.push(render_hunt_output(
                    rule,
                    event,
                    command.format,
                    command.full,
                ));
            }
        }

        if planned_rule.feed_correlation {
            for correlation_match in
                correlation_engine.observe_match(rule, event, &command.correlation_event_fields)
            {
                run.correlation_matched += 1;

                if !common.quiet {
                    run.output
                        .push(HuntRenderedOutput::Text(render_correlation_match(
                            &correlation_match,
                            command.format,
                            command.correlation_event_limit,
                            command.full,
                        )));
                }
            }
        }
    });
}

fn should_parallelize(inputs: &[DiscoveredInput], common: &CommonArgs) -> bool {
    inputs.len() > 1 && common.jobs != 1
}

#[derive(Debug, Default)]
struct HuntInputResult {
    scanned: usize,
    matched: usize,
    output: Vec<HuntRenderedOutput>,
}

fn process_hunt_input_without_correlation(
    input: &DiscoveredInput,
    hunt_plan: &HuntPlan<'_>,
    command: &HuntArgs,
    common: &CommonArgs,
) -> Result<HuntInputResult, RunError> {
    let mut result = HuntInputResult::default();

    if common.quiet && !common.stats {
        let read_stats = read_evtx_records_with_errors(input, common.strict, |_| {})?;
        result.scanned = read_stats.records_seen;
        return Ok(result);
    }

    read_evtx_events_with_errors(
        input,
        common.strict,
        |event| {
            result.scanned += 1;
            let context = SigmaEventContext::new(&event);

            for_each_candidate_rule(hunt_plan, &event, |planned_rule| {
                let rule = planned_rule.rule;

                if planned_rule.emit_alert && rule.matches_context(&context) {
                    result.matched += 1;

                    if !common.quiet {
                        result.output.push(render_hunt_output(
                            rule,
                            &event,
                            command.format,
                            command.full,
                        ));
                    }
                }
            });
        },
        |_| {},
    )?;

    Ok(result)
}

fn runtime_correlation_scope(scope: CorrelationScope) -> CorrelationRuntimeScope {
    match scope {
        CorrelationScope::File => CorrelationRuntimeScope::File,
        CorrelationScope::Host => CorrelationRuntimeScope::Host,
        CorrelationScope::Global => CorrelationRuntimeScope::Global,
    }
}

fn build_correlation_engine(
    command: &HuntArgs,
    correlations: &[SigmaCorrelationRule],
) -> Result<SigmaCorrelationEngine, RunError> {
    if command.disable_correlation {
        return Ok(SigmaCorrelationEngine::new(
            &[],
            runtime_correlation_scope(command.correlation_scope),
            0,
        ));
    }

    let correlation_lateness =
        parse_sigma_duration(&command.correlation_lateness).ok_or_else(|| {
            RunError::InvalidCorrelationLateness {
                value: command.correlation_lateness.clone(),
            }
        })?;

    Ok(SigmaCorrelationEngine::new_with_lateness(
        correlations,
        runtime_correlation_scope(command.correlation_scope),
        command.correlation_max_state,
        correlation_lateness,
    ))
}

#[derive(Debug)]
struct HuntPlan<'a> {
    rules: Vec<PlannedRule<'a>>,
    general_rule_indices: Vec<usize>,
    channel_rule_indices: HashMap<String, Vec<usize>>,
    event_id_rule_indices: HashMap<u64, Vec<usize>>,
    channel_event_id_rule_indices: HashMap<(String, u64), Vec<usize>>,
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

    let planned: Vec<_> = rules
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
    let rule_indices = index_planned_rules(&planned);

    Ok(HuntPlan {
        rules: planned,
        general_rule_indices: rule_indices.general,
        channel_rule_indices: rule_indices.channel,
        event_id_rule_indices: rule_indices.event_id,
        channel_event_id_rule_indices: rule_indices.channel_event_id,
        alert_rule_count,
    })
}

#[derive(Debug, Default)]
struct HuntRuleIndex {
    general: Vec<usize>,
    channel: HashMap<String, Vec<usize>>,
    event_id: HashMap<u64, Vec<usize>>,
    channel_event_id: HashMap<(String, u64), Vec<usize>>,
}

fn index_planned_rules(planned: &[PlannedRule<'_>]) -> HuntRuleIndex {
    let mut index = HuntRuleIndex::default();

    for (rule_index, planned_rule) in planned.iter().enumerate() {
        match (
            planned_rule.rule.required_channels(),
            planned_rule.rule.required_event_ids(),
        ) {
            (Some(channels), Some(event_ids)) => {
                for channel in channels {
                    let channel = normalize_hunt_index_channel(&channel);
                    for event_id in &event_ids {
                        index
                            .channel_event_id
                            .entry((channel.clone(), *event_id))
                            .or_default()
                            .push(rule_index);
                    }
                }
            }
            (Some(channels), None) => {
                for channel in channels {
                    index
                        .channel
                        .entry(normalize_hunt_index_channel(&channel))
                        .or_default()
                        .push(rule_index);
                }
            }
            (None, Some(event_ids)) => {
                for event_id in event_ids {
                    index.event_id.entry(event_id).or_default().push(rule_index);
                }
            }
            (None, None) => index.general.push(rule_index),
        }
    }

    index
}

fn for_each_candidate_rule<'a>(
    hunt_plan: &'a HuntPlan<'a>,
    event: &Event,
    mut visit: impl FnMut(&'a PlannedRule<'a>),
) {
    for index in &hunt_plan.general_rule_indices {
        visit(&hunt_plan.rules[*index]);
    }

    let channel = event
        .metadata
        .channel
        .as_deref()
        .map(normalize_hunt_index_channel);

    if let Some(channel) = channel.as_deref()
        && let Some(indices) = hunt_plan.channel_rule_indices.get(channel)
    {
        for index in indices {
            visit(&hunt_plan.rules[*index]);
        }
    }

    if let Some(event_id) = event.metadata.event_id
        && let Some(indices) = hunt_plan.event_id_rule_indices.get(&event_id)
    {
        for index in indices {
            visit(&hunt_plan.rules[*index]);
        }
    }

    if let (Some(channel), Some(event_id)) = (channel.as_deref(), event.metadata.event_id)
        && let Some(indices) = hunt_plan
            .channel_event_id_rule_indices
            .get(&(channel.to_owned(), event_id))
    {
        for index in indices {
            visit(&hunt_plan.rules[*index]);
        }
    }
}

fn normalize_hunt_index_channel(channel: &str) -> String {
    channel.to_ascii_lowercase()
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
    let query = read_query(command)?;
    let query = parse_search_query(&query)?;
    let format = OutputFormat::from(command.format);

    if command.explain {
        return Ok(CommandOutcome::message(format!("{query:#?}")));
    }

    let output_fields = search_output_fields(command, &query.keep_fields);
    let style = search_display_style(common);
    let inputs = discover_inputs(discovery)?;
    let mut output = Vec::new();
    let mut stats = SearchStats::default();
    let mut error_writer = ErrorWriter::new(command.errors.as_ref())?;

    if let Some(summarize) = &query.summarize {
        return run_aggregate_search(
            &inputs,
            &query,
            summarize,
            command,
            common,
            format,
            style,
            error_writer,
        );
    }

    if command.limit.is_some() || !should_parallelize(&inputs, common) {
        let mut stdout = SearchOutput::stdout(format, style);

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

                    if query.matches(&event) {
                        stats.matched += 1;

                        stdout.write(&render_search_match(&event, output_fields, format, style));
                    }
                },
                |error| error_writer.write(error),
            )?;

            stats.parse_errors += read_stats.records_failed;
            stats.add_parse_error_samples(read_stats.error_samples);
        }

        if common.stats && !common.quiet {
            stdout.write_text(&stats.render());
        }

        error_writer.finish()?;
        let output = stdout.finish()?;

        return Ok(CommandOutcome {
            message: (!output.is_empty()).then(|| output.join("\n\n")),
            diagnostic: None,
        });
    } else if should_parallelize(&inputs, common) {
        for result in run_parallel_by_input(&inputs, common, |input| {
            process_search_input(input, &query, output_fields, format, style, common)
        })? {
            stats.merge(result.stats);

            for error in &result.errors {
                error_writer.write(error);
            }

            output.extend(
                result
                    .output
                    .into_iter()
                    .filter_map(|rendered| rendered.output),
            );
        }
    } else {
        for input in &inputs {
            let result = process_search_input(input, &query, output_fields, format, style, common)?;
            stats.merge(result.stats);

            for error in &result.errors {
                error_writer.write(error);
            }

            output.extend(
                result
                    .output
                    .into_iter()
                    .filter_map(|rendered| rendered.output),
            );
        }
    }

    error_writer.finish()?;

    if common.stats && !common.quiet {
        output.push(stats.render());
    }

    Ok(CommandOutcome {
        message: (!output.is_empty()).then(|| join_search_output(&output, format, style)),
        diagnostic: None,
    })
}

#[derive(Debug, Default)]
struct SearchInputResult {
    output: Vec<SearchRenderedEvent>,
    errors: Vec<EvtxRecordError>,
    stats: SearchStats,
}

#[derive(Debug)]
struct SearchRenderedEvent {
    output: Option<String>,
}

struct SearchOutput {
    writer: BufWriter<Stdout>,
    records_written: usize,
    format: OutputFormat,
    style: DisplayStyle,
    error: Option<std::io::Error>,
}

impl SearchOutput {
    fn stdout(format: OutputFormat, style: DisplayStyle) -> Self {
        Self {
            writer: BufWriter::new(std::io::stdout()),
            records_written: 0,
            format,
            style,
            error: None,
        }
    }

    fn write(&mut self, rendered: &str) {
        self.write_section(rendered, true);
    }

    fn write_text(&mut self, rendered: &str) {
        self.write_section(rendered, false);
    }

    fn write_section(&mut self, rendered: &str, match_separator: bool) {
        if self.error.is_some() {
            return;
        }

        if self.records_written > 0 {
            let delimiter = match_separator
                .then(|| search_match_delimiter(self.format, self.style))
                .filter(|delimiter| !delimiter.is_empty());
            let separator_result = if let Some(delimiter) = delimiter {
                writeln!(self.writer, "\n{delimiter}\n")
            } else {
                writeln!(self.writer, "\n")
            };

            if let Err(source) = separator_result {
                self.error = Some(source);
                return;
            }
        }

        if let Err(source) = write!(self.writer, "{rendered}") {
            self.error = Some(source);
            return;
        }

        self.records_written += 1;
    }

    fn finish(mut self) -> Result<Vec<String>, RunError> {
        if let Some(source) = self.error {
            return Err(RunError::StdoutWrite(source));
        }

        if self.records_written > 0 {
            writeln!(self.writer).map_err(RunError::StdoutWrite)?;
        }

        self.writer.flush().map_err(RunError::StdoutWrite)?;
        Ok(Vec::new())
    }
}

fn process_search_input(
    input: &DiscoveredInput,
    query: &SearchQuery,
    output_fields: &[String],
    format: OutputFormat,
    style: DisplayStyle,
    common: &CommonArgs,
) -> Result<SearchInputResult, RunError> {
    let mut result = SearchInputResult::default();

    let read_stats = read_evtx_events_with_errors(
        input,
        common.strict,
        |event| {
            if query.matches(&event) {
                result.stats.matched += 1;
                result.output.push(SearchRenderedEvent {
                    output: Some(render_search_match(&event, output_fields, format, style)),
                });
            }
        },
        |error| result.errors.push(error.clone()),
    )?;

    result.stats.scanned += read_stats.records_seen;
    result.stats.parse_errors += read_stats.records_failed;
    result
        .stats
        .add_parse_error_samples(read_stats.error_samples);

    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn run_aggregate_search(
    inputs: &[DiscoveredInput],
    query: &SearchQuery,
    summarize: &Summarize,
    command: &SearchArgs,
    common: &CommonArgs,
    format: OutputFormat,
    style: DisplayStyle,
    mut error_writer: ErrorWriter,
) -> Result<CommandOutcome, RunError> {
    let mut aggregate_state = AggregateState::new(summarize);
    let mut search_stats = SearchStats::default();

    if command.limit.is_some() || !should_parallelize(inputs, common) {
        for input in inputs {
            if reached_limit(command.limit, search_stats.matched) {
                break;
            }

            let read_stats = read_evtx_events_with_errors(
                input,
                common.strict,
                |event| {
                    if reached_limit(command.limit, search_stats.matched) {
                        return;
                    }

                    search_stats.scanned += 1;

                    if query.matches(&event) {
                        search_stats.matched += 1;
                        aggregate_state.add_event(&event, summarize);
                    }
                },
                |error| error_writer.write(error),
            )?;

            search_stats.parse_errors += read_stats.records_failed;
            search_stats.add_parse_error_samples(read_stats.error_samples);
        }
    } else {
        for result in run_parallel_by_input(inputs, common, |input| {
            process_aggregate_input(input, query, summarize, common)
        })? {
            search_stats.merge(result.stats);

            for error in &result.errors {
                error_writer.write(error);
            }

            aggregate_state.merge(result.state);
        }
    }

    error_writer.finish()?;

    let mut output =
        render_aggregate_rows(&aggregate_state.rows(summarize), summarize, format, style);

    if common.stats && !common.quiet {
        if !output.is_empty() {
            output.push_str("\n\n");
        }
        output.push_str(&search_stats.render());
    }

    Ok(CommandOutcome {
        message: (!output.is_empty()).then_some(output),
        diagnostic: None,
    })
}

#[derive(Debug)]
struct AggregateInputResult {
    state: AggregateState,
    errors: Vec<EvtxRecordError>,
    stats: SearchStats,
}

fn process_aggregate_input(
    input: &DiscoveredInput,
    query: &SearchQuery,
    summarize: &Summarize,
    common: &CommonArgs,
) -> Result<AggregateInputResult, RunError> {
    let mut result = AggregateInputResult {
        state: AggregateState::new(summarize),
        errors: Vec::new(),
        stats: SearchStats::default(),
    };

    let read_stats = read_evtx_events_with_errors(
        input,
        common.strict,
        |event| {
            if query.matches(&event) {
                result.stats.matched += 1;
                result.state.add_event(&event, summarize);
            }
        },
        |error| result.errors.push(error.clone()),
    )?;

    result.stats.scanned += read_stats.records_seen;
    result.stats.parse_errors += read_stats.records_failed;
    result
        .stats
        .add_parse_error_samples(read_stats.error_samples);

    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct GroupKey(Vec<Option<String>>);

#[derive(Debug)]
struct AggregateState {
    rows: HashMap<GroupKey, AggregateRowState>,
    aggregate_count: usize,
}

#[derive(Debug)]
struct AggregateRowState {
    groups: Vec<Option<String>>,
    aggregates: Vec<AggregateValue>,
}

#[derive(Debug)]
enum AggregateValue {
    Count(u64),
    MakeSet {
        values: Vec<String>,
        seen: HashSet<String>,
        max_size: usize,
    },
}

#[derive(Debug)]
struct AggregateRow {
    groups: Vec<Option<String>>,
    aggregates: Vec<AggregateOutputValue>,
}

#[derive(Debug)]
enum AggregateOutputValue {
    Number(u64),
    List(Vec<String>),
}

impl AggregateState {
    fn new(summarize: &Summarize) -> Self {
        Self {
            rows: HashMap::new(),
            aggregate_count: summarize.aggregates.len(),
        }
    }

    fn add_event(&mut self, event: &Event, summarize: &Summarize) {
        let groups = summarize
            .group_by
            .iter()
            .map(|group| {
                event
                    .field(&group.field)
                    .and_then(crate::event::FieldValue::as_text)
            })
            .collect::<Vec<_>>();
        let key = GroupKey(groups.clone());
        let row = self
            .rows
            .entry(key)
            .or_insert_with(|| AggregateRowState::new(groups, summarize));

        row.add_event(event, summarize);
    }

    fn merge(&mut self, other: Self) {
        for (key, other_row) in other.rows {
            let row = self.rows.entry(key).or_insert_with(|| {
                AggregateRowState::from_values(other_row.groups.clone(), self.aggregate_count)
            });
            row.merge(other_row);
        }
    }

    fn rows(&self, summarize: &Summarize) -> Vec<AggregateRow> {
        let mut rows = self
            .rows
            .values()
            .map(AggregateRowState::to_output_row)
            .collect::<Vec<_>>();

        rows.sort_by(|left, right| {
            left.groups
                .cmp(&right.groups)
                .then_with(|| aggregate_row_tiebreak(left, right, summarize))
        });

        rows
    }
}

impl AggregateRowState {
    fn new(groups: Vec<Option<String>>, summarize: &Summarize) -> Self {
        Self {
            groups,
            aggregates: summarize
                .aggregates
                .iter()
                .map(|aggregate| match aggregate.function {
                    AggregateFunction::Count => AggregateValue::Count(0),
                    AggregateFunction::MakeSet { max_size, .. } => AggregateValue::MakeSet {
                        values: Vec::new(),
                        seen: HashSet::new(),
                        max_size,
                    },
                })
                .collect(),
        }
    }

    fn from_values(groups: Vec<Option<String>>, aggregate_count: usize) -> Self {
        Self {
            groups,
            aggregates: Vec::with_capacity(aggregate_count),
        }
    }

    fn add_event(&mut self, event: &Event, summarize: &Summarize) {
        for (value, aggregate) in self.aggregates.iter_mut().zip(&summarize.aggregates) {
            match (value, &aggregate.function) {
                (AggregateValue::Count(count), AggregateFunction::Count) => *count += 1,
                (
                    AggregateValue::MakeSet {
                        values,
                        seen,
                        max_size,
                    },
                    AggregateFunction::MakeSet { field, .. },
                ) => {
                    if values.len() >= *max_size {
                        continue;
                    }

                    if let Some(text) = event
                        .field(field)
                        .and_then(crate::event::FieldValue::as_text)
                        && seen.insert(text.clone())
                    {
                        values.push(text);
                    }
                }
                (
                    AggregateValue::Count(_) | AggregateValue::MakeSet { .. },
                    AggregateFunction::Count | AggregateFunction::MakeSet { .. },
                ) => {}
            }
        }
    }

    fn merge(&mut self, other: Self) {
        if self.aggregates.is_empty() {
            self.aggregates = other.aggregates;
            return;
        }

        for (value, other_value) in self.aggregates.iter_mut().zip(other.aggregates) {
            match (value, other_value) {
                (AggregateValue::Count(count), AggregateValue::Count(other_count)) => {
                    *count += other_count;
                }
                (
                    AggregateValue::MakeSet {
                        values,
                        seen,
                        max_size,
                    },
                    AggregateValue::MakeSet {
                        values: other_values,
                        ..
                    },
                ) => {
                    for text in other_values {
                        if values.len() >= *max_size {
                            break;
                        }

                        if seen.insert(text.clone()) {
                            values.push(text);
                        }
                    }
                }
                (
                    AggregateValue::Count(_) | AggregateValue::MakeSet { .. },
                    AggregateValue::Count(_) | AggregateValue::MakeSet { .. },
                ) => {}
            }
        }
    }

    fn to_output_row(&self) -> AggregateRow {
        AggregateRow {
            groups: self.groups.clone(),
            aggregates: self
                .aggregates
                .iter()
                .map(|value| match value {
                    AggregateValue::Count(count) => AggregateOutputValue::Number(*count),
                    AggregateValue::MakeSet { values, .. } => {
                        let mut values = values.clone();
                        values.sort();
                        AggregateOutputValue::List(values)
                    }
                })
                .collect(),
        }
    }
}

fn aggregate_row_tiebreak(
    left: &AggregateRow,
    right: &AggregateRow,
    _summarize: &Summarize,
) -> std::cmp::Ordering {
    left.aggregates.len().cmp(&right.aggregates.len())
}

fn render_aggregate_rows(
    rows: &[AggregateRow],
    summarize: &Summarize,
    format: OutputFormat,
    style: DisplayStyle,
) -> String {
    match format {
        OutputFormat::Json => {
            let value = rows
                .iter()
                .map(|row| aggregate_row_json(row, summarize))
                .collect::<Vec<_>>();
            serde_json::to_string_pretty(&value)
                .expect("serializing aggregate rows should not fail")
        }
        OutputFormat::Jsonl => rows
            .iter()
            .map(|row| aggregate_row_json(row, summarize).to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        OutputFormat::Pretty
        | OutputFormat::Compact
        | OutputFormat::Csv
        | OutputFormat::Timeline => render_aggregate_rows_pretty(rows, summarize, style),
    }
}

fn aggregate_row_json(row: &AggregateRow, summarize: &Summarize) -> serde_json::Value {
    let groups = summarize
        .group_by
        .iter()
        .zip(&row.groups)
        .map(|(group, value)| {
            (
                group.alias.clone(),
                value
                    .as_ref()
                    .map_or(serde_json::Value::Null, |text| json!(text)),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let aggregates = summarize
        .aggregates
        .iter()
        .zip(&row.aggregates)
        .map(|(aggregate, value)| {
            let value = match value {
                AggregateOutputValue::Number(number) => json!(number),
                AggregateOutputValue::List(values) => json!(values),
            };
            (aggregate.alias.clone(), value)
        })
        .collect::<serde_json::Map<_, _>>();

    json!({
        "groups": groups,
        "aggregates": aggregates,
    })
}

fn render_aggregate_rows_pretty(
    rows: &[AggregateRow],
    summarize: &Summarize,
    style: DisplayStyle,
) -> String {
    rows.iter()
        .map(|row| render_aggregate_row_pretty(row, summarize, style))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn render_aggregate_row_pretty(
    row: &AggregateRow,
    summarize: &Summarize,
    style: DisplayStyle,
) -> String {
    let mut output = String::new();
    let label = styled_label("summary", style);
    let _ = write!(output, "{label}");

    for (group, value) in summarize.group_by.iter().zip(&row.groups) {
        let field = styled_label(&group.alias, style);
        let value = value.as_deref().unwrap_or("-");
        let _ = write!(output, "\n  {field}: {value}");
    }

    for (aggregate, value) in summarize.aggregates.iter().zip(&row.aggregates) {
        let field = styled_label(&aggregate.alias, style);
        match value {
            AggregateOutputValue::Number(number) => {
                let _ = write!(output, "\n  {field}: {number}");
            }
            AggregateOutputValue::List(values) => {
                let joined = values.join(", ");
                let _ = write!(output, "\n  {field}: [{joined}]");
            }
        }
    }

    output
}

fn styled_label(text: &str, style: DisplayStyle) -> std::borrow::Cow<'_, str> {
    if style.colored() {
        std::borrow::Cow::Owned(format!("\x1b[2;36m{text}\x1b[0m"))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

fn search_display_style(common: &CommonArgs) -> DisplayStyle {
    if common.no_color || !std::io::stdout().is_terminal() {
        DisplayStyle::Plain
    } else {
        DisplayStyle::Color
    }
}

fn join_search_output(output: &[String], format: OutputFormat, style: DisplayStyle) -> String {
    let delimiter = search_match_delimiter(format, style);

    if delimiter.is_empty() {
        output.join("\n\n")
    } else {
        output.join(&format!("\n\n{delimiter}\n\n"))
    }
}

pub fn run_dump(
    command: &DumpArgs,
    discovery: &DiscoveryConfig,
    common: &CommonArgs,
) -> Result<CommandOutcome, RunError> {
    if !matches!(
        command.format,
        DumpFormat::Jsonl | DumpFormat::Json | DumpFormat::Csv
    ) {
        return Err(RunError::UnsupportedDumpFormat {
            format: command.format,
        });
    }

    if matches!(command.format, DumpFormat::Csv) && command.fields.is_empty() {
        return Err(RunError::DumpCsvRequiresFields);
    }
    if matches!(command.format, DumpFormat::Csv) && command.raw {
        return Err(RunError::DumpCsvRawUnsupported);
    }

    let inputs = discover_inputs(discovery)?;
    let stream_stdout = command.output.is_none() && !should_parallelize(&inputs, common);
    let mut output = DumpOutput::new(command, stream_stdout)?;
    let mut error_writer = ErrorWriter::new(command.errors.as_ref())?;
    let mut stats = DumpStats::default();
    let strict = common.strict || command.fail_fast;

    if should_parallelize(&inputs, common) {
        let mode = DumpOutputMode::from_command(command);

        for result in run_parallel_by_input(&inputs, common, |input| {
            process_dump_input(input, command, mode, strict)
        })? {
            stats.merge(result.stats);

            for error in &result.errors {
                error_writer.write(error);
            }

            for record in result.records {
                output.write_serialized_record(record);
            }
        }
    } else {
        for input in &inputs {
            let input_stats = process_dump_input_streaming(
                input,
                command,
                DumpOutputMode::from_command(command),
                strict,
                &mut output,
                &mut error_writer,
            )?;
            stats.merge(input_stats);
        }
    }

    error_writer.finish()?;
    let mut message = output.finish()?;

    if common.stats && !common.quiet {
        message.push(stats.render(inputs.len()));
    }

    Ok(CommandOutcome {
        message: (!message.is_empty()).then(|| message.join("\n")),
        diagnostic: None,
    })
}

#[derive(Debug, Default)]
struct DumpInputResult {
    records: Vec<String>,
    errors: Vec<EvtxRecordError>,
    stats: DumpStats,
}

fn process_dump_input(
    input: &DiscoveredInput,
    command: &DumpArgs,
    mode: DumpOutputMode,
    strict: bool,
) -> Result<DumpInputResult, RunError> {
    let mut result = DumpInputResult::default();

    let read_stats = read_evtx_events_with_errors(
        input,
        strict,
        |event| {
            result.stats.records_dumped += 1;
            result
                .records
                .push(serialize_dump_event(&event, command, mode));
        },
        |error| result.errors.push(error.clone()),
    )?;

    result.stats.parse_errors += read_stats.records_failed;
    result
        .stats
        .add_parse_error_samples(read_stats.error_samples);

    Ok(result)
}

fn process_dump_input_streaming(
    input: &DiscoveredInput,
    command: &DumpArgs,
    mode: DumpOutputMode,
    strict: bool,
    output: &mut DumpOutput,
    error_writer: &mut ErrorWriter,
) -> Result<DumpStats, RunError> {
    let mut stats = DumpStats::default();

    let read_stats = read_evtx_events_with_errors(
        input,
        strict,
        |event| {
            stats.records_dumped += 1;
            output.write_serialized_record(serialize_dump_event(&event, command, mode));
        },
        |error| error_writer.write(error),
    )?;

    stats.parse_errors += read_stats.records_failed;
    stats.add_parse_error_samples(read_stats.error_samples);

    Ok(stats)
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

#[cfg(test)]
fn render_hunt_match(
    rule: &SigmaRule,
    event: &Event,
    format: OutputFormat,
    full_output: bool,
) -> String {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => render_hunt_json(rule, event, format),
        OutputFormat::Pretty
        | OutputFormat::Compact
        | OutputFormat::Csv
        | OutputFormat::Timeline => render_hunt_pretty(rule, event, full_output),
    }
}

fn render_hunt_output(
    rule: &SigmaRule,
    event: &Event,
    format: OutputFormat,
    full_output: bool,
) -> HuntRenderedOutput {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            HuntRenderedOutput::Text(render_hunt_json(rule, event, format))
        }
        OutputFormat::Pretty
        | OutputFormat::Compact
        | OutputFormat::Csv
        | OutputFormat::Timeline => HuntRenderedOutput::PrettyMatch {
            full_output,
            row: render_hunt_pretty_row(rule, event, full_output),
        },
    }
}

#[cfg(test)]
fn render_hunt_pretty(rule: &SigmaRule, event: &Event, full_output: bool) -> String {
    render_hunt_pretty_table(
        &[render_hunt_pretty_row(rule, event, full_output)],
        full_output,
    )
}

fn render_hunt_pretty_row(rule: &SigmaRule, event: &Event, full_output: bool) -> Vec<String> {
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
    let payload = format_table_field(&render_event_payload(event, 0), full_output);

    let event_label = format!("{event_id}/{record_id}");
    let rule_title = format_table_field(&rule.title, full_output);
    let host = format_table_field(computer, full_output);

    if full_output {
        return vec![
            timestamp.to_owned(),
            rule_title,
            event_label,
            level.to_owned(),
            format_table_field(channel, full_output),
            host,
            format_table_field(&event.source.file_path.display().to_string(), full_output),
            payload,
        ];
    }

    vec![
        timestamp.to_owned(),
        rule_title,
        event_label,
        level.to_owned(),
        host,
        payload,
    ]
}

fn render_hunt_pretty_table(rows: &[Vec<String>], full_output: bool) -> String {
    if full_output {
        return render_table(
            &[
                TableColumn::new("Timestamp", 29),
                TableColumn::new("Detections", 36),
                TableColumn::new("Event", 10),
                TableColumn::new("Level", 8),
                TableColumn::new("Channel", 42),
                TableColumn::new("Host", 20),
                TableColumn::new("File", 42),
                TableColumn::new("Payload", 80),
            ],
            rows,
        );
    }

    render_table(
        &[
            TableColumn::new("Timestamp", 29),
            TableColumn::new("Detections", 30),
            TableColumn::new("Event", 10),
            TableColumn::new("Level", 8),
            TableColumn::new("Host", 20),
            TableColumn::new("Payload", 42),
        ],
        rows,
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
    full_output: bool,
) -> String {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            render_correlation_json(correlation_match, format)
        }
        OutputFormat::Pretty
        | OutputFormat::Compact
        | OutputFormat::Csv
        | OutputFormat::Timeline => {
            render_correlation_pretty(correlation_match, event_limit, full_output)
        }
    }
}

fn render_correlation_pretty(
    correlation_match: &SigmaCorrelationMatch,
    event_limit: usize,
    full_output: bool,
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

    let payload = format_table_field(
        &correlation_payload(correlation_match, event_limit),
        full_output,
    );
    let title = format_table_field(&correlation_match.rule.title, full_output);
    let group = format_table_field(&group, full_output);

    if full_output {
        return render_table(
            &[
                TableColumn::new("Timestamp", 29),
                TableColumn::new("Detections", 44),
                TableColumn::new("Matches", 7),
                TableColumn::new("Level", 8),
                TableColumn::new("Group", 44),
                TableColumn::new("Window", 58),
                TableColumn::new("Payload", 80),
            ],
            &[vec![
                correlation_match.window_end.clone(),
                title,
                correlation_match.matches.len().to_string(),
                level.to_owned(),
                group,
                format!(
                    "{}..{}",
                    correlation_match.window_start, correlation_match.window_end
                ),
                payload,
            ]],
        );
    }

    render_table(
        &[
            TableColumn::new("Timestamp", 29),
            TableColumn::new("Detections", 34),
            TableColumn::new("Matches", 7),
            TableColumn::new("Level", 8),
            TableColumn::new("Group", 34),
            TableColumn::new("Payload", 46),
        ],
        &[vec![
            correlation_match.window_end.clone(),
            title,
            correlation_match.matches.len().to_string(),
            level.to_owned(),
            group,
            payload,
        ]],
    )
}

fn correlation_payload(correlation_match: &SigmaCorrelationMatch, event_limit: usize) -> String {
    if event_limit == 0
        || correlation_match
            .matches
            .iter()
            .all(|source| source.fields.is_empty())
    {
        return "-".to_owned();
    }

    let shown = correlation_match.matches.len().min(event_limit);
    let mut output = String::new();

    for (index, source_match) in correlation_match
        .matches
        .iter()
        .take(event_limit)
        .enumerate()
    {
        if index > 0 {
            output.push_str("\n---\n");
        }

        let event_id = source_match
            .event_id
            .map_or_else(|| "-".to_owned(), |value| value.to_string());
        let record_id = source_match
            .record_id
            .map_or_else(|| "-".to_owned(), |value| value.to_string());
        let channel = source_match.channel.as_deref().unwrap_or("-");
        let _ = write!(
            output,
            "timestamp: {}\nrule_match: {}\nchannel: {channel}\nevent_id: {event_id}\nevent_record_id: {record_id}",
            source_match.timestamp, source_match.rule_title
        );

        for (field, value) in &source_match.fields {
            let value = value.as_deref().unwrap_or("null");
            let _ = write!(output, "\n{field}: {value}");
        }
    }

    if correlation_match.matches.len() > shown {
        let remaining = correlation_match.matches.len() - shown;
        let _ = write!(
            output,
            "\n... {remaining} more contributing event(s); increase --correlation-event-limit to show more"
        );
    }

    output
}

#[derive(Debug, Clone, Copy)]
struct TableColumn {
    header: &'static str,
    max_width: usize,
}

impl TableColumn {
    const fn new(header: &'static str, max_width: usize) -> Self {
        Self { header, max_width }
    }
}

fn render_table(columns: &[TableColumn], rows: &[Vec<String>]) -> String {
    let rows = rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| sanitize_table_cell(cell))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let widths = table_widths(columns, &rows);
    let wrapped_rows = wrap_table_rows(&rows, &widths);
    let top_border = table_border(&widths, '┌', '┬', '┐');
    let middle_border = table_border(&widths, '├', '┼', '┤');
    let bottom_border = table_border(&widths, '└', '┴', '┘');
    let mut output = String::new();

    output.push_str(&top_border);
    output.push('\n');
    output.push_str(&table_row(
        columns.iter().map(|column| column.header),
        &widths,
    ));
    output.push('\n');
    output.push_str(&middle_border);

    for row in &wrapped_rows {
        output.push('\n');
        output.push_str(&render_table_data_row(row, &widths));
    }

    output.push('\n');
    output.push_str(&bottom_border);
    output
}

fn table_widths(columns: &[TableColumn], rows: &[Vec<String>]) -> Vec<usize> {
    let mut widths = columns
        .iter()
        .map(|column| text_width(column.header))
        .collect::<Vec<_>>();

    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if let (Some(column), Some(width)) = (columns.get(index), widths.get_mut(index)) {
                *width = (*width).max(preferred_cell_width(cell, column.max_width));
            }
        }
    }

    for (width, column) in widths.iter_mut().zip(columns) {
        *width = (*width).min(column.max_width);
    }

    widths
}

fn preferred_cell_width(cell: &str, max_width: usize) -> usize {
    cell.split_whitespace()
        .map(text_width)
        .max()
        .map_or(0, |width| width.min(max_width))
        .max(text_width(cell).min(max_width))
}

fn table_border(widths: &[usize], left: char, separator: char, right: char) -> String {
    let mut output = String::new();
    output.push(left);

    for width in widths {
        output.push_str(&"─".repeat(width + 2));
        output.push(separator);
    }

    output.pop();
    output.push(right);
    output
}

fn table_row<'a>(values: impl IntoIterator<Item = &'a str>, widths: &[usize]) -> String {
    let mut output = String::new();
    output.push('│');

    for (value, width) in values.into_iter().zip(widths) {
        let _ = write!(output, " {value:<width$} │");
    }

    output
}

fn render_table_data_row(row: &[Vec<String>], widths: &[usize]) -> String {
    let height = row.iter().map(Vec::len).max().unwrap_or(1);
    let mut output = String::new();

    for line_index in 0..height {
        if line_index > 0 {
            output.push('\n');
        }

        output.push('│');

        for (cell, width) in row.iter().zip(widths) {
            let value = cell.get(line_index).map_or("", String::as_str);
            let _ = write!(output, " {value:<width$} │");
        }
    }

    output
}

fn wrap_table_rows(rows: &[Vec<String>], widths: &[usize]) -> Vec<Vec<Vec<String>>> {
    rows.iter()
        .map(|row| {
            row.iter()
                .zip(widths)
                .map(|(cell, width)| wrap_cell(cell, *width))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn sanitize_table_cell(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("  ::  ")
        .replace(['\r', '\t'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_table_field(value: &str, full_output: bool) -> String {
    const TRUNCATE_LEN: usize = 496;

    let mut output = sanitize_table_cell(value);

    if !full_output && output.len() > TRUNCATE_LEN {
        output.truncate(TRUNCATE_LEN);
        output.push_str("...\n(use --full to show all content)");
    }

    output
}

fn wrap_cell(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![value.to_owned()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in value.split_whitespace() {
        let word_width = text_width(word);
        if word_width > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            lines.extend(split_long_word(word, width));
            continue;
        }

        if current.is_empty() {
            current.push_str(word);
        } else if text_width(&current) + 1 + word_width <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn split_long_word(word: &str, width: usize) -> Vec<String> {
    word.chars()
        .collect::<Vec<_>>()
        .chunks(width)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect()
}

fn text_width(value: &str) -> usize {
    value.chars().count()
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

struct DumpOutput {
    path: Option<String>,
    writer: Option<BufWriter<File>>,
    stdout_writer: Option<BufWriter<Stdout>>,
    mode: DumpOutputMode,
    csv_header: Option<String>,
    records: Vec<String>,
    records_written: usize,
    error: Option<std::io::Error>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DumpOutputMode {
    Jsonl,
    Json { pretty: bool },
    Csv,
}

impl DumpOutput {
    fn new(command: &DumpArgs, stream_stdout: bool) -> Result<Self, RunError> {
        let mode = DumpOutputMode::from_command(command);
        let csv_header = matches!(mode, DumpOutputMode::Csv)
            .then(|| csv_record_from_values(command.fields.iter().map(String::as_str)));

        let Some(path) = &command.output else {
            return Ok(Self {
                path: None,
                writer: None,
                stdout_writer: stream_stdout.then(|| BufWriter::new(std::io::stdout())),
                mode,
                csv_header,
                records: Vec::new(),
                records_written: 0,
                error: None,
            });
        };
        let path_label = path.display().to_string();
        let file = File::create(path).map_err(|source| RunError::DumpOutputCreate {
            path: path_label.clone(),
            source,
        })?;

        Ok(Self {
            path: Some(path_label),
            writer: Some(BufWriter::new(file)),
            stdout_writer: None,
            mode,
            csv_header,
            records: Vec::new(),
            records_written: 0,
            error: None,
        })
    }

    fn write_serialized_record(&mut self, serialized: String) {
        if self.error.is_some() {
            return;
        }

        match (&mut self.writer, &mut self.stdout_writer) {
            (Some(writer), _) => {
                if matches!(self.mode, DumpOutputMode::Csv) && self.records_written == 0 {
                    let header = self
                        .csv_header
                        .as_deref()
                        .expect("CSV output should have a header");

                    if let Err(source) = writeln!(writer, "{header}") {
                        self.error = Some(source);
                        return;
                    }
                }

                if let Err(source) =
                    write_dump_record(writer, self.mode, self.records_written, &serialized)
                {
                    self.error = Some(source);
                    return;
                }
            }
            (None, Some(writer)) => {
                if matches!(self.mode, DumpOutputMode::Csv) && self.records_written == 0 {
                    let header = self
                        .csv_header
                        .as_deref()
                        .expect("CSV output should have a header");

                    if let Err(source) = writeln!(writer, "{header}") {
                        self.error = Some(source);
                        return;
                    }
                }

                if let Err(source) =
                    write_dump_record(writer, self.mode, self.records_written, &serialized)
                {
                    self.error = Some(source);
                    return;
                }
            }
            (None, None) => self.records.push(serialized),
        }

        self.records_written += 1;
    }

    fn finish(self) -> Result<Vec<String>, RunError> {
        if self.path.is_none() {
            if let Some(source) = self.error {
                return Err(RunError::DumpOutputWrite {
                    path: "<stdout>".to_owned(),
                    source,
                });
            }

            if let Some(mut writer) = self.stdout_writer {
                finish_dump_writer(
                    &mut writer,
                    self.mode,
                    self.csv_header.as_deref(),
                    self.records_written,
                )
                .map_err(|source| RunError::DumpOutputWrite {
                    path: "<stdout>".to_owned(),
                    source,
                })?;
                writer.flush().map_err(|source| RunError::DumpOutputWrite {
                    path: "<stdout>".to_owned(),
                    source,
                })?;
                return Ok(Vec::new());
            }

            return Ok(render_dump_stdout(
                self.mode,
                self.csv_header.as_deref(),
                &self.records,
            ));
        }

        let path = self.path.expect("path should exist when writing to a file");

        if let Some(source) = self.error {
            return Err(RunError::DumpOutputWrite { path, source });
        }

        let Some(mut writer) = self.writer else {
            return Ok(Vec::new());
        };

        finish_dump_writer(
            &mut writer,
            self.mode,
            self.csv_header.as_deref(),
            self.records_written,
        )
        .map_err(|source| RunError::DumpOutputWrite {
            path: path.clone(),
            source,
        })?;
        writer
            .flush()
            .map_err(|source| RunError::DumpOutputWrite { path, source })?;

        Ok(Vec::new())
    }
}

fn serialize_dump_event(event: &Event, command: &DumpArgs, mode: DumpOutputMode) -> String {
    match mode {
        DumpOutputMode::Jsonl | DumpOutputMode::Json { .. } => {
            let value = dump_json_value(event, &command.fields, command.raw);
            serialize_dump_record(&value, mode)
        }
        DumpOutputMode::Csv => csv_record(event, &command.fields),
    }
}

impl DumpOutputMode {
    fn from_command(command: &DumpArgs) -> Self {
        match command.format {
            DumpFormat::Jsonl => Self::Jsonl,
            DumpFormat::Json => Self::Json {
                pretty: command.pretty && !command.compact,
            },
            DumpFormat::Csv => Self::Csv,
            DumpFormat::Xml => {
                unreachable!("unsupported dump formats are rejected before output creation")
            }
        }
    }
}

fn serialize_dump_record(value: &serde_json::Value, mode: DumpOutputMode) -> String {
    match mode {
        DumpOutputMode::Jsonl | DumpOutputMode::Json { pretty: false } => value.to_string(),
        DumpOutputMode::Json { pretty: true } => serde_json::to_string_pretty(value)
            .expect("serializing a serde_json::Value should not fail"),
        DumpOutputMode::Csv => unreachable!("CSV records are serialized separately"),
    }
}

fn write_dump_record(
    writer: &mut impl std::io::Write,
    mode: DumpOutputMode,
    records_written: usize,
    serialized: &str,
) -> std::io::Result<()> {
    match mode {
        DumpOutputMode::Jsonl | DumpOutputMode::Csv => writeln!(writer, "{serialized}"),
        DumpOutputMode::Json { pretty: false } => {
            if records_written == 0 {
                write!(writer, "[")?;
            } else {
                write!(writer, ",")?;
            }

            write!(writer, "{serialized}")
        }
        DumpOutputMode::Json { pretty: true } => {
            if records_written == 0 {
                writeln!(writer, "[")?;
            } else {
                writeln!(writer, ",")?;
            }

            write!(writer, "{}", indent_json(serialized))
        }
    }
}

fn finish_dump_writer(
    writer: &mut impl std::io::Write,
    mode: DumpOutputMode,
    csv_header: Option<&str>,
    records_written: usize,
) -> std::io::Result<()> {
    match mode {
        DumpOutputMode::Jsonl => Ok(()),
        DumpOutputMode::Csv => {
            if records_written == 0 {
                writeln!(
                    writer,
                    "{}",
                    csv_header.expect("CSV output should have a header")
                )
            } else {
                Ok(())
            }
        }
        DumpOutputMode::Json { pretty: false } => {
            if records_written == 0 {
                write!(writer, "[]")
            } else {
                write!(writer, "]")
            }
        }
        DumpOutputMode::Json { pretty: true } => {
            if records_written == 0 {
                writeln!(writer, "[]")
            } else {
                writeln!(writer)?;
                writeln!(writer, "]")
            }
        }
    }
}

fn render_dump_stdout(
    mode: DumpOutputMode,
    csv_header: Option<&str>,
    records: &[String],
) -> Vec<String> {
    match mode {
        DumpOutputMode::Jsonl => records.to_vec(),
        DumpOutputMode::Csv => {
            let mut output = Vec::with_capacity(records.len() + 1);
            output.push(
                csv_header
                    .expect("CSV output should have a header")
                    .to_owned(),
            );
            output.extend(records.iter().cloned());
            output
        }
        DumpOutputMode::Json { pretty: false } => vec![format!("[{}]", records.join(","))],
        DumpOutputMode::Json { pretty: true } => {
            if records.is_empty() {
                return vec!["[]".to_owned()];
            }

            let body = records
                .iter()
                .map(|record| indent_json(record))
                .collect::<Vec<_>>()
                .join(",\n");
            vec![format!("[\n{body}\n]")]
        }
    }
}

fn indent_json(value: &str) -> String {
    value
        .lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn csv_record(event: &Event, fields: &[String]) -> String {
    csv_record_from_values(fields.iter().map(|field| {
        event
            .field(field)
            .and_then(crate::event::FieldValue::as_text)
            .unwrap_or_default()
    }))
}

fn csv_record_from_values(values: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    values
        .into_iter()
        .map(|value| csv_field(value.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

struct ErrorWriter {
    path: Option<String>,
    writer: Option<BufWriter<File>>,
    error: Option<std::io::Error>,
}

impl ErrorWriter {
    fn new(path: Option<&std::path::PathBuf>) -> Result<Self, RunError> {
        let Some(path) = path else {
            return Ok(Self {
                path: None,
                writer: None,
                error: None,
            });
        };
        let path_label = path.display().to_string();
        let file = File::create(path).map_err(|source| RunError::ParseErrorsCreate {
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
            return Err(RunError::ParseErrorsWrite { path, source });
        }

        let Some(mut writer) = self.writer else {
            return Ok(());
        };

        writer
            .flush()
            .map_err(|source| RunError::ParseErrorsWrite { path, source })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DumpStats {
    records_dumped: usize,
    parse_errors: usize,
    parse_error_samples: Vec<EvtxRecordError>,
}

impl DumpStats {
    const MAX_PARSE_ERROR_SAMPLES: usize = 5;

    fn merge(&mut self, other: Self) {
        self.records_dumped += other.records_dumped;
        self.parse_errors += other.parse_errors;
        self.add_parse_error_samples(other.parse_error_samples);
    }

    fn add_parse_error_samples(&mut self, samples: Vec<EvtxRecordError>) {
        let remaining =
            Self::MAX_PARSE_ERROR_SAMPLES.saturating_sub(self.parse_error_samples.len());

        self.parse_error_samples
            .extend(samples.into_iter().take(remaining));
    }

    fn render(self, input_count: usize) -> String {
        let mut output = format!(
            "stats: dumped={} parse_errors={} inputs={}",
            self.records_dumped, self.parse_errors, input_count
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SearchStats {
    scanned: usize,
    matched: usize,
    parse_errors: usize,
    parse_error_samples: Vec<EvtxRecordError>,
}

impl SearchStats {
    const MAX_PARSE_ERROR_SAMPLES: usize = 5;

    fn merge(&mut self, other: Self) {
        self.scanned += other.scanned;
        self.matched += other.matched;
        self.parse_errors += other.parse_errors;
        self.add_parse_error_samples(other.parse_error_samples);
    }

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
mod tests;
