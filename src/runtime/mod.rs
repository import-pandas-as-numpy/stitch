use std::{
    collections::HashMap,
    fmt::Write as _,
    fs::{self, File},
    io::{BufWriter, Stdout, Write as _},
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
use crate::output::{dump_json_value, render_event_payload, render_search_match};
use crate::query::{QueryError, parse_search_query};
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
    event_id_rule_indices: HashMap<u64, Vec<usize>>,
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
    let (general_rule_indices, event_id_rule_indices) = index_planned_rules(&planned);

    Ok(HuntPlan {
        rules: planned,
        general_rule_indices,
        event_id_rule_indices,
        alert_rule_count,
    })
}

fn index_planned_rules(planned: &[PlannedRule<'_>]) -> (Vec<usize>, HashMap<u64, Vec<usize>>) {
    let mut general_rule_indices = Vec::new();
    let mut event_id_rule_indices: HashMap<u64, Vec<usize>> = HashMap::new();

    for (index, planned_rule) in planned.iter().enumerate() {
        if let Some(event_ids) = planned_rule.rule.required_event_ids() {
            for event_id in event_ids {
                event_id_rule_indices
                    .entry(event_id)
                    .or_default()
                    .push(index);
            }
        } else {
            general_rule_indices.push(index);
        }
    }

    (general_rule_indices, event_id_rule_indices)
}

fn for_each_candidate_rule<'a>(
    hunt_plan: &'a HuntPlan<'a>,
    event: &Event,
    mut visit: impl FnMut(&'a PlannedRule<'a>),
) {
    for index in &hunt_plan.general_rule_indices {
        visit(&hunt_plan.rules[*index]);
    }

    if let Some(event_id) = event.metadata.event_id
        && let Some(indices) = hunt_plan.event_id_rule_indices.get(&event_id)
    {
        for index in indices {
            visit(&hunt_plan.rules[*index]);
        }
    }
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
    let inputs = discover_inputs(discovery)?;
    let mut output = Vec::new();
    let mut stats = SearchStats::default();
    let mut error_writer = ErrorWriter::new(command.errors.as_ref())?;

    if command.limit.is_some() || !should_parallelize(&inputs, common) {
        let mut stdout = SearchOutput::stdout();

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

                        stdout.write(&render_search_match(&event, output_fields, format));
                    }
                },
                |error| error_writer.write(error),
            )?;

            stats.parse_errors += read_stats.records_failed;
            stats.add_parse_error_samples(read_stats.error_samples);
        }

        if common.stats && !common.quiet {
            stdout.write(&stats.render());
        }

        error_writer.finish()?;
        let output = stdout.finish()?;

        return Ok(CommandOutcome {
            message: (!output.is_empty()).then(|| output.join("\n\n")),
            diagnostic: None,
        });
    } else if should_parallelize(&inputs, common) {
        for result in run_parallel_by_input(&inputs, common, |input| {
            process_search_input(input, &query, output_fields, format, common)
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
            let result = process_search_input(input, &query, output_fields, format, common)?;
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
        message: (!output.is_empty()).then(|| output.join("\n\n")),
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
    error: Option<std::io::Error>,
}

impl SearchOutput {
    fn stdout() -> Self {
        Self {
            writer: BufWriter::new(std::io::stdout()),
            records_written: 0,
            error: None,
        }
    }

    fn write(&mut self, rendered: &str) {
        if self.error.is_some() {
            return;
        }

        if self.records_written > 0
            && let Err(source) = writeln!(self.writer, "\n")
        {
            self.error = Some(source);
            return;
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
    query: &crate::query::SearchQuery,
    output_fields: &[String],
    format: OutputFormat,
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
                    output: Some(render_search_match(&event, output_fields, format)),
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
mod tests {
    use std::{fs, path::PathBuf};

    use serde_json::json;

    use crate::cli::{CorrelationScope, HuntArgs, SearchArgs, SearchOutputFormat};
    use crate::input::DiscoveredInput;

    use super::*;

    #[test]
    fn reads_inline_query() {
        let args = SearchArgs {
            query: Some("event.id == 4625".to_owned()),
            query_file: None,
            fields: Vec::new(),
            format: SearchOutputFormat::Pretty,
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
            format: SearchOutputFormat::Pretty,
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
    fn hunt_plan_indexes_rules_by_required_event_id() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let event_rule = fixture.path().join("event-id.yml");
        let general_rule = fixture.path().join("general.yml");
        fs::write(
            &event_rule,
            r"
title: Event ID Rule
detection:
  selection:
    EventID: 4625
  condition: selection
",
        )
        .expect("event rule should be written");
        fs::write(
            &general_rule,
            r"
title: General Rule
detection:
  selection:
    Event.EventData.TargetUserName|contains: admin
  condition: selection
",
        )
        .expect("general rule should be written");
        let report = load_sigma_rules(&[fixture.path().to_path_buf()]).expect("rules should load");
        let command = hunt_args();

        let plan = build_hunt_plan(&command, &report.rules, &[]).expect("hunt plan should build");

        assert_eq!(plan.rules.len(), 2);
        assert_eq!(
            plan.event_id_rule_indices.get(&4625).map(Vec::len),
            Some(1),
            "event-id rule should be indexed by required EventID"
        );
        assert_eq!(
            plan.general_rule_indices.len(),
            1,
            "rule without required EventID should remain in the general bucket"
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
        let mut writer = ErrorWriter::new(Some(&path)).expect("writer should be created");

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
            &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
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

        let output = render_hunt_match(&rule, &event, OutputFormat::Jsonl, false);
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("hunt JSONL should be valid JSON");

        assert_eq!(value["rule"]["title"], "Suspicious Process");
        assert_eq!(value["rule"]["level"], "high");
        assert_eq!(value["event"]["event_id"], 4688);
        assert_eq!(value["event"]["computer"], "WIN-01");
        assert_eq!(value["event"]["source"]["file_path"], "Security.evtx");
    }

    #[test]
    fn hunt_pretty_output_is_tabular_with_concise_payload() {
        let rule = SigmaRule::test_rule("Suspicious Process", Some("high".to_owned()));
        let event = Event::from_raw(
            &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
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
                    },
                    "EventData": {
                        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -NoProfile"
                    }
                }
            }),
        );

        let output = render_hunt_match(&rule, &event, OutputFormat::Pretty, false);

        assert!(output.contains("│ Timestamp"));
        assert!(output.contains("│ Detections"));
        assert!(output.contains("│ Event"));
        assert!(output.contains("Suspicious Process"));
        assert!(output.contains("│ 4688/42"));
        assert!(!output.contains("│ Channel"));
        assert!(!output.contains("│ File"));
        assert!(output.contains("│ Payload"));
        assert!(output.contains("CommandLine:"));
        assert!(output.contains("powershell.exe -NoProfile"));
        assert!(
            !output.contains("SystemTime:"),
            "hunt payload should stay focused on event data"
        );
    }

    #[test]
    fn hunt_full_pretty_output_includes_source_columns() {
        let rule = SigmaRule::test_rule("Suspicious Process", Some("high".to_owned()));
        let event = Event::from_raw(
            &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
            Some(42),
            json!({
                "Event": {
                    "System": {
                        "EventID": 4688,
                        "Channel": "Security",
                        "Computer": "WIN-01",
                        "TimeCreated": {
                            "#attributes": {
                                "SystemTime": "2026-06-27T12:00:00Z"
                            }
                        }
                    },
                    "EventData": {
                        "CommandLine": "powershell.exe -NoProfile"
                    }
                }
            }),
        );

        let output = render_hunt_match(&rule, &event, OutputFormat::Pretty, true);

        assert!(output.contains("│ Channel"));
        assert!(output.contains("│ File"));
        assert!(output.contains("Security.evtx"));
        assert!(output.contains("│ 4688/42"));
    }

    #[test]
    fn hunt_pretty_table_stays_aligned_with_embedded_newlines() {
        let rule =
            SigmaRule::test_rule("Suspicious Process With Unicode σ", Some("high".to_owned()));
        let event = Event::from_raw(
            &DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from(".")),
            Some(42),
            json!({
                "Event": {
                    "System": {
                        "EventID": 4688,
                        "Channel": "Microsoft-Windows-Security-Auditing/Operational",
                        "Computer": "WIN-01",
                        "TimeCreated": {
                            "#attributes": {
                                "SystemTime": "2026-06-27T12:00:00Z"
                            }
                        }
                    },
                    "EventData": {
                        "CommandLine": "first line\nsecond line with a veryveryveryveryveryverylongtoken",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    }
                }
            }),
        );

        let output = render_hunt_match(&rule, &event, OutputFormat::Pretty, false);
        let lines = output.lines().collect::<Vec<_>>();
        let expected_width = text_width(lines[0]);

        for line in lines {
            assert_eq!(
                text_width(line),
                expected_width,
                "table line should stay aligned after renderer-controlled wrapping:\n{output}"
            );
        }

        assert!(
            output.contains(r"first line\nsecond line"),
            "embedded payload newlines should be escaped inside the payload cell:\n{output}"
        );
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
            full: false,
            output: None,
            min_level: None,
            summary: false,
        }
    }
}
