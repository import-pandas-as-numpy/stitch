use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::event::{Event, FieldValue};

#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub path: PathBuf,
    pub name: Option<String>,
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub tags: Vec<String>,
    logsource: LogsourcePrefilter,
    detection: Detection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigmaCorrelationRule {
    pub path: PathBuf,
    pub name: Option<String>,
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub tags: Vec<String>,
    pub correlation: CorrelationDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationDefinition {
    pub kind: CorrelationKind,
    pub referenced_rules: Vec<String>,
    pub group_by: Vec<String>,
    pub timespan: Duration,
    pub condition: Option<CountCondition>,
    pub value_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationKind {
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountCondition {
    operator: CountOperator,
    threshold: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CountOperator {
    GreaterThan,
    GreaterThanOrEqual,
    Equal,
    NotEqual,
    LessThanOrEqual,
    LessThan,
}

#[derive(Debug, Default, Clone)]
pub struct SigmaLoadReport {
    pub rules: Vec<SigmaRule>,
    pub correlations: Vec<SigmaCorrelationRule>,
    pub skipped_rules: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationRuntimeScope {
    File,
    Host,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigmaCorrelationMatch {
    pub rule: SigmaCorrelationRule,
    pub group: Vec<(String, String)>,
    pub window_start: String,
    pub window_end: String,
    pub matches: Vec<CorrelationSourceMatch>,
}

#[derive(Debug)]
pub struct SigmaEventContext<'a> {
    event: &'a Event,
    raw_text: OnceCell<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationSourceMatch {
    pub rule_title: String,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub timestamp: String,
    pub record_id: Option<u64>,
    pub channel: Option<String>,
    pub event_id: Option<u64>,
    pub computer: Option<String>,
    pub file_path: PathBuf,
    pub fields: Vec<(String, Option<String>)>,
}

#[derive(Debug)]
pub struct SigmaCorrelationEngine {
    rules: Vec<CorrelationRuntimeRule>,
    scope: CorrelationRuntimeScope,
    max_state: usize,
    allowed_lateness: Duration,
    max_seen_timestamp: Option<OffsetDateTime>,
    state: HashMap<CorrelationStateKey, CorrelationWindow>,
    evicted_state_entries: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SigmaCorrelationStats {
    pub state_entries: usize,
    pub evicted_state_entries: usize,
}

#[derive(Debug, Clone)]
struct CorrelationRuntimeRule {
    index: usize,
    rule: SigmaCorrelationRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CorrelationStateKey {
    rule_index: usize,
    scope: String,
    group: Vec<(String, String)>,
}

#[derive(Debug, Default)]
struct CorrelationWindow {
    matches: VecDeque<CorrelationWindowMatch>,
    alerted: bool,
}

#[derive(Debug, Clone)]
struct CorrelationWindowMatch {
    timestamp: OffsetDateTime,
    source: CorrelationSourceMatch,
    values: Vec<String>,
    reference_index: usize,
}

#[derive(Debug, Error)]
pub enum SigmaLoadError {
    #[error("rule path is neither a file nor directory: {path}")]
    UnsupportedPath { path: PathBuf },
    #[error("failed to read rule directory {path}: {source}")]
    DirectoryRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read Sigma rule {path}: {source}")]
    RuleRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse Sigma rule {path}: {source}")]
    RuleParse {
        path: PathBuf,
        #[source]
        source: noyalib::Error,
    },
    #[error("unsupported Sigma rule {path}: {message}")]
    UnsupportedRule { path: PathBuf, message: String },
}

#[derive(Debug, Deserialize)]
struct RawSigmaRule {
    name: Option<String>,
    title: Option<String>,
    id: Option<String>,
    status: Option<String>,
    level: Option<String>,
    #[serde(default)]
    tags: StringList,
    #[serde(rename = "type")]
    rule_type: Option<String>,
    logsource: Option<RawLogsource>,
    correlation: Option<noyalib::Value>,
    detection: Option<noyalib::Value>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct RawLogsource {
    product: Option<String>,
    service: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Clone)]
struct Detection {
    condition: ConditionExpr,
    selections: Vec<Selection>,
    prefilter: SigmaMetadataPrefilter,
}

#[derive(Debug, Clone)]
struct Selection {
    name: String,
    alternatives: Vec<SelectionAlternative>,
}

#[derive(Debug, Clone)]
struct SelectionAlternative {
    predicates: Vec<FieldPredicate>,
    keywords: Vec<KeywordPredicate>,
}

#[derive(Debug, Clone)]
struct FieldPredicate {
    field: String,
    matcher: FieldMatcher,
    values: Vec<SigmaValue>,
    regexes: Vec<Regex>,
    networks: Vec<IpNetwork>,
}

#[derive(Debug, Clone)]
struct KeywordPredicate {
    values: Vec<SigmaValue>,
    require_all: bool,
    case: StringCase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SigmaValue {
    String(String),
    Number(u64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldMatcher {
    Equals { require_all: bool, case: StringCase },
    NotEquals { require_all: bool, case: StringCase },
    Contains { require_all: bool, case: StringCase },
    StartsWith { require_all: bool, case: StringCase },
    EndsWith { require_all: bool, case: StringCase },
    Exists,
    LessThan { require_all: bool },
    LessThanOrEqual { require_all: bool },
    GreaterThan { require_all: bool },
    GreaterThanOrEqual { require_all: bool },
    Regex { require_all: bool },
    Cidr { require_all: bool },
    FieldRef { require_all: bool, negated: bool },
    TimePart { part: TimePart, require_all: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum StringCase {
    #[default]
    Insensitive,
    Sensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimePart {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueTransform {
    Windash,
    Base64,
    Base64Offset,
    Utf16Le,
    Utf16Be,
    Utf16Bom,
    RegexFlags {
        case_insensitive: bool,
        multi_line: bool,
        dot_matches_new_line: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConditionExpr {
    Selection(String),
    OneOf(String),
    AllOf(String),
    Not(Box<ConditionExpr>),
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
}

impl SigmaRule {
    #[cfg(test)]
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        self.matches_context(&SigmaEventContext::new(event))
    }

    #[must_use]
    pub fn matches_context(&self, context: &SigmaEventContext<'_>) -> bool {
        self.logsource.matches(context.event()) && self.detection.matches(context)
    }

    #[must_use]
    pub fn required_event_ids(&self) -> Option<Vec<u64>> {
        self.detection.prefilter.required_event_ids()
    }

    #[must_use]
    pub fn required_channels(&self) -> Option<Vec<String>> {
        required_channels(&self.logsource, &self.detection.prefilter)
    }

    #[must_use]
    pub fn is_referenced_by(&self, references: &[String]) -> bool {
        references
            .iter()
            .any(|reference| self.matches_reference(reference))
    }

    fn matches_reference(&self, reference: &str) -> bool {
        self.name.as_deref() == Some(reference)
            || self.id.as_deref() == Some(reference)
            || self.title == reference
    }

    #[cfg(test)]
    fn metadata_prefilter_count(&self) -> usize {
        self.detection.prefilter.len()
    }

    #[cfg(test)]
    fn logsource_prefilter_count(&self) -> usize {
        self.logsource.len()
    }

    #[cfg(test)]
    pub fn test_rule(title: impl Into<String>, level: Option<String>) -> Self {
        let title = title.into();
        Self {
            path: PathBuf::from("rule.yml"),
            name: Some(title.to_ascii_lowercase().replace(' ', "_")),
            title,
            id: Some("11111111-1111-1111-1111-111111111111".to_owned()),
            status: Some("test".to_owned()),
            level,
            tags: vec!["attack.execution".to_owned()],
            logsource: LogsourcePrefilter::default(),
            detection: Detection {
                condition: ConditionExpr::Selection("selection".to_owned()),
                selections: Vec::new(),
                prefilter: SigmaMetadataPrefilter::default(),
            },
        }
    }
}

impl<'a> SigmaEventContext<'a> {
    #[must_use]
    pub fn new(event: &'a Event) -> Self {
        Self {
            event,
            raw_text: OnceCell::new(),
        }
    }

    fn event(&self) -> &Event {
        self.event
    }

    fn raw_text(&self) -> &str {
        self.raw_text.get_or_init(|| self.event.raw.to_string())
    }
}

#[derive(Debug, Clone, Default)]
struct LogsourcePrefilter {
    channels: Vec<String>,
}

impl LogsourcePrefilter {
    fn from_raw(logsource: Option<&RawLogsource>) -> Self {
        let Some(logsource) = logsource else {
            return Self::default();
        };

        if !logsource_is_windows(logsource) {
            return Self::default();
        }

        Self {
            channels: logsource_channels(logsource),
        }
    }

    fn matches(&self, event: &Event) -> bool {
        self.channels.is_empty()
            || event.metadata.channel.as_deref().is_some_and(|channel| {
                self.channels
                    .iter()
                    .any(|expected| channel.eq_ignore_ascii_case(expected))
            })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.channels.len()
    }
}

fn logsource_is_windows(logsource: &RawLogsource) -> bool {
    logsource
        .product
        .as_deref()
        .is_none_or(|product| product.eq_ignore_ascii_case("windows"))
}

fn logsource_channels(logsource: &RawLogsource) -> Vec<String> {
    let mut channels = Vec::new();

    if let Some(service) = logsource.service.as_deref() {
        channels.extend(logsource_service_channels(service));
    }

    if let Some(category) = logsource.category.as_deref() {
        channels.extend(logsource_category_channels(category));
    }

    channels.sort();
    channels.dedup();
    channels
}

fn logsource_service_channels(service: &str) -> Vec<String> {
    match service.to_ascii_lowercase().as_str() {
        "security" => vec!["Security".to_owned()],
        "system" => vec!["System".to_owned()],
        "sysmon" => vec!["Microsoft-Windows-Sysmon/Operational".to_owned()],
        "powershell" => vec![
            "Microsoft-Windows-PowerShell/Operational".to_owned(),
            "Windows PowerShell".to_owned(),
        ],
        "defender" | "windefend" | "microsoft-windows-windows defender" => {
            vec!["Microsoft-Windows-Windows Defender/Operational".to_owned()]
        }
        "wmi" | "wmi-activity" => vec!["Microsoft-Windows-WMI-Activity/Operational".to_owned()],
        "taskscheduler" | "task-scheduler" => {
            vec!["Microsoft-Windows-TaskScheduler/Operational".to_owned()]
        }
        _ => Vec::new(),
    }
}

fn logsource_category_channels(category: &str) -> Vec<String> {
    match category.to_ascii_lowercase().as_str() {
        "process_creation" | "network_connection" | "file_event" | "dns_query" => {
            vec!["Microsoft-Windows-Sysmon/Operational".to_owned()]
        }
        _ => Vec::new(),
    }
}

impl CountCondition {
    #[cfg(test)]
    pub fn test_gte(threshold: usize) -> Self {
        Self {
            operator: CountOperator::GreaterThanOrEqual,
            threshold,
        }
    }

    fn matches(self, count: usize) -> bool {
        match self.operator {
            CountOperator::GreaterThan => count > self.threshold,
            CountOperator::GreaterThanOrEqual => count >= self.threshold,
            CountOperator::Equal => count == self.threshold,
            CountOperator::NotEqual => count != self.threshold,
            CountOperator::LessThanOrEqual => count <= self.threshold,
            CountOperator::LessThan => count < self.threshold,
        }
    }
}

impl SigmaCorrelationEngine {
    #[must_use]
    pub fn new(
        rules: &[SigmaCorrelationRule],
        scope: CorrelationRuntimeScope,
        max_state: usize,
    ) -> Self {
        Self::new_with_lateness(rules, scope, max_state, Duration::seconds(0))
    }

    #[must_use]
    pub fn new_with_lateness(
        rules: &[SigmaCorrelationRule],
        scope: CorrelationRuntimeScope,
        max_state: usize,
        allowed_lateness: Duration,
    ) -> Self {
        Self {
            rules: rules
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, rule)| CorrelationRuntimeRule { index, rule })
                .collect(),
            scope,
            max_state,
            allowed_lateness,
            max_seen_timestamp: None,
            state: HashMap::new(),
            evicted_state_entries: 0,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn stats(&self) -> SigmaCorrelationStats {
        SigmaCorrelationStats {
            state_entries: self.state.len(),
            evicted_state_entries: self.evicted_state_entries,
        }
    }

    pub fn observe_match(
        &mut self,
        rule: &SigmaRule,
        event: &Event,
        event_fields: &[String],
    ) -> Vec<SigmaCorrelationMatch> {
        let mut matches = Vec::new();
        let timestamp = event
            .metadata
            .timestamp
            .as_deref()
            .and_then(parse_event_timestamp);
        let Some(timestamp) = timestamp else {
            return matches;
        };
        let watermark = self.update_watermark(timestamp);
        self.evict_expired_state(watermark);

        if timestamp < watermark {
            return matches;
        }

        for runtime_rule in self.rules.clone() {
            let Some(reference_index) = correlation_reference_index(&runtime_rule.rule, rule)
            else {
                continue;
            };

            let Some(group) = correlation_group(&runtime_rule.rule, event, self.scope) else {
                continue;
            };
            let key = CorrelationStateKey {
                rule_index: runtime_rule.index,
                scope: correlation_scope_value(event, self.scope),
                group: group.clone(),
            };
            let Some(values) = correlation_value_fields(&runtime_rule.rule, event) else {
                continue;
            };
            let source = correlation_source_match(rule, event, event_fields);
            let window = self.state.entry(key).or_default();
            insert_correlation_match(
                &mut window.matches,
                CorrelationWindowMatch {
                    timestamp,
                    source,
                    values,
                    reference_index,
                },
            );
            evict_old_correlation_matches(
                &mut window.matches,
                watermark,
                runtime_rule.rule.correlation.timespan,
            );

            if window.matches.is_empty() {
                continue;
            }

            let condition_matches = correlation_window_matches(&runtime_rule.rule, window);
            if condition_matches && !window.alerted {
                window.alerted = true;
                matches.push(build_correlation_match(&runtime_rule.rule, group, window));
            } else if !condition_matches {
                window.alerted = false;
            }
        }

        self.enforce_state_limit();
        matches
    }

    fn update_watermark(&mut self, timestamp: OffsetDateTime) -> OffsetDateTime {
        self.max_seen_timestamp = Some(
            self.max_seen_timestamp
                .map_or(timestamp, |current| current.max(timestamp)),
        );

        self.max_seen_timestamp
            .expect("max seen timestamp should be set")
            - self.allowed_lateness
    }

    fn evict_expired_state(&mut self, watermark: OffsetDateTime) {
        let timespans = self
            .rules
            .iter()
            .map(|rule| (rule.index, rule.rule.correlation.timespan))
            .collect::<HashMap<_, _>>();

        for (key, window) in &mut self.state {
            if let Some(timespan) = timespans.get(&key.rule_index) {
                evict_old_correlation_matches(&mut window.matches, watermark, *timespan);
            }
        }

        self.state.retain(|_, window| !window.matches.is_empty());
    }

    fn enforce_state_limit(&mut self) {
        if self.max_state == 0 || self.state.len() <= self.max_state {
            return;
        }

        while self.state.len() > self.max_state {
            let Some(key) = oldest_correlation_state_key(&self.state) else {
                return;
            };
            self.state.remove(&key);
            self.evicted_state_entries += 1;
        }
    }
}

impl Detection {
    fn matches(&self, context: &SigmaEventContext<'_>) -> bool {
        self.prefilter.matches(context.event()) && self.condition.matches(context, &self.selections)
    }
}

#[derive(Debug, Clone, Default)]
struct SigmaMetadataPrefilter {
    predicates: Vec<FieldPredicate>,
}

impl SigmaMetadataPrefilter {
    fn from_condition(condition: &ConditionExpr, selections: &[Selection]) -> Self {
        let mut predicates = Vec::new();
        collect_condition_prefilters(condition, selections, &mut predicates);
        Self { predicates }
    }

    fn matches(&self, event: &Event) -> bool {
        self.predicates
            .iter()
            .all(|predicate| predicate.matches(event))
    }

    fn required_event_ids(&self) -> Option<Vec<u64>> {
        let mut event_ids = None;

        for predicate in &self.predicates {
            if predicate.field == "event.id" {
                event_ids = event_id_values(predicate);
            }
        }

        event_ids
    }

    fn required_channels(&self) -> Option<Vec<String>> {
        let mut channels = None;

        for predicate in &self.predicates {
            if predicate.field == "channel" {
                channels = channel_values(predicate);
            }
        }

        channels
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.predicates.len()
    }
}

fn event_id_values(predicate: &FieldPredicate) -> Option<Vec<u64>> {
    let FieldMatcher::Equals { require_all, .. } = predicate.matcher else {
        return None;
    };

    let values = predicate
        .values
        .iter()
        .map(|value| match value {
            SigmaValue::Number(value) => Some(*value),
            SigmaValue::String(value) => value.parse().ok(),
            SigmaValue::Bool(_) | SigmaValue::Null => None,
        })
        .collect::<Option<Vec<_>>>()?;

    if require_all && values.len() != 1 {
        return None;
    }

    Some(values)
}

fn required_channels(
    logsource: &LogsourcePrefilter,
    metadata: &SigmaMetadataPrefilter,
) -> Option<Vec<String>> {
    match (
        non_empty_channels(&logsource.channels),
        metadata.required_channels(),
    ) {
        (None, None) => None,
        (Some(channels), None) | (None, Some(channels)) => Some(channels),
        (Some(logsource_channels), Some(metadata_channels)) => {
            Some(intersect_channels(&logsource_channels, &metadata_channels))
        }
    }
}

fn non_empty_channels(channels: &[String]) -> Option<Vec<String>> {
    (!channels.is_empty()).then(|| channels.to_vec())
}

fn channel_values(predicate: &FieldPredicate) -> Option<Vec<String>> {
    let FieldMatcher::Equals { require_all, .. } = predicate.matcher else {
        return None;
    };

    let mut values = predicate
        .values
        .iter()
        .map(|value| match value {
            SigmaValue::String(value) => Some(value.clone()),
            SigmaValue::Number(_) | SigmaValue::Bool(_) | SigmaValue::Null => None,
        })
        .collect::<Option<Vec<_>>>()?;

    if require_all && values.len() != 1 {
        return None;
    }

    sort_dedup_case_insensitive(&mut values);
    Some(values)
}

fn intersect_channels(left: &[String], right: &[String]) -> Vec<String> {
    let mut channels = left
        .iter()
        .filter(|left| right.iter().any(|right| left.eq_ignore_ascii_case(right)))
        .cloned()
        .collect::<Vec<_>>();
    sort_dedup_case_insensitive(&mut channels);
    channels
}

fn sort_dedup_case_insensitive(values: &mut Vec<String>) {
    values.sort_by_key(|value| value.to_ascii_lowercase());
    values.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
}

fn collect_condition_prefilters(
    condition: &ConditionExpr,
    selections: &[Selection],
    predicates: &mut Vec<FieldPredicate>,
) {
    match condition {
        ConditionExpr::Selection(name) => {
            if let Some(selection) = selections.iter().find(|selection| selection.name == *name) {
                collect_selection_prefilters(selection, predicates);
            }
        }
        ConditionExpr::AllOf(pattern) => {
            for selection in matching_selections(pattern, selections) {
                collect_selection_prefilters(selection, predicates);
            }
        }
        ConditionExpr::And(left, right) => {
            collect_condition_prefilters(left, selections, predicates);
            collect_condition_prefilters(right, selections, predicates);
        }
        ConditionExpr::OneOf(_) | ConditionExpr::Not(_) | ConditionExpr::Or(_, _) => {}
    }
}

fn collect_selection_prefilters(selection: &Selection, predicates: &mut Vec<FieldPredicate>) {
    let [alternative] = selection.alternatives.as_slice() else {
        return;
    };

    predicates.extend(
        alternative
            .predicates
            .iter()
            .filter(|predicate| is_metadata_prefilter_predicate(predicate))
            .cloned(),
    );
}

fn is_metadata_prefilter_predicate(predicate: &FieldPredicate) -> bool {
    is_metadata_prefilter_field(&predicate.field)
        && !predicate
            .values
            .iter()
            .any(|value| matches!(value, SigmaValue::Null))
        && matches!(
            predicate.matcher,
            FieldMatcher::Equals { .. }
                | FieldMatcher::LessThan { .. }
                | FieldMatcher::LessThanOrEqual { .. }
                | FieldMatcher::GreaterThan { .. }
                | FieldMatcher::GreaterThanOrEqual { .. }
        )
}

fn is_metadata_prefilter_field(field: &str) -> bool {
    matches!(
        field,
        "timestamp"
            | "event.timestamp"
            | "winlog.timestamp"
            | "Event.System.TimeCreated.SystemTime"
            | "Event.System.TimeCreated.#attributes.SystemTime"
            | "channel"
            | "event.channel"
            | "winlog.channel"
            | "provider"
            | "event.provider"
            | "winlog.provider_name"
            | "event.id"
            | "event_id"
            | "winlog.event_id"
            | "computer"
            | "host"
            | "host.name"
            | "source.computer"
    )
}

impl ConditionExpr {
    fn matches(&self, context: &SigmaEventContext<'_>, selections: &[Selection]) -> bool {
        match self {
            Self::Selection(name) => selections
                .iter()
                .find(|selection| selection.name == *name)
                .is_some_and(|selection| selection.matches(context)),
            Self::OneOf(pattern) => matching_selections(pattern, selections)
                .into_iter()
                .any(|selection| selection.matches(context)),
            Self::AllOf(pattern) => {
                let matched = matching_selections(pattern, selections);
                !matched.is_empty() && matched.iter().all(|selection| selection.matches(context))
            }
            Self::Not(expression) => !expression.matches(context, selections),
            Self::And(left, right) => {
                left.matches(context, selections) && right.matches(context, selections)
            }
            Self::Or(left, right) => {
                left.matches(context, selections) || right.matches(context, selections)
            }
        }
    }
}

fn matching_selections<'a>(pattern: &str, selections: &'a [Selection]) -> Vec<&'a Selection> {
    selections
        .iter()
        .filter(|selection| pattern == "them" || wildcard_matches(pattern, &selection.name))
        .collect()
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let mut remaining = value;
    let mut parts = pattern.split('*').peekable();
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');

    if let Some(first) = parts.next() {
        if !starts_with_wildcard {
            let Some(after_prefix) = remaining.strip_prefix(first) else {
                return false;
            };
            remaining = after_prefix;
        } else if !first.is_empty() {
            let Some(index) = remaining.find(first) else {
                return false;
            };
            remaining = &remaining[index + first.len()..];
        }
    }

    while let Some(part) = parts.next() {
        if part.is_empty() {
            continue;
        }

        if parts.peek().is_none() && !ends_with_wildcard {
            return remaining.ends_with(part);
        }

        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
    }

    ends_with_wildcard || remaining.is_empty()
}

impl Selection {
    fn matches(&self, context: &SigmaEventContext<'_>) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| alternative.matches(context))
    }
}

impl SelectionAlternative {
    fn matches(&self, context: &SigmaEventContext<'_>) -> bool {
        self.predicates
            .iter()
            .all(|predicate| predicate.matches(context.event()))
            && self.keywords.iter().all(|keyword| keyword.matches(context))
    }
}

impl FieldPredicate {
    fn matches(&self, event: &Event) -> bool {
        if matches!(self.matcher, FieldMatcher::Exists) {
            return matches_exists(event.field(&self.field), &self.values);
        }

        let null_matches = matches!(self.matcher, FieldMatcher::Equals { .. })
            && match_values_missing_field(&self.values, matcher_require_all(self.matcher));

        event.field(&self.field).map_or(null_matches, |field| {
            let null_matches = matches!(self.matcher, FieldMatcher::Equals { .. })
                && match_values_present_field_null(
                    field,
                    &self.values,
                    matcher_require_all(self.matcher),
                );

            null_matches
                || match self.matcher {
                    FieldMatcher::Regex { require_all } => {
                        match_compiled_regexes(field, &self.regexes, require_all)
                    }
                    FieldMatcher::Cidr { require_all } => {
                        match_compiled_networks(field, &self.networks, require_all)
                    }
                    FieldMatcher::FieldRef {
                        require_all,
                        negated,
                    } => match_field_refs(event, field, &self.values, require_all, negated),
                    FieldMatcher::TimePart { part, require_all } => {
                        match_time_parts(field, &self.values, part, require_all)
                    }
                    matcher => matcher.matches(field, &self.values),
                }
        })
    }
}

impl KeywordPredicate {
    fn matches(&self, context: &SigmaEventContext<'_>) -> bool {
        let event_text = context.raw_text();
        if self.require_all {
            self.values
                .iter()
                .all(|value| keyword_value_matches(event_text, value, self.case))
        } else {
            self.values
                .iter()
                .any(|value| keyword_value_matches(event_text, value, self.case))
        }
    }
}

impl FieldMatcher {
    fn matches(self, field: FieldValue<'_>, expected: &[SigmaValue]) -> bool {
        match self {
            Self::Equals { require_all, case } => {
                match_values(field, expected, require_all, case, equals_value)
            }
            Self::NotEquals { require_all, case } => {
                match_values(field, expected, require_all, case, not_equals_value)
            }
            Self::Contains { require_all, case } => {
                match_values(field, expected, require_all, case, contains_value)
            }
            Self::StartsWith { require_all, case } => {
                match_values(field, expected, require_all, case, starts_with_value)
            }
            Self::EndsWith { require_all, case } => {
                match_values(field, expected, require_all, case, ends_with_value)
            }
            Self::LessThan { require_all } => {
                match_ordered_values(field, expected, require_all, |left, right| left < right)
            }
            Self::LessThanOrEqual { require_all } => {
                match_ordered_values(field, expected, require_all, |left, right| left <= right)
            }
            Self::GreaterThan { require_all } => {
                match_ordered_values(field, expected, require_all, |left, right| left > right)
            }
            Self::GreaterThanOrEqual { require_all } => {
                match_ordered_values(field, expected, require_all, |left, right| left >= right)
            }
            Self::Exists
            | Self::Regex { require_all: _ }
            | Self::Cidr { require_all: _ }
            | Self::FieldRef { .. }
            | Self::TimePart { .. } => false,
        }
    }
}

#[derive(Debug, Default)]
struct StringList(Vec<String>);

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = noyalib::Value::deserialize(deserializer)?;

        match value {
            noyalib::Value::Sequence(values) => values
                .into_iter()
                .map(|value| match value {
                    noyalib::Value::String(value) => Ok(value),
                    other => Err(serde::de::Error::custom(format!(
                        "expected string tag, found {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Self),
            noyalib::Value::String(value) => Ok(Self(vec![value])),
            noyalib::Value::Null => Ok(Self::default()),
            other => Err(serde::de::Error::custom(format!(
                "expected string or list of strings, found {other:?}"
            ))),
        }
    }
}

pub fn load_sigma_rules(paths: &[PathBuf]) -> Result<SigmaLoadReport, SigmaLoadError> {
    load_sigma_rules_with_mode(paths, SigmaLoadMode::Strict)
}

pub fn load_sigma_rules_non_strict(paths: &[PathBuf]) -> Result<SigmaLoadReport, SigmaLoadError> {
    load_sigma_rules_with_mode(paths, SigmaLoadMode::SkipInvalidRules)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigmaLoadMode {
    Strict,
    SkipInvalidRules,
}

fn load_sigma_rules_with_mode(
    paths: &[PathBuf],
    mode: SigmaLoadMode,
) -> Result<SigmaLoadReport, SigmaLoadError> {
    let mut report = SigmaLoadReport::default();

    for path in paths {
        load_path(path, &mut report, mode)?;
    }

    report
        .rules
        .sort_by(|left, right| left.path.cmp(&right.path));
    report
        .correlations
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(report)
}

fn load_path(
    path: &Path,
    report: &mut SigmaLoadReport,
    mode: SigmaLoadMode,
) -> Result<(), SigmaLoadError> {
    if path.is_file() {
        if is_yaml_path(path) {
            match load_file(path) {
                Ok(file_report) => report.merge(file_report),
                Err(error) if mode == SigmaLoadMode::SkipInvalidRules && error.is_rule_error() => {
                    report.skipped_rules += 1;
                }
                Err(error) => return Err(error),
            }
        }

        return Ok(());
    }

    if path.is_dir() {
        for entry in fs::read_dir(path).map_err(|source| SigmaLoadError::DirectoryRead {
            path: path.to_path_buf(),
            source,
        })? {
            let entry = entry.map_err(|source| SigmaLoadError::DirectoryRead {
                path: path.to_path_buf(),
                source,
            })?;
            load_path(&entry.path(), report, mode)?;
        }

        return Ok(());
    }

    Err(SigmaLoadError::UnsupportedPath {
        path: path.to_path_buf(),
    })
}

impl SigmaLoadReport {
    fn merge(&mut self, mut other: Self) {
        self.rules.append(&mut other.rules);
        self.correlations.append(&mut other.correlations);
        self.skipped_rules += other.skipped_rules;
    }
}

impl SigmaLoadError {
    fn is_rule_error(&self) -> bool {
        matches!(
            self,
            Self::RuleRead { .. } | Self::RuleParse { .. } | Self::UnsupportedRule { .. }
        )
    }
}

fn load_file(path: &Path) -> Result<SigmaLoadReport, SigmaLoadError> {
    let content = fs::read_to_string(path).map_err(|source| SigmaLoadError::RuleRead {
        path: path.to_path_buf(),
        source,
    })?;
    let documents = split_yaml_documents(&content);

    if documents.is_empty() {
        return Err(unsupported_rule(path, "rule file is empty"));
    }

    let mut report = SigmaLoadReport::default();

    for document in documents {
        load_document(path, document, &mut report)?;
    }

    Ok(report)
}

fn load_document(
    path: &Path,
    document: &str,
    report: &mut SigmaLoadReport,
) -> Result<(), SigmaLoadError> {
    let raw: RawSigmaRule =
        noyalib::from_str(document).map_err(|source| SigmaLoadError::RuleParse {
            path: path.to_path_buf(),
            source,
        })?;
    let title = raw.title.clone().unwrap_or_else(|| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("untitled")
            .to_owned()
    });

    if is_correlation_rule(&raw) {
        report.correlations.push(SigmaCorrelationRule {
            path: path.to_path_buf(),
            name: raw.name,
            title,
            id: raw.id,
            status: raw.status,
            level: raw.level,
            tags: raw.tags.0,
            correlation: parse_correlation_definition(path, raw.correlation)?,
        });
        return Ok(());
    }

    report.rules.push(SigmaRule {
        path: path.to_path_buf(),
        name: raw.name,
        title,
        id: raw.id,
        status: raw.status,
        level: raw.level,
        tags: raw.tags.0,
        logsource: LogsourcePrefilter::from_raw(raw.logsource.as_ref()),
        detection: parse_detection(path, raw.detection)?,
    });

    Ok(())
}

fn parse_correlation_definition(
    path: &Path,
    correlation: Option<noyalib::Value>,
) -> Result<CorrelationDefinition, SigmaLoadError> {
    let Some(correlation) = correlation else {
        return Err(unsupported_rule(
            path,
            "correlation rule is missing a correlation mapping",
        ));
    };

    let noyalib::Value::Mapping(entries) = &correlation else {
        return Err(unsupported_rule(
            path,
            "correlation section must be a mapping",
        ));
    };

    let mut kind = None;
    let mut referenced_rules = Vec::new();
    let mut group_by = Vec::new();
    let mut timespan = None;
    let mut condition = None;

    for (key, value) in entries {
        match key.as_str() {
            "type" => {
                kind = Some(parse_correlation_kind(path, value)?);
            }
            "rules" => {
                referenced_rules = parse_correlation_string_list(path, "rules", value)?;
            }
            "group-by" | "group_by" => {
                group_by = parse_correlation_string_list(path, "group-by", value)?;
            }
            "timespan" | "timeframe" => {
                timespan = Some(parse_correlation_timespan(path, value)?);
            }
            "condition" => {
                condition = Some(parse_count_condition(path, value)?);
            }
            _ => {}
        }
    }

    let kind = kind.ok_or_else(|| unsupported_rule(path, "correlation rules require a type"))?;
    let timespan =
        timespan.ok_or_else(|| unsupported_rule(path, "correlation rules require a timespan"))?;
    if referenced_rules.is_empty() {
        return Err(unsupported_rule(
            path,
            "correlation rules require a non-empty rules list",
        ));
    }
    if matches!(kind, CorrelationKind::ValueCount)
        && condition
            .as_ref()
            .is_none_or(|condition| condition.value_fields.is_empty())
    {
        return Err(unsupported_rule(
            path,
            "value_count correlation rules require a condition field",
        ));
    }
    if matches!(
        kind,
        CorrelationKind::EventCount | CorrelationKind::ValueCount
    ) && condition.is_none()
    {
        return Err(unsupported_rule(
            path,
            "count correlation rules require condition",
        ));
    }

    Ok(CorrelationDefinition {
        kind,
        referenced_rules,
        group_by,
        timespan,
        condition: condition.as_ref().map(|condition| condition.count),
        value_fields: condition.map_or_else(Vec::new, |condition| condition.value_fields),
    })
}

#[derive(Debug)]
struct ParsedCorrelationCondition {
    count: CountCondition,
    value_fields: Vec<String>,
}

fn parse_correlation_kind(
    path: &Path,
    value: &noyalib::Value,
) -> Result<CorrelationKind, SigmaLoadError> {
    let kind = parse_correlation_string(path, "type", value)?;

    match kind.as_str() {
        "event_count" => Ok(CorrelationKind::EventCount),
        "value_count" => Ok(CorrelationKind::ValueCount),
        "temporal" => Ok(CorrelationKind::Temporal),
        "temporal_ordered" => Ok(CorrelationKind::TemporalOrdered),
        _ => Err(unsupported_rule(
            path,
            format!("unsupported correlation type {kind:?}"),
        )),
    }
}

fn parse_correlation_timespan(
    path: &Path,
    value: &noyalib::Value,
) -> Result<Duration, SigmaLoadError> {
    let timespan = parse_correlation_string(path, "timespan", value)?;
    parse_sigma_duration(&timespan).ok_or_else(|| {
        unsupported_rule(
            path,
            format!(
                "invalid correlation timespan {timespan:?}; expected values like 30s, 5m, 2h, or 1d"
            ),
        )
    })
}

fn parse_count_condition(
    path: &Path,
    value: &noyalib::Value,
) -> Result<ParsedCorrelationCondition, SigmaLoadError> {
    match value {
        noyalib::Value::Mapping(entries) => parse_count_condition_mapping(path, entries),
        noyalib::Value::String(_) => parse_count_condition_string(path, value),
        other => Err(unsupported_rule(
            path,
            format!("correlation condition must be a mapping, found {other:?}"),
        )),
    }
}

fn parse_count_condition_mapping(
    path: &Path,
    entries: &noyalib::Mapping,
) -> Result<ParsedCorrelationCondition, SigmaLoadError> {
    let mut condition = None;
    let mut value_fields = Vec::new();

    for (key, value) in entries {
        match key.as_str() {
            "field" => value_fields = parse_correlation_string_list(path, "field", value)?,
            "gt" | "gte" | "eq" | "neq" | "lte" | "lt" | ">" | ">=" | "==" | "!=" | "<=" | "<" => {
                if condition.is_some() {
                    return Err(unsupported_rule(
                        path,
                        "correlation condition must contain exactly one count operator",
                    ));
                }
                condition = Some(CountCondition {
                    operator: parse_count_operator(path, key)?,
                    threshold: parse_correlation_usize(path, key, value)?,
                });
            }
            _ => {
                return Err(unsupported_rule(
                    path,
                    format!("unsupported correlation condition key {key:?}"),
                ));
            }
        }
    }

    Ok(ParsedCorrelationCondition {
        count: condition.ok_or_else(|| {
            unsupported_rule(path, "correlation condition is missing a count operator")
        })?,
        value_fields,
    })
}

fn parse_count_condition_string(
    path: &Path,
    value: &noyalib::Value,
) -> Result<ParsedCorrelationCondition, SigmaLoadError> {
    let condition = parse_correlation_string(path, "condition", value)?;
    let mut parts = condition.split_whitespace();
    let operator = parts
        .next()
        .ok_or_else(|| unsupported_rule(path, "correlation condition is empty"))?;
    let threshold = parts
        .next()
        .ok_or_else(|| unsupported_rule(path, "correlation condition is missing a threshold"))?;

    if parts.next().is_some() {
        return Err(unsupported_rule(
            path,
            format!("unsupported correlation condition {condition:?}"),
        ));
    }

    let operator = parse_count_operator(path, operator)?;
    let threshold = threshold.parse::<usize>().map_err(|_| {
        unsupported_rule(
            path,
            format!(
                "correlation condition threshold must be an unsigned integer, found {threshold:?}"
            ),
        )
    })?;

    Ok(ParsedCorrelationCondition {
        count: CountCondition {
            operator,
            threshold,
        },
        value_fields: Vec::new(),
    })
}

fn parse_count_operator(path: &Path, operator: &str) -> Result<CountOperator, SigmaLoadError> {
    match operator {
        "gt" | ">" => Ok(CountOperator::GreaterThan),
        "gte" | ">=" => Ok(CountOperator::GreaterThanOrEqual),
        "eq" | "==" => Ok(CountOperator::Equal),
        "neq" | "!=" => Ok(CountOperator::NotEqual),
        "lte" | "<=" => Ok(CountOperator::LessThanOrEqual),
        "lt" | "<" => Ok(CountOperator::LessThan),
        _ => Err(unsupported_rule(
            path,
            format!("unsupported correlation condition operator {operator:?}"),
        )),
    }
}

fn parse_correlation_usize(
    path: &Path,
    field: &str,
    value: &noyalib::Value,
) -> Result<usize, SigmaLoadError> {
    match value {
        noyalib::Value::Number(value) => {
            let number = noyalib::Value::Number(*value);
            let json_value = noyalib::from_value::<JsonValue>(&number).map_err(|source| {
                SigmaLoadError::RuleParse {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            json_value
                .as_u64()
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| {
                    unsupported_rule(
                        path,
                        format!("correlation condition {field:?} must be an unsigned integer"),
                    )
                })
        }
        noyalib::Value::String(value) => value.parse::<usize>().map_err(|_| {
            unsupported_rule(
                path,
                format!("correlation condition {field:?} must be an unsigned integer"),
            )
        }),
        other => Err(unsupported_rule(
            path,
            format!("correlation condition {field:?} must be numeric, found {other:?}"),
        )),
    }
}

fn parse_correlation_string(
    path: &Path,
    field: &str,
    value: &noyalib::Value,
) -> Result<String, SigmaLoadError> {
    match value {
        noyalib::Value::String(value) => Ok(value.clone()),
        other => Err(unsupported_rule(
            path,
            format!("correlation field {field:?} must be a string, found {other:?}"),
        )),
    }
}

fn parse_correlation_string_list(
    path: &Path,
    field: &str,
    value: &noyalib::Value,
) -> Result<Vec<String>, SigmaLoadError> {
    match value {
        noyalib::Value::String(value) => Ok(vec![value.clone()]),
        noyalib::Value::Sequence(values) => values
            .iter()
            .map(|value| match value {
                noyalib::Value::String(value) => Ok(value.clone()),
                other => Err(unsupported_rule(
                    path,
                    format!("correlation field {field:?} must contain strings, found {other:?}"),
                )),
            })
            .collect(),
        other => Err(unsupported_rule(
            path,
            format!(
                "correlation field {field:?} must be a string or list of strings, found {other:?}"
            ),
        )),
    }
}

fn split_yaml_documents(content: &str) -> Vec<&str> {
    let mut documents = Vec::new();
    let mut start = 0usize;
    let mut offset = 0usize;

    for line in content.split_inclusive('\n') {
        if matches!(line.trim(), "---" | "...") {
            let document = content[start..offset].trim();
            if !document.is_empty() {
                documents.push(document);
            }
            start = offset + line.len();
        }

        offset += line.len();
    }

    let document = content[start..].trim();
    if !document.is_empty() {
        documents.push(document);
    }

    documents
}

#[must_use]
pub fn parse_sigma_duration(value: &str) -> Option<Duration> {
    let unit = value.chars().last()?;
    let number = value[..value.len().saturating_sub(unit.len_utf8())]
        .parse::<i64>()
        .ok()?;

    if number < 0 {
        return None;
    }

    Some(match unit {
        's' => Duration::seconds(number),
        'm' => Duration::minutes(number),
        'h' => Duration::hours(number),
        'd' => Duration::days(number),
        _ => return None,
    })
}

fn correlation_reference_index(
    correlation: &SigmaCorrelationRule,
    rule: &SigmaRule,
) -> Option<usize> {
    correlation
        .correlation
        .referenced_rules
        .iter()
        .position(|reference| rule.matches_reference(reference))
}

fn correlation_group(
    correlation: &SigmaCorrelationRule,
    event: &Event,
    scope: CorrelationRuntimeScope,
) -> Option<Vec<(String, String)>> {
    let mut group = Vec::new();

    match scope {
        CorrelationRuntimeScope::File => group.push((
            "scope.file".to_owned(),
            event.source.file_path.display().to_string(),
        )),
        CorrelationRuntimeScope::Host => group.push((
            "scope.host".to_owned(),
            event.metadata.computer.clone().unwrap_or_default(),
        )),
        CorrelationRuntimeScope::Global => {}
    }

    for field in &correlation.correlation.group_by {
        let resolved = sigma_field_alias(field);
        let value = event.field(&resolved)?.as_text()?;
        group.push((field.clone(), value));
    }

    Some(group)
}

fn correlation_value_fields(
    correlation: &SigmaCorrelationRule,
    event: &Event,
) -> Option<Vec<String>> {
    if !matches!(correlation.correlation.kind, CorrelationKind::ValueCount) {
        return Some(Vec::new());
    }

    correlation
        .correlation
        .value_fields
        .iter()
        .map(|field| {
            let resolved = sigma_field_alias(field);
            event.field(&resolved)?.as_text()
        })
        .collect()
}

fn correlation_window_matches(rule: &SigmaCorrelationRule, window: &CorrelationWindow) -> bool {
    match rule.correlation.kind {
        CorrelationKind::EventCount => rule
            .correlation
            .condition
            .is_some_and(|condition| condition.matches(window.matches.len())),
        CorrelationKind::ValueCount => {
            let mut values = window
                .matches
                .iter()
                .map(|entry| entry.values.clone())
                .collect::<Vec<_>>();
            values.sort();
            values.dedup();
            rule.correlation
                .condition
                .is_some_and(|condition| condition.matches(values.len()))
        }
        CorrelationKind::Temporal => temporal_window_matches(rule, window),
        CorrelationKind::TemporalOrdered => temporal_ordered_window_matches(rule, window),
    }
}

fn temporal_window_matches(rule: &SigmaCorrelationRule, window: &CorrelationWindow) -> bool {
    let mut seen = vec![false; rule.correlation.referenced_rules.len()];

    for entry in &window.matches {
        if let Some(value) = seen.get_mut(entry.reference_index) {
            *value = true;
        }
    }

    !seen.is_empty() && seen.into_iter().all(|seen| seen)
}

fn temporal_ordered_window_matches(
    rule: &SigmaCorrelationRule,
    window: &CorrelationWindow,
) -> bool {
    let mut next = 0usize;

    for entry in &window.matches {
        if entry.reference_index == next {
            next += 1;

            if next == rule.correlation.referenced_rules.len() {
                return true;
            }
        }
    }

    false
}

fn oldest_correlation_state_key(
    state: &HashMap<CorrelationStateKey, CorrelationWindow>,
) -> Option<CorrelationStateKey> {
    state
        .iter()
        .min_by(|(left_key, left_window), (right_key, right_window)| {
            let left_timestamp = left_window.matches.back().map(|entry| entry.timestamp);
            let right_timestamp = right_window.matches.back().map(|entry| entry.timestamp);

            left_timestamp
                .cmp(&right_timestamp)
                .then_with(|| left_key.rule_index.cmp(&right_key.rule_index))
                .then_with(|| left_key.scope.cmp(&right_key.scope))
                .then_with(|| left_key.group.cmp(&right_key.group))
        })
        .map(|(key, _)| key.clone())
}

fn correlation_scope_value(event: &Event, scope: CorrelationRuntimeScope) -> String {
    match scope {
        CorrelationRuntimeScope::File => event.source.file_path.display().to_string(),
        CorrelationRuntimeScope::Host => event.metadata.computer.clone().unwrap_or_default(),
        CorrelationRuntimeScope::Global => String::new(),
    }
}

fn correlation_source_match(
    rule: &SigmaRule,
    event: &Event,
    event_fields: &[String],
) -> CorrelationSourceMatch {
    CorrelationSourceMatch {
        rule_title: rule.title.clone(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        timestamp: event.metadata.timestamp.clone().unwrap_or_default(),
        record_id: event.metadata.record_id,
        channel: event.metadata.channel.clone(),
        event_id: event.metadata.event_id,
        computer: event.metadata.computer.clone(),
        file_path: event.source.file_path.clone(),
        fields: event_fields
            .iter()
            .map(|field| {
                let resolved = sigma_field_alias(field);
                (
                    field.clone(),
                    event.field(&resolved).and_then(FieldValue::as_text),
                )
            })
            .collect(),
    }
}

fn insert_correlation_match(
    matches: &mut VecDeque<CorrelationWindowMatch>,
    entry: CorrelationWindowMatch,
) {
    if let Some(index) = matches
        .iter()
        .position(|existing| existing.timestamp > entry.timestamp)
    {
        matches.insert(index, entry);
    } else {
        matches.push_back(entry);
    }
}

fn evict_old_correlation_matches(
    matches: &mut VecDeque<CorrelationWindowMatch>,
    watermark: OffsetDateTime,
    timespan: Duration,
) {
    while matches
        .front()
        .is_some_and(|entry| watermark - entry.timestamp > timespan)
    {
        matches.pop_front();
    }
}

fn build_correlation_match(
    rule: &SigmaCorrelationRule,
    group: Vec<(String, String)>,
    window: &CorrelationWindow,
) -> SigmaCorrelationMatch {
    let window_start = window
        .matches
        .front()
        .map(|entry| entry.source.timestamp.clone())
        .unwrap_or_default();
    let window_end = window
        .matches
        .back()
        .map(|entry| entry.source.timestamp.clone())
        .unwrap_or_default();

    SigmaCorrelationMatch {
        rule: rule.clone(),
        group,
        window_start,
        window_end,
        matches: window
            .matches
            .iter()
            .map(|entry| entry.source.clone())
            .collect(),
    }
}

fn parse_event_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok().or_else(|| {
        let normalized = format!("{value}Z");
        OffsetDateTime::parse(&normalized, &Rfc3339).ok()
    })
}

fn parse_detection(
    path: &Path,
    detection: Option<noyalib::Value>,
) -> Result<Detection, SigmaLoadError> {
    let Some(noyalib::Value::Mapping(entries)) = detection else {
        return Err(unsupported_rule(
            path,
            "rule is missing a detection mapping",
        ));
    };

    let mut condition = None;
    let mut selections = Vec::new();

    for (key, value) in entries {
        if key == "condition" {
            condition = Some(parse_condition_value(path, value)?);
            continue;
        }

        selections.push(parse_selection(path, key, value)?);
    }

    let condition_exprs =
        condition.ok_or_else(|| unsupported_rule(path, "missing detection condition"))?;
    let condition = combine_condition_exprs(
        condition_exprs
            .iter()
            .map(|condition_text| parse_condition(path, condition_text))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .ok_or_else(|| unsupported_rule(path, "condition is empty"))?;

    validate_condition_selections(path, &condition, &selections)?;
    let prefilter = SigmaMetadataPrefilter::from_condition(&condition, &selections);

    Ok(Detection {
        condition,
        selections,
        prefilter,
    })
}

fn parse_selection(
    path: &Path,
    name: String,
    value: noyalib::Value,
) -> Result<Selection, SigmaLoadError> {
    let alternatives = match value {
        noyalib::Value::Mapping(entries) => vec![parse_selection_mapping(path, entries)?],
        noyalib::Value::Sequence(values) => values
            .into_iter()
            .map(|value| parse_selection_alternative(path, value))
            .collect::<Result<Vec<_>, _>>()?,
        value => vec![parse_keyword_alternative(
            path,
            value,
            false,
            StringCase::Insensitive,
        )?],
    };

    if alternatives.is_empty() {
        return Err(unsupported_rule(
            path,
            format!("selection {name:?} must not be empty"),
        ));
    }

    Ok(Selection { name, alternatives })
}

fn parse_selection_alternative(
    path: &Path,
    value: noyalib::Value,
) -> Result<SelectionAlternative, SigmaLoadError> {
    match value {
        noyalib::Value::Mapping(entries) => parse_selection_mapping(path, entries),
        value => parse_keyword_alternative(path, value, false, StringCase::Insensitive),
    }
}

fn parse_selection_mapping(
    path: &Path,
    entries: noyalib::Mapping,
) -> Result<SelectionAlternative, SigmaLoadError> {
    let mut predicates = Vec::new();
    let mut keywords = Vec::new();

    for (field, value) in entries {
        let (field, matcher, transforms) = parse_field_key(path, &field)?;

        if field.is_empty() {
            keywords.push(parse_keyword_predicate(path, matcher, value)?);
            continue;
        }

        validate_transform_chain(path, &transforms)?;
        let values = apply_value_transforms(path, parse_sigma_values(path, value)?, &transforms)?;
        validate_field_values(path, matcher, &values)?;
        let regexes = compile_regexes(path, matcher, &values)?;
        let networks = compile_networks(path, matcher, &values)?;
        predicates.push(FieldPredicate {
            field: sigma_field_alias(field).into_owned(),
            matcher,
            values,
            regexes,
            networks,
        });
    }

    Ok(SelectionAlternative {
        predicates,
        keywords,
    })
}

fn parse_keyword_alternative(
    path: &Path,
    value: noyalib::Value,
    require_all: bool,
    case: StringCase,
) -> Result<SelectionAlternative, SigmaLoadError> {
    let values = parse_sigma_values(path, value)?;
    validate_keyword_values(path, &values)?;

    Ok(SelectionAlternative {
        predicates: Vec::new(),
        keywords: vec![KeywordPredicate {
            values,
            require_all,
            case,
        }],
    })
}

fn parse_keyword_predicate(
    path: &Path,
    matcher: FieldMatcher,
    value: noyalib::Value,
) -> Result<KeywordPredicate, SigmaLoadError> {
    let (require_all, case) = match matcher {
        FieldMatcher::Equals { require_all, case }
        | FieldMatcher::Contains { require_all, case } => (require_all, case),
        FieldMatcher::StartsWith { .. }
        | FieldMatcher::EndsWith { .. }
        | FieldMatcher::NotEquals { .. }
        | FieldMatcher::Exists
        | FieldMatcher::LessThan { .. }
        | FieldMatcher::LessThanOrEqual { .. }
        | FieldMatcher::GreaterThan { .. }
        | FieldMatcher::GreaterThanOrEqual { .. }
        | FieldMatcher::Regex { .. }
        | FieldMatcher::Cidr { .. }
        | FieldMatcher::FieldRef { .. }
        | FieldMatcher::TimePart { .. } => {
            return Err(unsupported_rule(
                path,
                "keyword selections only support all, cased, and contains modifiers",
            ));
        }
    };

    let values = parse_sigma_values(path, value)?;
    validate_keyword_values(path, &values)?;

    Ok(KeywordPredicate {
        values,
        require_all,
        case,
    })
}

fn compile_regexes(
    path: &Path,
    matcher: FieldMatcher,
    values: &[SigmaValue],
) -> Result<Vec<Regex>, SigmaLoadError> {
    if !matches!(matcher, FieldMatcher::Regex { .. }) {
        return Ok(Vec::new());
    }

    values
        .iter()
        .map(|value| {
            let SigmaValue::String(pattern) = value else {
                return Err(unsupported_rule(
                    path,
                    "regex modifier requires string values",
                ));
            };

            Regex::new(pattern).map_err(|error| {
                unsupported_rule(path, format!("invalid Sigma regex {pattern:?}: {error}"))
            })
        })
        .collect()
}

fn validate_field_values(
    path: &Path,
    matcher: FieldMatcher,
    values: &[SigmaValue],
) -> Result<(), SigmaLoadError> {
    if !matches!(matcher, FieldMatcher::Equals { .. })
        && values.iter().any(|value| matches!(value, SigmaValue::Null))
    {
        return Err(unsupported_rule(
            path,
            "null Sigma values are only supported with equality matching",
        ));
    }

    match matcher {
        FieldMatcher::Exists => {
            if values
                .iter()
                .all(|value| matches!(value, SigmaValue::Bool(_)))
            {
                Ok(())
            } else {
                Err(unsupported_rule(
                    path,
                    "exists modifier requires boolean values",
                ))
            }
        }
        FieldMatcher::LessThan { .. }
        | FieldMatcher::LessThanOrEqual { .. }
        | FieldMatcher::GreaterThan { .. }
        | FieldMatcher::GreaterThanOrEqual { .. }
        | FieldMatcher::TimePart { .. } => {
            if values
                .iter()
                .all(|value| matches!(value, SigmaValue::Number(_)))
            {
                Ok(())
            } else {
                Err(unsupported_rule(
                    path,
                    "numeric and time modifiers require numeric values",
                ))
            }
        }
        FieldMatcher::FieldRef { .. } => {
            if values
                .iter()
                .all(|value| matches!(value, SigmaValue::String(_)))
            {
                Ok(())
            } else {
                Err(unsupported_rule(
                    path,
                    "fieldref modifier requires string field-name values",
                ))
            }
        }
        FieldMatcher::Equals { .. }
        | FieldMatcher::NotEquals { .. }
        | FieldMatcher::Contains { .. }
        | FieldMatcher::StartsWith { .. }
        | FieldMatcher::EndsWith { .. }
        | FieldMatcher::Regex { .. }
        | FieldMatcher::Cidr { .. } => Ok(()),
    }
}

fn validate_transform_chain(
    path: &Path,
    transforms: &[ValueTransform],
) -> Result<(), SigmaLoadError> {
    if transforms
        .iter()
        .any(|transform| matches!(transform, ValueTransform::RegexFlags { .. }))
        && transforms.len() > 1
    {
        return Err(unsupported_rule(
            path,
            "regex sub-modifiers cannot be combined with value transformation modifiers",
        ));
    }

    Ok(())
}

fn validate_keyword_values(path: &Path, values: &[SigmaValue]) -> Result<(), SigmaLoadError> {
    if values
        .iter()
        .all(|value| matches!(value, SigmaValue::String(_)))
    {
        Ok(())
    } else {
        Err(unsupported_rule(
            path,
            "keyword selections require string values",
        ))
    }
}

fn compile_networks(
    path: &Path,
    matcher: FieldMatcher,
    values: &[SigmaValue],
) -> Result<Vec<IpNetwork>, SigmaLoadError> {
    if !matches!(matcher, FieldMatcher::Cidr { .. }) {
        return Ok(Vec::new());
    }

    values
        .iter()
        .map(|value| {
            let SigmaValue::String(cidr) = value else {
                return Err(unsupported_rule(
                    path,
                    "cidr modifier requires string values",
                ));
            };

            IpNetwork::parse(cidr)
                .map_err(|()| unsupported_rule(path, format!("invalid Sigma CIDR {cidr:?}")))
        })
        .collect()
}

fn parse_field_key<'a>(
    path: &Path,
    field: &'a str,
) -> Result<(&'a str, FieldMatcher, Vec<ValueTransform>), SigmaLoadError> {
    let mut parts = field.split('|');
    let field_name = parts
        .next()
        .ok_or_else(|| unsupported_rule(path, "selection field name is empty"))?;
    let mut state = ModifierState::default();

    for modifier in parts {
        state.apply(path, modifier)?;
    }

    let (matcher, transforms) = state.finish();
    Ok((field_name, matcher, transforms))
}

#[derive(Debug, Default)]
struct ModifierState {
    operation: Option<String>,
    require_all: bool,
    case: StringCase,
    regex_flags: RegexFlags,
    transforms: Vec<ValueTransform>,
    negated: bool,
}

#[derive(Debug, Default)]
struct RegexFlags {
    case_insensitive: bool,
    multi_line: bool,
    dot_matches_new_line: bool,
}

impl ModifierState {
    fn apply(&mut self, path: &Path, modifier: &str) -> Result<(), SigmaLoadError> {
        match modifier {
            "contains" | "startswith" | "endswith" | "exists" | "lt" | "lte" | "gt" | "gte"
            | "re" | "cidr" | "fieldref" | "minute" | "hour" | "day" | "week" | "month"
            | "year" => self.operation = Some(modifier.to_owned()),
            "neq" => {
                self.negated = true;
                if self.operation.as_deref() != Some("fieldref") {
                    self.operation = Some("neq".to_owned());
                }
            }
            "i" => self.regex_flags.case_insensitive = true,
            "m" => self.regex_flags.multi_line = true,
            "s" => self.regex_flags.dot_matches_new_line = true,
            "windash" => self.transforms.push(ValueTransform::Windash),
            "base64" => self.transforms.push(ValueTransform::Base64),
            "base64offset" => self.transforms.push(ValueTransform::Base64Offset),
            "utf16le" | "wide" => self.transforms.push(ValueTransform::Utf16Le),
            "utf16be" => self.transforms.push(ValueTransform::Utf16Be),
            "utf16" => self.transforms.push(ValueTransform::Utf16Bom),
            "expand" => {
                return Err(unsupported_rule(
                    path,
                    "expand modifier requires placeholder configuration, which is not implemented",
                ));
            }
            "all" => self.require_all = true,
            "cased" => self.case = StringCase::Sensitive,
            other => {
                return Err(unsupported_rule(
                    path,
                    format!("unsupported Sigma modifier {other:?}"),
                ));
            }
        }

        Ok(())
    }

    fn finish(mut self) -> (FieldMatcher, Vec<ValueTransform>) {
        let matcher = match self.operation.as_deref() {
            Some("contains") => FieldMatcher::Contains {
                require_all: self.require_all,
                case: self.case,
            },
            Some("startswith") => FieldMatcher::StartsWith {
                require_all: self.require_all,
                case: self.case,
            },
            Some("endswith") => FieldMatcher::EndsWith {
                require_all: self.require_all,
                case: self.case,
            },
            Some("exists") => FieldMatcher::Exists,
            Some("neq") => FieldMatcher::NotEquals {
                require_all: self.require_all,
                case: self.case,
            },
            Some("lt") => FieldMatcher::LessThan {
                require_all: self.require_all,
            },
            Some("lte") => FieldMatcher::LessThanOrEqual {
                require_all: self.require_all,
            },
            Some("gt") => FieldMatcher::GreaterThan {
                require_all: self.require_all,
            },
            Some("gte") => FieldMatcher::GreaterThanOrEqual {
                require_all: self.require_all,
            },
            Some("re") => {
                self.transforms.push(ValueTransform::RegexFlags {
                    case_insensitive: self.regex_flags.case_insensitive,
                    multi_line: self.regex_flags.multi_line,
                    dot_matches_new_line: self.regex_flags.dot_matches_new_line,
                });
                FieldMatcher::Regex {
                    require_all: self.require_all,
                }
            }
            Some("cidr") => FieldMatcher::Cidr {
                require_all: self.require_all,
            },
            Some("fieldref") => FieldMatcher::FieldRef {
                require_all: self.require_all,
                negated: self.negated,
            },
            Some("minute") => self.time_matcher(TimePart::Minute),
            Some("hour") => self.time_matcher(TimePart::Hour),
            Some("day") => self.time_matcher(TimePart::Day),
            Some("week") => self.time_matcher(TimePart::Week),
            Some("month") => self.time_matcher(TimePart::Month),
            Some("year") => self.time_matcher(TimePart::Year),
            Some(_) => unreachable!("operation is constrained by modifier parsing"),
            None => FieldMatcher::Equals {
                require_all: self.require_all,
                case: self.case,
            },
        };

        (matcher, self.transforms)
    }

    fn time_matcher(&self, part: TimePart) -> FieldMatcher {
        FieldMatcher::TimePart {
            part,
            require_all: self.require_all,
        }
    }
}

fn parse_sigma_values(
    path: &Path,
    value: noyalib::Value,
) -> Result<Vec<SigmaValue>, SigmaLoadError> {
    match value {
        noyalib::Value::Sequence(values) => values
            .into_iter()
            .map(|value| parse_sigma_value(path, value))
            .collect(),
        value => parse_sigma_value(path, value).map(|value| vec![value]),
    }
}

fn parse_sigma_value(path: &Path, value: noyalib::Value) -> Result<SigmaValue, SigmaLoadError> {
    match value {
        noyalib::Value::String(value) => Ok(SigmaValue::String(value)),
        noyalib::Value::Bool(value) => Ok(SigmaValue::Bool(value)),
        noyalib::Value::Null => Ok(SigmaValue::Null),
        noyalib::Value::Number(value) => {
            let number = noyalib::Value::Number(value);
            let json_value = noyalib::from_value::<JsonValue>(&number).map_err(|source| {
                SigmaLoadError::RuleParse {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            json_value.as_u64().map(SigmaValue::Number).ok_or_else(|| {
                unsupported_rule(path, "only unsigned numeric Sigma values are supported")
            })
        }
        other => Err(unsupported_rule(
            path,
            format!("unsupported Sigma detection value {other:?}"),
        )),
    }
}

fn apply_value_transforms(
    path: &Path,
    values: Vec<SigmaValue>,
    transforms: &[ValueTransform],
) -> Result<Vec<SigmaValue>, SigmaLoadError> {
    transforms.iter().try_fold(values, |values, transform| {
        apply_value_transform(path, values, *transform)
    })
}

fn apply_value_transform(
    path: &Path,
    values: Vec<SigmaValue>,
    transform: ValueTransform,
) -> Result<Vec<SigmaValue>, SigmaLoadError> {
    values
        .into_iter()
        .map(|value| apply_single_value_transform(path, value, transform))
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_iter)
        .map(Iterator::flatten)
        .map(Iterator::collect)
}

fn apply_single_value_transform(
    path: &Path,
    value: SigmaValue,
    transform: ValueTransform,
) -> Result<Vec<SigmaValue>, SigmaLoadError> {
    let SigmaValue::String(value) = value else {
        return Err(unsupported_rule(
            path,
            "Sigma value transformation modifiers require string values",
        ));
    };

    match transform {
        ValueTransform::Windash => Ok(windash_variants(&value)
            .into_iter()
            .map(SigmaValue::String)
            .collect()),
        ValueTransform::Base64 => Ok(vec![SigmaValue::String(base64_encode(value.as_bytes()))]),
        ValueTransform::Base64Offset => Ok(base64_offset_variants(value.as_bytes())
            .into_iter()
            .map(SigmaValue::String)
            .collect()),
        ValueTransform::Utf16Le => Ok(vec![SigmaValue::String(bytes_to_hex(&utf16_bytes(
            &value,
            Utf16ByteOrder::Little,
            false,
        )))]),
        ValueTransform::Utf16Be => Ok(vec![SigmaValue::String(bytes_to_hex(&utf16_bytes(
            &value,
            Utf16ByteOrder::Big,
            false,
        )))]),
        ValueTransform::Utf16Bom => Ok(vec![SigmaValue::String(bytes_to_hex(&utf16_bytes(
            &value,
            Utf16ByteOrder::Little,
            true,
        )))]),
        ValueTransform::RegexFlags {
            case_insensitive,
            multi_line,
            dot_matches_new_line,
        } => Ok(vec![SigmaValue::String(regex_with_flags(
            &value,
            case_insensitive,
            multi_line,
            dot_matches_new_line,
        ))]),
    }
}

fn parse_condition_value(
    path: &Path,
    value: noyalib::Value,
) -> Result<Vec<String>, SigmaLoadError> {
    match value {
        noyalib::Value::String(value) => Ok(vec![value]),
        noyalib::Value::Sequence(values) => values
            .into_iter()
            .map(|value| match value {
                noyalib::Value::String(value) => Ok(value),
                other => Err(unsupported_rule(
                    path,
                    format!("condition list values must be strings, found {other:?}"),
                )),
            })
            .collect(),
        other => Err(unsupported_rule(
            path,
            format!("condition must be a string or list of strings, found {other:?}"),
        )),
    }
}

fn combine_condition_exprs(expressions: Vec<ConditionExpr>) -> Option<ConditionExpr> {
    expressions
        .into_iter()
        .reduce(|left, right| ConditionExpr::Or(Box::new(left), Box::new(right)))
}

fn sigma_field_alias(field: &str) -> Cow<'_, str> {
    match field {
        "EventID" => Cow::Borrowed("event.id"),
        "Channel" => Cow::Borrowed("channel"),
        "Provider_Name" | "ProviderName" => Cow::Borrowed("provider"),
        "Computer" => Cow::Borrowed("computer"),
        _ if field.contains('.') => Cow::Borrowed(field),
        _ => Cow::Owned(format!("Event.EventData.{field}")),
    }
}

fn match_values(
    field: FieldValue<'_>,
    expected: &[SigmaValue],
    require_all: bool,
    case: StringCase,
    predicate: fn(FieldValue<'_>, &SigmaValue, StringCase) -> bool,
) -> bool {
    if require_all {
        expected
            .iter()
            .all(|expected| predicate(field, expected, case))
    } else {
        expected
            .iter()
            .any(|expected| predicate(field, expected, case))
    }
}

fn matcher_require_all(matcher: FieldMatcher) -> bool {
    match matcher {
        FieldMatcher::Equals { require_all, .. }
        | FieldMatcher::NotEquals { require_all, .. }
        | FieldMatcher::Contains { require_all, .. }
        | FieldMatcher::StartsWith { require_all, .. }
        | FieldMatcher::EndsWith { require_all, .. }
        | FieldMatcher::LessThan { require_all }
        | FieldMatcher::LessThanOrEqual { require_all }
        | FieldMatcher::GreaterThan { require_all }
        | FieldMatcher::GreaterThanOrEqual { require_all }
        | FieldMatcher::Regex { require_all }
        | FieldMatcher::Cidr { require_all }
        | FieldMatcher::FieldRef { require_all, .. }
        | FieldMatcher::TimePart { require_all, .. } => require_all,
        FieldMatcher::Exists => false,
    }
}

fn match_values_missing_field(expected: &[SigmaValue], require_all: bool) -> bool {
    match_null_values(true, expected, require_all)
}

fn match_values_present_field_null(
    field: FieldValue<'_>,
    expected: &[SigmaValue],
    require_all: bool,
) -> bool {
    match_null_values(is_null_field(field), expected, require_all)
}

fn match_null_values(field_is_null: bool, expected: &[SigmaValue], require_all: bool) -> bool {
    if require_all {
        expected
            .iter()
            .all(|expected| matches!(expected, SigmaValue::Null) && field_is_null)
    } else {
        expected
            .iter()
            .any(|expected| matches!(expected, SigmaValue::Null) && field_is_null)
    }
}

fn is_null_field(field: FieldValue<'_>) -> bool {
    matches!(field, FieldValue::Json(serde_json::Value::Null))
}

fn matches_exists(field: Option<FieldValue<'_>>, expected: &[SigmaValue]) -> bool {
    expected.iter().any(|expected| {
        matches!(
            expected,
            SigmaValue::Bool(expected_exists) if field.is_some() == *expected_exists
        )
    })
}

fn equals_value(field: FieldValue<'_>, expected: &SigmaValue, case: StringCase) -> bool {
    match expected {
        SigmaValue::String(value) => field
            .as_text()
            .is_some_and(|text| equals_text(&text, value, case)),
        SigmaValue::Number(value) => field.as_u64() == Some(*value),
        SigmaValue::Bool(value) => {
            matches!(field, FieldValue::Bool(field_value) if field_value == *value)
        }
        SigmaValue::Null => is_null_field(field),
    }
}

fn not_equals_value(field: FieldValue<'_>, expected: &SigmaValue, case: StringCase) -> bool {
    !equals_value(field, expected, case)
}

fn match_ordered_values(
    field: FieldValue<'_>,
    expected: &[SigmaValue],
    require_all: bool,
    predicate: fn(u64, u64) -> bool,
) -> bool {
    let Some(field_value) = field.as_u64() else {
        return false;
    };

    if require_all {
        expected.iter().all(|expected| {
            matches!(expected, SigmaValue::Number(expected) if predicate(field_value, *expected))
        })
    } else {
        expected.iter().any(|expected| {
            matches!(expected, SigmaValue::Number(expected) if predicate(field_value, *expected))
        })
    }
}

fn match_field_refs(
    event: &Event,
    field: FieldValue<'_>,
    expected: &[SigmaValue],
    require_all: bool,
    negated: bool,
) -> bool {
    let predicate = |expected: &SigmaValue| {
        let SigmaValue::String(reference) = expected else {
            return false;
        };
        let Some(reference_value) = event.field(&sigma_field_alias(reference)) else {
            return false;
        };
        let matches = field_values_equal(field, reference_value);

        if negated { !matches } else { matches }
    };

    if require_all {
        expected.iter().all(predicate)
    } else {
        expected.iter().any(predicate)
    }
}

fn field_values_equal(left: FieldValue<'_>, right: FieldValue<'_>) -> bool {
    if let (Some(left), Some(right)) = (left.as_u64(), right.as_u64()) {
        return left == right;
    }

    match (left.as_text(), right.as_text()) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(&right),
        _ => false,
    }
}

fn match_time_parts(
    field: FieldValue<'_>,
    expected: &[SigmaValue],
    part: TimePart,
    require_all: bool,
) -> bool {
    let Some(value) = field
        .as_text()
        .and_then(|text| extract_time_part(&text, part))
    else {
        return false;
    };

    if require_all {
        expected
            .iter()
            .all(|expected| matches!(expected, SigmaValue::Number(expected) if value == *expected))
    } else {
        expected
            .iter()
            .any(|expected| matches!(expected, SigmaValue::Number(expected) if value == *expected))
    }
}

fn extract_time_part(value: &str, part: TimePart) -> Option<u64> {
    let normalized;
    let value = if value.ends_with('Z') || value.contains('+') {
        value
    } else {
        normalized = format!("{value}Z");
        &normalized
    };
    let datetime = OffsetDateTime::parse(value, &Rfc3339).ok()?;

    Some(match part {
        TimePart::Minute => u64::from(datetime.minute()),
        TimePart::Hour => u64::from(datetime.hour()),
        TimePart::Day => u64::from(datetime.day()),
        TimePart::Week => u64::from(datetime.iso_week()),
        TimePart::Month => datetime.month() as u64,
        TimePart::Year => u64::try_from(datetime.year()).ok()?,
    })
}

fn contains_value(field: FieldValue<'_>, expected: &SigmaValue, case: StringCase) -> bool {
    string_match(field, expected, case, contains_text)
}

fn starts_with_value(field: FieldValue<'_>, expected: &SigmaValue, case: StringCase) -> bool {
    string_match(field, expected, case, starts_with_text)
}

fn ends_with_value(field: FieldValue<'_>, expected: &SigmaValue, case: StringCase) -> bool {
    string_match(field, expected, case, ends_with_text)
}

fn match_compiled_regexes(field: FieldValue<'_>, regexes: &[Regex], require_all: bool) -> bool {
    let Some(text) = field.as_text() else {
        return false;
    };

    if require_all {
        regexes.iter().all(|regex| regex.is_match(&text))
    } else {
        regexes.iter().any(|regex| regex.is_match(&text))
    }
}

fn match_compiled_networks(
    field: FieldValue<'_>,
    networks: &[IpNetwork],
    require_all: bool,
) -> bool {
    let Some(address) = field
        .as_text()
        .and_then(|value| value.parse::<IpAddr>().ok())
    else {
        return false;
    };

    if require_all {
        networks.iter().all(|network| network.contains(address))
    } else {
        networks.iter().any(|network| network.contains(address))
    }
}

fn string_match(
    field: FieldValue<'_>,
    expected: &SigmaValue,
    case: StringCase,
    predicate: fn(&str, &str, StringCase) -> bool,
) -> bool {
    let SigmaValue::String(expected) = expected else {
        return false;
    };

    field
        .as_text()
        .is_some_and(|text| predicate(&text, expected, case))
}

fn keyword_value_matches(event_text: &str, value: &SigmaValue, case: StringCase) -> bool {
    let SigmaValue::String(value) = value else {
        return false;
    };

    contains_text(event_text, value, case)
}

fn equals_text(field: &str, expected: &str, case: StringCase) -> bool {
    if contains_wildcard(expected) {
        return wildcard_text_matches(field, expected, case);
    }

    match case {
        StringCase::Insensitive => field.eq_ignore_ascii_case(expected),
        StringCase::Sensitive => field == expected,
    }
}

fn contains_text(field: &str, expected: &str, case: StringCase) -> bool {
    match case {
        StringCase::Insensitive => field
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase()),
        StringCase::Sensitive => field.contains(expected),
    }
}

fn starts_with_text(field: &str, expected: &str, case: StringCase) -> bool {
    match case {
        StringCase::Insensitive => field
            .to_ascii_lowercase()
            .starts_with(&expected.to_ascii_lowercase()),
        StringCase::Sensitive => field.starts_with(expected),
    }
}

fn ends_with_text(field: &str, expected: &str, case: StringCase) -> bool {
    match case {
        StringCase::Insensitive => field
            .to_ascii_lowercase()
            .ends_with(&expected.to_ascii_lowercase()),
        StringCase::Sensitive => field.ends_with(expected),
    }
}

fn contains_wildcard(value: &str) -> bool {
    value.contains('*') || value.contains('?')
}

fn wildcard_text_matches(field: &str, pattern: &str, case: StringCase) -> bool {
    let field = match case {
        StringCase::Insensitive => field.to_ascii_lowercase(),
        StringCase::Sensitive => field.to_owned(),
    };
    let pattern = match case {
        StringCase::Insensitive => pattern.to_ascii_lowercase(),
        StringCase::Sensitive => pattern.to_owned(),
    };

    wildcard_chars_match(
        &field.chars().collect::<Vec<_>>(),
        &pattern.chars().collect::<Vec<_>>(),
    )
}

fn wildcard_chars_match(field: &[char], pattern: &[char]) -> bool {
    let mut field_index = 0usize;
    let mut pattern_index = 0usize;
    let mut star_index = None;
    let mut retry_field_index = 0usize;

    while field_index < field.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == field[field_index])
        {
            field_index += 1;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_index = Some(pattern_index);
            retry_field_index = field_index;
            pattern_index += 1;
        } else if let Some(star_index) = star_index {
            pattern_index = star_index + 1;
            retry_field_index += 1;
            field_index = retry_field_index;
        } else {
            return false;
        }
    }

    pattern[pattern_index..]
        .iter()
        .all(|character| *character == '*')
}

fn windash_variants(value: &str) -> Vec<String> {
    const DASHES: [char; 5] = ['-', '/', '–', '—', '―'];

    let mut variants = vec![String::new()];

    for character in value.chars() {
        if DASHES.contains(&character) {
            variants = variants
                .into_iter()
                .flat_map(|prefix| {
                    DASHES.into_iter().map(move |dash| {
                        let mut variant = prefix.clone();
                        variant.push(dash);
                        variant
                    })
                })
                .collect();
        } else {
            for variant in &mut variants {
                variant.push(character);
            }
        }
    }

    variants.sort();
    variants.dedup();
    variants
}

fn base64_offset_variants(value: &[u8]) -> Vec<String> {
    (0..=2)
        .map(|offset| {
            let mut bytes = vec![0u8; offset];
            bytes.extend_from_slice(value);
            base64_encode(&bytes)
        })
        .collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();

    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let combined = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);

        output.push(ALPHABET[((combined >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((combined >> 12) & 0x3f) as usize] as char);

        if chunk.len() > 1 {
            output.push(ALPHABET[((combined >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[(combined & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

#[derive(Debug, Clone, Copy)]
enum Utf16ByteOrder {
    Little,
    Big,
}

fn utf16_bytes(value: &str, byte_order: Utf16ByteOrder, bom: bool) -> Vec<u8> {
    let mut bytes = Vec::new();

    if bom {
        bytes.extend_from_slice(&[0xff, 0xfe]);
    }

    for unit in value.encode_utf16() {
        let unit_bytes = match byte_order {
            Utf16ByteOrder::Little => unit.to_le_bytes(),
            Utf16ByteOrder::Big => unit.to_be_bytes(),
        };
        bytes.extend_from_slice(&unit_bytes);
    }

    bytes
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }

    output
}

fn regex_with_flags(
    pattern: &str,
    case_insensitive: bool,
    multi_line: bool,
    dot_matches_new_line: bool,
) -> String {
    let flags = [
        (case_insensitive, 'i'),
        (multi_line, 'm'),
        (dot_matches_new_line, 's'),
    ]
    .into_iter()
    .filter_map(|(enabled, flag)| enabled.then_some(flag))
    .collect::<String>();

    if flags.is_empty() {
        pattern.to_owned()
    } else {
        format!("(?{flags}){pattern}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    fn parse(value: &str) -> Result<Self, ()> {
        let Some((address, prefix)) = value.split_once('/') else {
            return Err(());
        };
        let address = address.parse::<IpAddr>().map_err(|_| ())?;
        let prefix = prefix.parse::<u8>().map_err(|_| ())?;

        match address {
            IpAddr::V4(address) => {
                if prefix > 32 {
                    return Err(());
                }

                let mask = prefix_mask_u32(prefix);
                Ok(Self::V4 {
                    network: u32::from(address) & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) => {
                if prefix > 128 {
                    return Err(());
                }

                let mask = prefix_mask_u128(prefix);
                Ok(Self::V6 {
                    network: u128::from(address) & mask,
                    prefix,
                })
            }
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                u32::from(address) & prefix_mask_u32(prefix) == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                u128::from(address) & prefix_mask_u128(prefix) == network
            }
            (Self::V4 { .. } | Self::V6 { .. }, IpAddr::V4(_) | IpAddr::V6(_)) => false,
        }
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn unsupported_rule(path: &Path, message: impl Into<String>) -> SigmaLoadError {
    SigmaLoadError::UnsupportedRule {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

fn parse_condition(path: &Path, condition: &str) -> Result<ConditionExpr, SigmaLoadError> {
    let tokens = tokenize_condition(condition);

    if tokens.is_empty() {
        return Err(unsupported_rule(path, "condition is empty"));
    }

    let mut parser = ConditionParser {
        tokens,
        position: 0,
    };
    let expression = parser.parse_or(path)?;

    if parser.position != parser.tokens.len() {
        return Err(unsupported_rule(
            path,
            format!("unexpected condition token {:?}", parser.peek_label()),
        ));
    }

    Ok(expression)
}

fn validate_condition_selections(
    path: &Path,
    condition: &ConditionExpr,
    selections: &[Selection],
) -> Result<(), SigmaLoadError> {
    match condition {
        ConditionExpr::Selection(name) => {
            if selections.iter().any(|selection| selection.name == *name) {
                Ok(())
            } else {
                Err(unsupported_rule(
                    path,
                    format!("condition references unknown selection {name:?}"),
                ))
            }
        }
        ConditionExpr::OneOf(pattern) | ConditionExpr::AllOf(pattern) => {
            if matching_selections(pattern, selections).is_empty() {
                Err(unsupported_rule(
                    path,
                    format!("condition pattern {pattern:?} does not match any selections"),
                ))
            } else {
                Ok(())
            }
        }
        ConditionExpr::Not(expression) => {
            validate_condition_selections(path, expression, selections)
        }
        ConditionExpr::And(left, right) | ConditionExpr::Or(left, right) => {
            validate_condition_selections(path, left, selections)?;
            validate_condition_selections(path, right, selections)
        }
    }
}

#[derive(Debug)]
struct ConditionParser {
    tokens: Vec<ConditionToken>,
    position: usize,
}

impl ConditionParser {
    fn parse_or(&mut self, path: &Path) -> Result<ConditionExpr, SigmaLoadError> {
        let mut expression = self.parse_and(path)?;

        while self.consume_keyword("or") {
            let right = self.parse_and(path)?;
            expression = ConditionExpr::Or(Box::new(expression), Box::new(right));
        }

        Ok(expression)
    }

    fn parse_and(&mut self, path: &Path) -> Result<ConditionExpr, SigmaLoadError> {
        let mut expression = self.parse_not(path)?;

        while self.consume_keyword("and") {
            let right = self.parse_not(path)?;
            expression = ConditionExpr::And(Box::new(expression), Box::new(right));
        }

        Ok(expression)
    }

    fn parse_not(&mut self, path: &Path) -> Result<ConditionExpr, SigmaLoadError> {
        if self.consume_keyword("not") {
            return Ok(ConditionExpr::Not(Box::new(self.parse_not(path)?)));
        }

        self.parse_primary(path)
    }

    fn parse_primary(&mut self, path: &Path) -> Result<ConditionExpr, SigmaLoadError> {
        if self.consume_symbol(ConditionSymbol::LeftParen) {
            let expression = self.parse_or(path)?;

            if self.consume_symbol(ConditionSymbol::RightParen) {
                return Ok(expression);
            }

            return Err(unsupported_rule(path, "condition is missing ')'"));
        }

        match self.next() {
            Some(ConditionToken::Ident(quantifier))
                if quantifier == "1" || quantifier.eq_ignore_ascii_case("all") =>
            {
                self.expect_keyword(path, "of")?;
                let pattern = self.expect_ident(path, "selection pattern")?;

                if quantifier == "1" {
                    Ok(ConditionExpr::OneOf(pattern))
                } else {
                    Ok(ConditionExpr::AllOf(pattern))
                }
            }
            Some(ConditionToken::Ident(name)) => Ok(ConditionExpr::Selection(name)),
            other => Err(unsupported_rule(
                path,
                format!(
                    "expected condition selection, found {}",
                    condition_token_label(other.as_ref())
                ),
            )),
        }
    }

    fn expect_keyword(&mut self, path: &Path, keyword: &str) -> Result<(), SigmaLoadError> {
        match self.next() {
            Some(ConditionToken::Ident(value)) if value.eq_ignore_ascii_case(keyword) => Ok(()),
            other => Err(unsupported_rule(
                path,
                format!(
                    "expected condition keyword {keyword:?}, found {}",
                    condition_token_label(other.as_ref())
                ),
            )),
        }
    }

    fn expect_ident(&mut self, path: &Path, expected: &str) -> Result<String, SigmaLoadError> {
        match self.next() {
            Some(ConditionToken::Ident(value)) => Ok(value),
            other => Err(unsupported_rule(
                path,
                format!(
                    "expected {expected}, found {}",
                    condition_token_label(other.as_ref())
                ),
            )),
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        if self.peek().is_some_and(
            |token| matches!(token, ConditionToken::Ident(value) if value.eq_ignore_ascii_case(keyword)),
        ) {
            self.position += 1;
            return true;
        }

        false
    }

    fn consume_symbol(&mut self, symbol: ConditionSymbol) -> bool {
        if self
            .peek()
            .is_some_and(|token| matches!(token, ConditionToken::Symbol(value) if *value == symbol))
        {
            self.position += 1;
            return true;
        }

        false
    }

    fn next(&mut self) -> Option<ConditionToken> {
        let token = self.tokens.get(self.position).cloned();

        if token.is_some() {
            self.position += 1;
        }

        token
    }

    fn peek(&self) -> Option<&ConditionToken> {
        self.tokens.get(self.position)
    }

    fn peek_label(&self) -> String {
        condition_token_label(self.peek())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConditionToken {
    Ident(String),
    Symbol(ConditionSymbol),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionSymbol {
    LeftParen,
    RightParen,
}

fn tokenize_condition(condition: &str) -> Vec<ConditionToken> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for character in condition.chars() {
        match character {
            ' ' | '\t' | '\n' | '\r' => push_condition_ident(&mut tokens, &mut current),
            '(' => {
                push_condition_ident(&mut tokens, &mut current);
                tokens.push(ConditionToken::Symbol(ConditionSymbol::LeftParen));
            }
            ')' => {
                push_condition_ident(&mut tokens, &mut current);
                tokens.push(ConditionToken::Symbol(ConditionSymbol::RightParen));
            }
            _ => current.push(character),
        }
    }

    push_condition_ident(&mut tokens, &mut current);
    tokens
}

fn push_condition_ident(tokens: &mut Vec<ConditionToken>, current: &mut String) {
    if current.is_empty() {
        return;
    }

    tokens.push(ConditionToken::Ident(std::mem::take(current)));
}

fn condition_token_label(token: Option<&ConditionToken>) -> String {
    match token {
        Some(ConditionToken::Ident(value)) => value.clone(),
        Some(ConditionToken::Symbol(symbol)) => format!("{symbol:?}"),
        None => "end of condition".to_owned(),
    }
}

fn is_correlation_rule(rule: &RawSigmaRule) -> bool {
    rule.correlation.is_some()
        || rule
            .rule_type
            .as_deref()
            .is_some_and(|rule_type| rule_type.eq_ignore_ascii_case("correlation"))
}

fn is_yaml_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::input::DiscoveredInput;

    use super::*;

    #[test]
    fn loads_regular_rules_and_correlation_documents() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        fs::write(
            fixture.path().join("process_creation.yml"),
            r"
title: Suspicious Process
name: suspicious_process
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
tags:
  - attack.execution
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
",
        )
        .expect("regular rule should be written");
        fs::write(
            fixture.path().join("correlation.yml"),
            r"
---
title: Many Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - suspicious_process
  condition:
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation rule should be written");
        fs::write(fixture.path().join("ignored.txt"), "not yaml")
            .expect("ignored file should be written");

        let report = load_sigma_rules(&[fixture.path().to_path_buf()])
            .expect("rules should load from directory");

        assert_eq!(report.rules.len(), 1);
        assert_eq!(report.rules[0].title, "Suspicious Process");
        assert_eq!(report.rules[0].level.as_deref(), Some("high"));
        assert_eq!(report.rules[0].tags, ["attack.execution"]);
        assert_eq!(report.correlations.len(), 1);
        assert_eq!(report.correlations[0].title, "Many Failed Logons");
        assert_eq!(
            report.correlations[0].correlation.kind,
            CorrelationKind::EventCount
        );
        assert_eq!(
            report.correlations[0].correlation.referenced_rules,
            ["suspicious_process"]
        );
        assert_eq!(
            report.correlations[0].correlation.timespan,
            Duration::minutes(5)
        );
        assert_eq!(
            report.correlations[0].correlation.condition,
            Some(CountCondition {
                operator: CountOperator::GreaterThanOrEqual,
                threshold: 2
            })
        );
        assert!(report.correlations[0].correlation.value_fields.is_empty());
    }

    #[test]
    fn loads_sigma_syntax_valid_fixtures() {
        let path = PathBuf::from("tests/fixtures/sigma-syntax/valid");
        let report = load_sigma_rules(&[path]).expect("valid Sigma syntax fixtures should load");

        assert_eq!(
            report.rules.len(),
            5,
            "valid syntax fixtures should include base Sigma rules"
        );
        assert_eq!(
            report.correlations.len(),
            4,
            "valid syntax fixtures should include correlation rules"
        );
        assert!(
            report
                .rules
                .iter()
                .any(|rule| rule.name.as_deref() == Some("syntax_base_modifiers")),
            "valid fixtures should load modifier-heavy base rule"
        );
        assert!(
            report
                .rules
                .iter()
                .any(|rule| rule.name.as_deref() == Some("syntax_alternatives_keywords")),
            "valid fixtures should load alternatives and keyword base rule"
        );
        assert!(
            report
                .correlations
                .iter()
                .any(|rule| rule.correlation.kind == CorrelationKind::EventCount),
            "valid fixtures should include event_count correlation"
        );
        assert!(
            report
                .correlations
                .iter()
                .any(|rule| rule.correlation.kind == CorrelationKind::ValueCount),
            "valid fixtures should include value_count correlation"
        );
        assert!(
            report
                .correlations
                .iter()
                .any(|rule| rule.correlation.kind == CorrelationKind::Temporal),
            "valid fixtures should include temporal correlation"
        );
        assert!(
            report
                .correlations
                .iter()
                .any(|rule| rule.correlation.kind == CorrelationKind::TemporalOrdered),
            "valid fixtures should include temporal_ordered correlation"
        );
    }

    #[test]
    fn rejects_sigma_syntax_invalid_fixtures_with_readable_errors() {
        let cases = [
            ("base_missing_condition.yml", "missing detection condition"),
            ("base_unknown_selection.yml", "unknown selection"),
            (
                "base_unsupported_modifier_typo.yml",
                "unsupported Sigma modifier",
            ),
            (
                "base_bad_condition_pattern.yml",
                "does not match any selections",
            ),
            ("correlation_missing_rules.yml", "non-empty rules list"),
            (
                "correlation_bad_type_typo.yml",
                "unsupported correlation type",
            ),
            (
                "correlation_value_count_missing_field.yml",
                "condition field",
            ),
            (
                "correlation_bad_timespan.yml",
                "invalid correlation timespan",
            ),
            (
                "correlation_bad_condition_operator.yml",
                "unsupported correlation condition key",
            ),
        ];

        for (fixture, expected) in cases {
            let path = PathBuf::from("tests/fixtures/sigma-syntax/invalid").join(fixture);
            let error = load_sigma_rules(std::slice::from_ref(&path))
                .expect_err("invalid Sigma syntax fixture should fail");
            let message = error.to_string();

            assert!(
                matches!(error, SigmaLoadError::UnsupportedRule { .. }),
                "{fixture} should fail as an unsupported Sigma rule, got {error:?}"
            );
            assert!(
                message.contains(expected),
                "{fixture} should mention {expected:?}, got {message:?}"
            );
        }

        let malformed_path =
            PathBuf::from("tests/fixtures/sigma-syntax/invalid/base_malformed_yaml.yml");
        let malformed_error = load_sigma_rules(&[malformed_path])
            .expect_err("malformed Sigma YAML fixture should fail");

        assert!(
            matches!(malformed_error, SigmaLoadError::RuleParse { .. }),
            "malformed YAML should fail during YAML parsing, got {malformed_error:?}"
        );
    }

    #[test]
    fn non_strict_loader_skips_invalid_rule_files_and_continues() {
        let path = PathBuf::from("tests/fixtures/sigma-syntax");
        let report =
            load_sigma_rules_non_strict(&[path]).expect("non-strict loading should skip bad rules");

        assert_eq!(
            report.rules.len(),
            5,
            "non-strict loading should keep valid base rules"
        );
        assert_eq!(
            report.correlations.len(),
            4,
            "non-strict loading should keep valid correlation rules"
        );
        assert_eq!(
            report.skipped_rules, 10,
            "non-strict loading should count invalid YAML rule files"
        );
    }

    #[test]
    fn temporal_ordered_correlation_emits_when_references_match_in_order() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("ordered_sequence.yml");
        fs::write(
            &path,
            r"
---
title: Process Start
name: process_start
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Process Network
name: process_network
detection:
  selection:
    EventID: 3
  condition: selection
---
title: Process File Write
name: process_file_write
detection:
  selection:
    EventID: 11
  condition: selection
---
title: Process Network Then File Sequence
type: correlation
correlation:
  type: temporal_ordered
  rules:
    - process_start
    - process_network
    - process_file_write
  group-by:
    - ProcessGuid
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
        let start = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));
        let network = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 3,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));
        let file_write = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 11,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:02:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &start, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[1], &network, &[])
                .is_empty()
        );

        let matches = engine.observe_match(&report.rules[2], &file_write, &[]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule.title, "Process Network Then File Sequence");
        assert_eq!(matches[0].matches.len(), 3);
        assert_eq!(matches[0].window_start, "2026-06-28T12:00:00Z");
        assert_eq!(matches[0].window_end, "2026-06-28T12:02:00Z");
    }

    #[test]
    fn temporal_ordered_correlation_rejects_out_of_order_references() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("ordered_sequence.yml");
        fs::write(
            &path,
            r"
---
title: First Event
name: first_event
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Second Event
name: second_event
detection:
  selection:
    EventID: 3
  condition: selection
---
title: Ordered Sequence
type: correlation
correlation:
  type: temporal_ordered
  rules:
    - first_event
    - second_event
  group-by:
    - ProcessGuid
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
        let second = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 3,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));
        let first = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[1], &second, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[0], &first, &[])
                .is_empty()
        );
    }

    #[test]
    fn temporal_correlation_matches_references_in_any_order() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("unordered_sequence.yml");
        fs::write(
            &path,
            r"
---
title: First Event
name: first_event
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Second Event
name: second_event
detection:
  selection:
    EventID: 3
  condition: selection
---
title: Unordered Sequence
type: correlation
correlation:
  type: temporal
  rules:
    - first_event
    - second_event
  group-by:
    - ProcessGuid
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
        let second = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 3,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));
        let first = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[1], &second, &[])
                .is_empty()
        );

        let matches = engine.observe_match(&report.rules[0], &first, &[]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule.title, "Unordered Sequence");
    }

    #[test]
    fn correlation_max_state_evicts_oldest_state_group() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("state_limit.yml");
        fs::write(
            &path,
            r"
---
title: Process Start
name: process_start
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Repeated Process Starts
type: correlation
correlation:
  type: event_count
  rules:
    - process_start
  group-by:
    - ProcessGuid
  condition:
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 1);
        let first_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));
        let second_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
                },
                "EventData": { "ProcessGuid": "{22222222-2222-2222-2222-222222222222}" }
            }
        }));
        let first_group_again = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:02:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &first_group, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[0], &second_group, &[])
                .is_empty()
        );
        assert_eq!(
            engine.stats(),
            SigmaCorrelationStats {
                state_entries: 1,
                evicted_state_entries: 1
            }
        );

        let matches = engine.observe_match(&report.rules[0], &first_group_again, &[]);

        assert!(
            matches.is_empty(),
            "oldest group should be evicted before it can reach threshold"
        );
        assert_eq!(
            engine.stats(),
            SigmaCorrelationStats {
                state_entries: 1,
                evicted_state_entries: 2
            }
        );
    }

    #[test]
    fn host_scoped_correlation_does_not_mix_hosts() {
        let report = repeated_process_correlation_report();
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
        let first_host = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));
        let second_host = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-02",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &first_host, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[0], &second_host, &[])
                .is_empty(),
            "host scope must not correlate matching group-by values across computers"
        );
        assert_eq!(
            engine.stats(),
            SigmaCorrelationStats {
                state_entries: 2,
                evicted_state_entries: 0
            }
        );
    }

    #[test]
    fn global_scoped_correlation_can_match_across_hosts() {
        let report = repeated_process_correlation_report();
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Global, 100);
        let first_host = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));
        let second_host = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Computer": "WIN-02",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
                },
                "EventData": { "ProcessGuid": "{11111111-1111-1111-1111-111111111111}" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &first_host, &[])
                .is_empty()
        );

        let matches = engine.observe_match(&report.rules[0], &second_host, &[]);

        assert_eq!(
            matches.len(),
            1,
            "global scope should allow cross-host correlation when group-by fields match"
        );
        assert_eq!(
            matches[0].group,
            [(
                "ProcessGuid".to_owned(),
                "{11111111-1111-1111-1111-111111111111}".to_owned()
            )]
        );
    }

    #[test]
    fn reports_invalid_yaml_with_rule_path() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("broken.yml");
        fs::write(&path, "title: [").expect("broken rule should be written");

        let error =
            load_sigma_rules(std::slice::from_ref(&path)).expect_err("invalid YAML should fail");

        assert!(
            matches!(error, SigmaLoadError::RuleParse { path: error_path, .. } if error_path == path),
            "invalid YAML should report the rule path"
        );
    }

    #[test]
    fn evaluates_simple_selection_against_event() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("failed_logon.yml");
        fs::write(
            &path,
            r"
title: Failed Logon
detection:
  selection:
    EventID: 4625
    Event.EventData.TargetUserName: alice.admin
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let matching = test_event(json!({
            "Event": {
                "System": { "EventID": 4625 },
                "EventData": { "TargetUserName": "alice.admin" }
            }
        }));
        let non_matching = test_event(json!({
            "Event": {
                "System": { "EventID": 4625 },
                "EventData": { "TargetUserName": "bob.admin" }
            }
        }));

        assert!(report.rules[0].matches(&matching));
        assert!(!report.rules[0].matches(&non_matching));
    }

    #[test]
    fn sigma_rules_extract_safe_metadata_prefilters() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("metadata_prefilter.yml");
        fs::write(
            &path,
            r"
title: Security Admin Logon
detection:
  selection:
    EventID: 4625
    Channel: Security
    Computer: WIN-01
    Event.EventData.TargetUserName|contains: admin
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let matching = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Security",
                    "Computer": "WIN-01"
                },
                "EventData": { "TargetUserName": "alice.admin" }
            }
        }));
        let wrong_metadata = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Security",
                    "Computer": "WIN-01"
                },
                "EventData": { "TargetUserName": "alice.admin" }
            }
        }));

        assert_eq!(
            report.rules[0].metadata_prefilter_count(),
            3,
            "EventID, Channel, and Computer should become safe metadata prefilters"
        );
        assert!(report.rules[0].matches(&matching));
        assert!(!report.rules[0].matches(&wrong_metadata));
    }

    #[test]
    fn sigma_logsource_service_filters_events_by_channel() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("security_logsource.yml");
        fs::write(
            &path,
            r"
title: Security Failed Logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let security_event = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Security"
                }
            }
        }));
        let sysmon_event = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                }
            }
        }));

        assert_eq!(
            report.rules[0].logsource_prefilter_count(),
            1,
            "security service should compile to one channel prefilter"
        );
        assert!(report.rules[0].matches(&security_event));
        assert!(
            !report.rules[0].matches(&sysmon_event),
            "same detection should not match events from a filtered-out channel"
        );
    }

    #[test]
    fn sigma_logsource_unknown_service_does_not_filter() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("unknown_logsource.yml");
        fs::write(
            &path,
            r"
title: Unknown Service Rule
logsource:
  product: windows
  service: custom-service
detection:
  selection:
    EventID: 4625
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Security"
                }
            }
        }));

        assert_eq!(
            report.rules[0].logsource_prefilter_count(),
            0,
            "unknown services should stay unfiltered instead of dropping possible matches"
        );
        assert!(report.rules[0].matches(&event));
    }

    #[test]
    fn sigma_prefilters_skip_or_and_multi_alternative_selections() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("unsafe_prefilter.yml");
        fs::write(
            &path,
            r"
title: Multi Branch Rule
detection:
  selection_a:
    EventID: 4625
  selection_b:
    Channel: Security
  selection_c:
    - EventID: 4688
    - Computer: WIN-01
  condition: selection_a or selection_b or selection_c
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Security",
                    "Computer": "WIN-02"
                }
            }
        }));

        assert_eq!(
            report.rules[0].metadata_prefilter_count(),
            0,
            "or branches and multi-alternative selections should not become required prefilters"
        );
        assert!(
            report.rules[0].matches(&event),
            "full Sigma condition should still match through selection_b"
        );
    }

    #[test]
    fn evaluates_selection_lists_against_event() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("logon_events.yml");
        fs::write(
            &path,
            r"
title: Logon Events
detection:
  selection:
    EventID:
      - 4624
      - 4625
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "System": { "EventID": 4624 }
            }
        }));

        assert!(report.rules[0].matches(&event));
    }

    #[test]
    fn sigma_event_context_can_be_reused_across_keyword_rules() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("keyword_rules.yml");
        fs::write(
            &path,
            r"
---
title: PowerShell Keyword
detection:
  selection:
    - powershell.exe
  condition: selection
---
title: Command Line Keyword
detection:
  selection:
    - NoProfile
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let event = test_event(json!({
            "Event": {
                "System": { "EventID": 4688 },
                "EventData": {
                    "CommandLine": "powershell.exe -NoProfile"
                }
            }
        }));
        let context = SigmaEventContext::new(&event);

        assert_eq!(report.rules.len(), 2);
        assert!(
            report
                .rules
                .iter()
                .all(|rule| rule.matches_context(&context)),
            "one event context should be reusable across keyword-heavy rule checks"
        );
    }

    #[test]
    fn evaluates_boolean_detection_conditions() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("boolean_condition.yml");
        fs::write(
            &path,
            r"
title: Boolean Condition
detection:
  selection_logon:
    EventID: 4624
  selection_user:
    Event.EventData.TargetUserName: alice.admin
  filter_machine:
    Event.EventData.TargetUserName: machine$
  condition: selection_logon and (selection_user or not filter_machine)
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let matching_user = test_event(json!({
            "Event": {
                "System": { "EventID": 4624 },
                "EventData": { "TargetUserName": "alice.admin" }
            }
        }));
        let matching_non_machine = test_event(json!({
            "Event": {
                "System": { "EventID": 4624 },
                "EventData": { "TargetUserName": "bob.admin" }
            }
        }));
        let filtered_machine = test_event(json!({
            "Event": {
                "System": { "EventID": 4624 },
                "EventData": { "TargetUserName": "machine$" }
            }
        }));
        let wrong_event_id = test_event(json!({
            "Event": {
                "System": { "EventID": 4625 },
                "EventData": { "TargetUserName": "alice.admin" }
            }
        }));

        assert!(report.rules[0].matches(&matching_user));
        assert!(report.rules[0].matches(&matching_non_machine));
        assert!(!report.rules[0].matches(&filtered_machine));
        assert!(!report.rules[0].matches(&wrong_event_id));
    }

    #[test]
    fn rejects_conditions_that_reference_unknown_selections() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("unknown_selection.yml");
        fs::write(
            &path,
            r"
title: Unknown Selection
detection:
  selection:
    EventID: 4624
  condition: selection and missing
",
        )
        .expect("rule should be written");

        let error = load_sigma_rules(&[path]).expect_err("unknown selection should fail");

        assert!(
            matches!(error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("unknown selection")),
            "unknown condition selections should be reported clearly"
        );
    }

    #[test]
    fn evaluates_common_string_modifiers() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("modifiers.yml");
        fs::write(
            &path,
            r"
title: Modifier Rule
detection:
  selection:
    Event.EventData.CommandLine|contains|all:
      - powershell
      - encoded
    Event.EventData.Image|endswith: powershell.exe
    Event.EventData.ParentImage|startswith: C:\Windows
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let matching = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "powershell.exe -encodedcommand abc",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ParentImage": "C:\\Windows\\explorer.exe"
                }
            }
        }));
        let missing_all_value = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "powershell.exe",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ParentImage": "C:\\Windows\\explorer.exe"
                }
            }
        }));

        assert!(report.rules[0].matches(&matching));
        assert!(!report.rules[0].matches(&missing_all_value));
    }

    #[test]
    fn sigma_string_matching_is_case_insensitive_unless_cased() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("case.yml");
        fs::write(
            &path,
            r"
title: Case Matching
detection:
  selection_default:
    EventID: 4688
    Image|endswith: POWERSHELL.EXE
    CommandLine|contains: noprofile
  selection_cased:
    EventID: 4688
    Image|endswith|cased: POWERSHELL.EXE
  condition: selection_default and not selection_cased
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "System": { "EventID": 4688 },
                "EventData": {
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -NoProfile"
                }
            }
        }));

        assert!(report.rules[0].matches(&event));
    }

    #[test]
    fn evaluates_condition_lists_as_or_expressions() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("condition_list.yml");
        fs::write(
            &path,
            r"
title: Condition List
detection:
  selection_process:
    EventID: 4688
  selection_dns:
    EventID: 22
  condition:
    - selection_process
    - selection_dns
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "System": { "EventID": 22 }
            }
        }));

        assert!(report.rules[0].matches(&event));
    }

    #[test]
    fn evaluates_lists_of_maps_as_or_alternatives() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("map_list.yml");
        fs::write(
            &path,
            r"
title: Map List
detection:
  selection:
    - EventID: 1
      Image|endswith: powershell.exe
    - EventID: 11
      TargetFilename|endswith: payload.bin
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "System": { "EventID": 11 },
                "EventData": {
                    "TargetFilename": "C:\\ProgramData\\Example\\payload.bin"
                }
            }
        }));

        assert!(report.rules[0].matches(&event));
    }

    #[test]
    fn evaluates_keyword_searches_and_all_keyword_lists() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("keywords.yml");
        fs::write(
            &path,
            r"
title: Keywords
detection:
  keywords_any:
    - Invoke-WebRequest
    - encodedcommand
  keywords_all:
    '|all':
      - powershell.exe
      - NoProfile
  condition: keywords_any and keywords_all
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "System": { "EventID": 4104 },
                "EventData": {
                    "ScriptBlockText": "powershell.exe -NoProfile; Invoke-WebRequest -Uri http://example.invalid"
                }
            }
        }));
        let missing_all = test_event(json!({
            "Event": {
                "System": { "EventID": 4104 },
                "EventData": {
                    "ScriptBlockText": "Invoke-WebRequest -Uri http://example.invalid"
                }
            }
        }));

        assert!(report.rules[0].matches(&event));
        assert!(!report.rules[0].matches(&missing_all));
    }

    #[test]
    fn evaluates_null_values_and_wildcard_string_patterns() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("null_wildcards.yml");
        fs::write(
            &path,
            r"
title: Null Wildcards
detection:
  selection:
    CommandLine: '*-NoProfile*'
    MissingField: null
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "powershell.exe -NoProfile"
                }
            }
        }));
        let non_matching = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "powershell.exe -File collect.ps1",
                    "MissingField": "present"
                }
            }
        }));

        assert!(report.rules[0].matches(&event));
        assert!(!report.rules[0].matches(&non_matching));
    }

    #[test]
    fn evaluates_exists_neq_numeric_and_fieldref_modifiers() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("generic_modifiers.yml");
        fs::write(
            &path,
            r"
title: Generic Modifiers
detection:
  selection:
    OptionalField|exists: false
    CommandLine|neq: cmd.exe
    ProcessId|gte: 1000
    ProcessId|lt: 6000
    SubjectUserName|fieldref: TargetUserName
    ParentProcessId|fieldref|neq: ProcessId
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "powershell.exe -NoProfile",
                    "ProcessId": "5104",
                    "ParentProcessId": "3888",
                    "SubjectUserName": "operator",
                    "TargetUserName": "operator"
                }
            }
        }));
        let wrong = test_event(json!({
            "Event": {
                "EventData": {
                    "OptionalField": "present",
                    "CommandLine": "cmd.exe",
                    "ProcessId": "7000",
                    "ParentProcessId": "7000",
                    "SubjectUserName": "operator",
                    "TargetUserName": "admin"
                }
            }
        }));

        assert!(report.rules[0].matches(&event));
        assert!(!report.rules[0].matches(&wrong));
    }

    #[test]
    fn evaluates_regex_flags_time_and_windash_modifiers() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("regex_time_windash.yml");
        fs::write(
            &path,
            r"
title: Regex Time Windash
detection:
  selection:
    CommandLine|windash|contains: -NoProfile
    ScriptBlockText|re|i|s: invoke-webrequest.+payload\.bin
    TimeCreated|hour: 10
    TimeCreated|minute: 6
    TimeCreated|year: 2026
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "powershell.exe /NoProfile",
                    "ScriptBlockText": "Invoke-WebRequest\n-OutFile payload.bin",
                    "TimeCreated": "2026-01-15T10:06:04Z"
                }
            }
        }));

        assert!(report.rules[0].matches(&event));
    }

    #[test]
    fn evaluates_encoding_modifiers() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("encoding.yml");
        fs::write(
            &path,
            r"
title: Encoding
detection:
  selection:
    EncodedCommand|contains|base64: powershell
    Utf16Hex|contains|utf16le: cmd
    Utf16BomHex|contains|utf16: cmd
    OffsetEncoded|contains|base64offset: cmd
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let event = test_event(json!({
            "Event": {
                "EventData": {
                    "EncodedCommand": "cG93ZXJzaGVsbA==",
                    "Utf16Hex": "63006d006400",
                    "Utf16BomHex": "fffe63006d006400",
                    "OffsetEncoded": "AGN DBA== Y21k"
                }
            }
        }));

        assert!(report.rules[0].matches(&event));
    }

    #[test]
    fn rejects_unsupported_modifiers() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("unsupported_modifier.yml");
        fs::write(
            &path,
            r"
title: Unsupported Modifier
detection:
  selection:
    Event.EventData.CommandLine|unknownmodifier: powershell
  condition: selection
",
        )
        .expect("rule should be written");

        let error = load_sigma_rules(&[path]).expect_err("unsupported modifier should fail");

        assert!(
            matches!(error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("unsupported Sigma modifier")),
            "unsupported modifiers should be reported clearly"
        );
    }

    #[test]
    fn evaluates_regex_and_cidr_modifiers() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("regex_cidr.yml");
        fs::write(
            &path,
            r"
title: Regex Cidr
detection:
  selection:
    Event.EventData.CommandLine|re: (?i)powershell(\.exe)?
    Event.EventData.SourceIp|cidr:
      - 10.0.0.0/8
      - 192.168.0.0/16
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let matching = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "PowerShell.exe -NoProfile",
                    "SourceIp": "10.1.2.3"
                }
            }
        }));
        let non_matching = test_event(json!({
            "Event": {
                "EventData": {
                    "CommandLine": "cmd.exe",
                    "SourceIp": "10.1.2.3"
                }
            }
        }));

        assert!(report.rules[0].matches(&matching));
        assert!(!report.rules[0].matches(&non_matching));
    }

    #[test]
    fn maps_common_windows_sigma_fields_to_evtx_event_data() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("windows_fields.yml");
        fs::write(
            &path,
            r"
title: Windows Field Aliases
detection:
  selection:
    EventID: 3
    Image|endswith: powershell.exe
    CommandLine|contains: NoProfile
    DestinationIp|cidr: 203.0.113.0/24
  condition: selection
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let matching = test_event(json!({
            "Event": {
                "System": { "EventID": 3 },
                "EventData": {
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -NoProfile",
                    "DestinationIp": "203.0.113.55"
                }
            }
        }));
        let wrong_network = test_event(json!({
            "Event": {
                "System": { "EventID": 3 },
                "EventData": {
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -NoProfile",
                    "DestinationIp": "198.51.100.55"
                }
            }
        }));

        assert!(report.rules[0].matches(&matching));
        assert!(!report.rules[0].matches(&wrong_network));
    }

    #[test]
    fn rejects_invalid_regex_and_cidr_modifier_values() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let regex_path = fixture.path().join("invalid_regex.yml");
        fs::write(
            &regex_path,
            r"
title: Invalid Regex
detection:
  selection:
    Event.EventData.CommandLine|re: (
  condition: selection
",
        )
        .expect("rule should be written");
        let cidr_path = fixture.path().join("invalid_cidr.yml");
        fs::write(
            &cidr_path,
            r"
title: Invalid Cidr
detection:
  selection:
    Event.EventData.SourceIp|cidr: 10.0.0.0/33
  condition: selection
",
        )
        .expect("rule should be written");

        let regex_error = load_sigma_rules(&[regex_path]).expect_err("invalid regex should fail");
        let cidr_error = load_sigma_rules(&[cidr_path]).expect_err("invalid CIDR should fail");

        assert!(
            matches!(regex_error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("invalid Sigma regex")),
            "invalid regex modifier values should be reported clearly"
        );
        assert!(
            matches!(cidr_error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("invalid Sigma CIDR")),
            "invalid CIDR modifier values should be reported clearly"
        );
    }

    #[test]
    fn evaluates_one_of_selection_patterns() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("one_of.yml");
        fs::write(
            &path,
            r"
title: One Of
detection:
  selection_a:
    EventID: 4624
  selection_b:
    EventID: 4625
  filter:
    Event.EventData.TargetUserName: machine$
  condition: 1 of selection_*
",
        )
        .expect("rule should be written");
        let report = load_sigma_rules(&[path]).expect("rule should load");
        let matching = test_event(json!({
            "Event": {
                "System": { "EventID": 4625 }
            }
        }));
        let non_matching = test_event(json!({
            "Event": {
                "System": { "EventID": 4672 }
            }
        }));

        assert!(report.rules[0].matches(&matching));
        assert!(!report.rules[0].matches(&non_matching));
    }

    #[test]
    fn evaluates_all_of_selection_patterns_and_them() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let all_path = fixture.path().join("all_of.yml");
        fs::write(
            &all_path,
            r"
title: All Of
detection:
  selection_event:
    EventID: 4624
  selection_user:
    Event.EventData.TargetUserName: alice.admin
  condition: all of selection_*
",
        )
        .expect("all-of rule should be written");
        let them_path = fixture.path().join("them.yml");
        fs::write(
            &them_path,
            r"
title: Them
detection:
  first:
    EventID: 4624
  second:
    Event.EventData.TargetUserName: alice.admin
  condition: 1 of them
",
        )
        .expect("them rule should be written");
        let report = load_sigma_rules(&[fixture.path().to_path_buf()]).expect("rules should load");
        let all_rule = report
            .rules
            .iter()
            .find(|rule| rule.title == "All Of")
            .expect("all-of rule should be loaded");
        let them_rule = report
            .rules
            .iter()
            .find(|rule| rule.title == "Them")
            .expect("them rule should be loaded");
        let matching = test_event(json!({
            "Event": {
                "System": { "EventID": 4624 },
                "EventData": { "TargetUserName": "alice.admin" }
            }
        }));
        let partial = test_event(json!({
            "Event": {
                "System": { "EventID": 4624 },
                "EventData": { "TargetUserName": "bob.admin" }
            }
        }));

        assert!(all_rule.matches(&matching));
        assert!(!all_rule.matches(&partial));
        assert!(them_rule.matches(&partial));
    }

    #[test]
    fn rejects_condition_patterns_that_match_no_selections() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("missing_pattern.yml");
        fs::write(
            &path,
            r"
title: Missing Pattern
detection:
  selection:
    EventID: 4624
  condition: 1 of missing_*
",
        )
        .expect("rule should be written");

        let error = load_sigma_rules(&[path]).expect_err("missing pattern should fail");

        assert!(
            matches!(error, SigmaLoadError::UnsupportedRule { message, .. } if message.contains("does not match any selections")),
            "missing selection patterns should be reported clearly"
        );
    }

    #[test]
    fn event_count_correlation_emits_when_grouped_window_reaches_threshold() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("failed_logon_correlation.yml");
        fs::write(
            &path,
            r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
        let first = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));
        let second = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));

        assert!(report.rules[0].matches(&first));
        assert!(
            engine
                .observe_match(&report.rules[0], &first, &[])
                .is_empty()
        );

        let matches = engine.observe_match(&report.rules[0], &second, &[]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule.title, "Repeated Failed Logons");
        assert_eq!(
            matches[0].group,
            [
                ("scope.host".to_owned(), "WIN-01".to_owned()),
                ("TargetUserName".to_owned(), "alice".to_owned())
            ]
        );
        assert_eq!(matches[0].matches.len(), 2);
        assert_eq!(matches[0].window_start, "2026-06-28T12:00:00Z");
        assert_eq!(matches[0].window_end, "2026-06-28T12:04:00Z");
    }

    #[test]
    fn correlation_lateness_allows_bounded_out_of_order_matches() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("bounded_lateness.yml");
        fs::write(
            &path,
            r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine = SigmaCorrelationEngine::new_with_lateness(
            &report.correlations,
            CorrelationRuntimeScope::Host,
            100,
            Duration::minutes(3),
        );
        let first = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));
        let future_other_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:07:00Z" }
                },
                "EventData": { "TargetUserName": "bob" }
            }
        }));
        let late_same_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &first, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[0], &future_other_group, &[])
                .is_empty()
        );

        let matches = engine.observe_match(&report.rules[0], &late_same_group, &[]);

        assert_eq!(
            matches.len(),
            1,
            "late event within allowed lateness should still complete the correlation"
        );
        assert_eq!(matches[0].window_start, "2026-06-28T12:00:00Z");
        assert_eq!(matches[0].window_end, "2026-06-28T12:04:00Z");
    }

    #[test]
    fn correlation_lateness_drops_events_older_than_watermark() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("late_drop.yml");
        fs::write(
            &path,
            r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine = SigmaCorrelationEngine::new_with_lateness(
            &report.correlations,
            CorrelationRuntimeScope::Host,
            100,
            Duration::minutes(1),
        );
        let first = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));
        let future_other_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:07:00Z" }
                },
                "EventData": { "TargetUserName": "bob" }
            }
        }));
        let too_late_same_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &first, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[0], &future_other_group, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[0], &too_late_same_group, &[])
                .is_empty(),
            "event older than the lateness watermark should not complete correlation"
        );
    }

    #[test]
    fn correlation_lateness_prunes_stale_state_across_groups() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("stale_prune.yml");
        fs::write(
            &path,
            r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Repeated Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine = SigmaCorrelationEngine::new_with_lateness(
            &report.correlations,
            CorrelationRuntimeScope::Host,
            100,
            Duration::seconds(0),
        );
        let first_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));
        let future_other_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:10:00Z" }
                },
                "EventData": { "TargetUserName": "bob" }
            }
        }));
        let stale_first_group = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:04:00Z" }
                },
                "EventData": { "TargetUserName": "alice" }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &first_group, &[])
                .is_empty()
        );
        assert_eq!(engine.stats().state_entries, 1);
        assert!(
            engine
                .observe_match(&report.rules[0], &future_other_group, &[])
                .is_empty()
        );
        assert_eq!(
            engine.stats().state_entries,
            1,
            "future event in another group should prune stale alice state and keep only bob"
        );

        let matches = engine.observe_match(&report.rules[0], &stale_first_group, &[]);

        assert!(
            matches.is_empty(),
            "stale event older than watermark must not complete an already-pruned group"
        );
        assert_eq!(engine.stats().state_entries, 1);
    }

    #[test]
    fn value_count_correlation_counts_distinct_values_in_grouped_window() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("failed_logon_value_count.yml");
        fs::write(
            &path,
            r"
---
title: Failed Logon
name: failed_logon
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Failed Logons From Multiple Addresses
type: correlation
correlation:
  type: value_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    field: IpAddress
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");
        let report = load_sigma_rules(&[path]).expect("rules should load");
        let mut engine =
            SigmaCorrelationEngine::new(&report.correlations, CorrelationRuntimeScope::Host, 100);
        let first = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:00:00Z" }
                },
                "EventData": {
                    "TargetUserName": "alice",
                    "IpAddress": "198.51.100.10"
                }
            }
        }));
        let duplicate_value = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:01:00Z" }
                },
                "EventData": {
                    "TargetUserName": "alice",
                    "IpAddress": "198.51.100.10"
                }
            }
        }));
        let second_value = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "WIN-01",
                    "TimeCreated": { "SystemTime": "2026-06-28T12:02:00Z" }
                },
                "EventData": {
                    "TargetUserName": "alice",
                    "IpAddress": "198.51.100.11"
                }
            }
        }));

        assert!(
            engine
                .observe_match(&report.rules[0], &first, &[])
                .is_empty()
        );
        assert!(
            engine
                .observe_match(&report.rules[0], &duplicate_value, &[])
                .is_empty()
        );

        let matches = engine.observe_match(&report.rules[0], &second_value, &[]);

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].rule.title,
            "Failed Logons From Multiple Addresses"
        );
        assert_eq!(matches[0].matches.len(), 3);
        assert_eq!(
            report.correlations[0].correlation.value_fields,
            ["IpAddress"]
        );
    }

    fn test_event(raw: serde_json::Value) -> Event {
        let input = DiscoveredInput::new(PathBuf::from("Security.evtx"), PathBuf::from("."));

        Event::from_raw(&input, Some(1), raw)
    }

    fn repeated_process_correlation_report() -> SigmaLoadReport {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        let path = fixture.path().join("repeated_process.yml");
        fs::write(
            &path,
            r"
---
title: Process Start
name: process_start
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Repeated Process Starts
type: correlation
correlation:
  type: event_count
  rules:
    - process_start
  group-by:
    - ProcessGuid
  condition:
    gte: 2
  timespan: 5m
",
        )
        .expect("correlation fixture should be written");

        load_sigma_rules(&[path]).expect("rules should load")
    }
}
