use std::borrow::Cow;
use std::fmt::Write as _;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::event::{Event, FieldValue};

#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub path: PathBuf,
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub tags: Vec<String>,
    detection: Detection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedSigmaRule {
    pub path: PathBuf,
    pub title: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Correlation,
}

#[derive(Debug, Default, Clone)]
pub struct SigmaLoadReport {
    pub rules: Vec<SigmaRule>,
    pub skipped: Vec<SkippedSigmaRule>,
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
    title: Option<String>,
    id: Option<String>,
    status: Option<String>,
    level: Option<String>,
    #[serde(default)]
    tags: StringList,
    #[serde(rename = "type")]
    rule_type: Option<String>,
    correlation: Option<noyalib::Value>,
    detection: Option<noyalib::Value>,
}

#[derive(Debug, Clone)]
struct Detection {
    condition: ConditionExpr,
    selections: Vec<Selection>,
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
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        self.detection.matches(event)
    }

    #[cfg(test)]
    pub fn test_rule(title: impl Into<String>, level: Option<String>) -> Self {
        Self {
            path: PathBuf::from("rule.yml"),
            title: title.into(),
            id: Some("11111111-1111-1111-1111-111111111111".to_owned()),
            status: Some("test".to_owned()),
            level,
            tags: vec!["attack.execution".to_owned()],
            detection: Detection {
                condition: ConditionExpr::Selection("selection".to_owned()),
                selections: Vec::new(),
            },
        }
    }
}

impl Detection {
    fn matches(&self, event: &Event) -> bool {
        self.condition.matches(event, &self.selections)
    }
}

impl ConditionExpr {
    fn matches(&self, event: &Event, selections: &[Selection]) -> bool {
        match self {
            Self::Selection(name) => selections
                .iter()
                .find(|selection| selection.name == *name)
                .is_some_and(|selection| selection.matches(event)),
            Self::OneOf(pattern) => matching_selections(pattern, selections)
                .into_iter()
                .any(|selection| selection.matches(event)),
            Self::AllOf(pattern) => {
                let matched = matching_selections(pattern, selections);
                !matched.is_empty() && matched.iter().all(|selection| selection.matches(event))
            }
            Self::Not(expression) => !expression.matches(event, selections),
            Self::And(left, right) => {
                left.matches(event, selections) && right.matches(event, selections)
            }
            Self::Or(left, right) => {
                left.matches(event, selections) || right.matches(event, selections)
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
    fn matches(&self, event: &Event) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| alternative.matches(event))
    }
}

impl SelectionAlternative {
    fn matches(&self, event: &Event) -> bool {
        self.predicates
            .iter()
            .all(|predicate| predicate.matches(event))
            && self.keywords.iter().all(|keyword| keyword.matches(event))
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
    fn matches(&self, event: &Event) -> bool {
        let event_text = event.raw.to_string();

        if self.require_all {
            self.values
                .iter()
                .all(|value| keyword_value_matches(&event_text, value, self.case))
        } else {
            self.values
                .iter()
                .any(|value| keyword_value_matches(&event_text, value, self.case))
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
    let mut report = SigmaLoadReport::default();

    for path in paths {
        load_path(path, &mut report)?;
    }

    report
        .rules
        .sort_by(|left, right| left.path.cmp(&right.path));
    report
        .skipped
        .sort_by(|left, right| left.path.cmp(&right.path));

    Ok(report)
}

fn load_path(path: &Path, report: &mut SigmaLoadReport) -> Result<(), SigmaLoadError> {
    if path.is_file() {
        if is_yaml_path(path) {
            load_file(path, report)?;
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
            load_path(&entry.path(), report)?;
        }

        return Ok(());
    }

    Err(SigmaLoadError::UnsupportedPath {
        path: path.to_path_buf(),
    })
}

fn load_file(path: &Path, report: &mut SigmaLoadReport) -> Result<(), SigmaLoadError> {
    let content = fs::read_to_string(path).map_err(|source| SigmaLoadError::RuleRead {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: RawSigmaRule =
        noyalib::from_str(&content).map_err(|source| SigmaLoadError::RuleParse {
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
        report.skipped.push(SkippedSigmaRule {
            path: path.to_path_buf(),
            title,
            reason: SkipReason::Correlation,
        });
        return Ok(());
    }

    report.rules.push(SigmaRule {
        path: path.to_path_buf(),
        title,
        id: raw.id,
        status: raw.status,
        level: raw.level,
        tags: raw.tags.0,
        detection: parse_detection(path, raw.detection)?,
    });

    Ok(())
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

    Ok(Detection {
        condition,
        selections,
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
    fn loads_regular_rules_and_skips_correlation_rules() {
        let fixture = tempfile::tempdir().expect("tempdir should be created");
        fs::write(
            fixture.path().join("process_creation.yml"),
            r"
title: Suspicious Process
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
title: Many Failed Logons
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
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
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, SkipReason::Correlation);
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

    fn test_event(raw: serde_json::Value) -> Event {
        let input = DiscoveredInput {
            path: PathBuf::from("Security.evtx"),
            collection_root: PathBuf::from("."),
        };

        Event::from_raw(&input, Some(1), raw)
    }
}
