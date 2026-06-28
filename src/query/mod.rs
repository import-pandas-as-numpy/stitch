use std::net::IpAddr;

use regex::{Regex, RegexBuilder};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::event::{Event, FieldValue};

#[derive(Debug, Clone)]
pub enum Expr {
    Comparison(Comparison),
    Regex(RegexComparison),
    Exists(String),
    CidrContains(CidrContains),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub filter: Expr,
    pub keep_fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Comparison {
    pub field: String,
    pub operator: Operator,
    pub value: Literal,
}

#[derive(Debug, Clone)]
pub struct RegexComparison {
    field: String,
    regex: Regex,
    negated: bool,
}

#[derive(Debug, Clone)]
pub struct CidrContains {
    field: String,
    network: IpNetwork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
    Contains,
    ContainsCi,
    In,
    Regex,
    NotRegex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    String(String),
    Number(u64),
    Bool(bool),
    List(Vec<Literal>),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QueryError {
    #[error("query is empty")]
    Empty,
    #[error("unexpected token {token:?}")]
    UnexpectedToken { token: String },
    #[error("expected {expected}, found {found:?}")]
    Expected { expected: String, found: String },
    #[error("unterminated string literal")]
    UnterminatedString,
    #[error("invalid number literal {literal:?}")]
    InvalidNumber { literal: String },
    #[error("invalid regex {pattern:?}: {message}")]
    InvalidRegex { pattern: String, message: String },
    #[error("unsupported regex flag {flag:?}")]
    UnsupportedRegexFlag { flag: char },
    #[error("unterminated regex literal")]
    UnterminatedRegex,
    #[error("invalid CIDR {value:?}")]
    InvalidCidr { value: String },
    #[error("invalid CIDR prefix {prefix} for {family}")]
    InvalidCidrPrefix { prefix: u8, family: &'static str },
    #[error("unsupported pipeline command {command:?}")]
    UnsupportedPipeline { command: String },
    #[error("keep requires at least one field")]
    EmptyKeep,
}

#[cfg(test)]
fn parse_query(query: &str) -> Result<Expr, QueryError> {
    let tokens = tokenize(query)?;

    if tokens.is_empty() {
        return Err(QueryError::Empty);
    }

    let mut parser = Parser::new(tokens);
    let expression = parser.parse_or()?;
    parser.expect_end()?;
    Ok(expression)
}

pub fn parse_search_query(query: &str) -> Result<SearchQuery, QueryError> {
    let tokens = tokenize(query)?;

    if tokens.is_empty() {
        return Err(QueryError::Empty);
    }

    let mut parser = Parser::new(tokens);
    let filter = parser.parse_or()?;
    let keep_fields = if parser.consume_symbol(Symbol::Pipe) {
        parser.parse_pipeline()?
    } else {
        Vec::new()
    };
    parser.expect_end()?;

    Ok(SearchQuery {
        filter,
        keep_fields,
    })
}

impl Expr {
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> bool {
        match self {
            Self::Comparison(comparison) => comparison.evaluate(event),
            Self::Regex(comparison) => comparison.evaluate(event),
            Self::Exists(field) => event.field(field).is_some(),
            Self::CidrContains(function) => function.evaluate(event),
            Self::Not(expression) => !expression.evaluate(event),
            Self::And(left, right) => left.evaluate(event) && right.evaluate(event),
            Self::Or(left, right) => left.evaluate(event) || right.evaluate(event),
        }
    }
}

impl CidrContains {
    fn new(field: String, cidr: &str) -> Result<Self, QueryError> {
        Ok(Self {
            field,
            network: IpNetwork::parse(cidr)?,
        })
    }

    #[must_use]
    pub fn evaluate(&self, event: &Event) -> bool {
        event
            .field(&self.field)
            .and_then(FieldValue::as_text)
            .and_then(|value| value.parse::<IpAddr>().ok())
            .is_some_and(|address| self.network.contains(address))
    }
}

#[derive(Debug, Clone, Copy)]
enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    fn parse(value: &str) -> Result<Self, QueryError> {
        let Some((address, prefix)) = value.split_once('/') else {
            return Err(QueryError::InvalidCidr {
                value: value.to_owned(),
            });
        };
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| QueryError::InvalidCidr {
                value: value.to_owned(),
            })?;
        let prefix = prefix.parse::<u8>().map_err(|_| QueryError::InvalidCidr {
            value: value.to_owned(),
        })?;

        match address {
            IpAddr::V4(address) => {
                if prefix > 32 {
                    return Err(QueryError::InvalidCidrPrefix {
                        prefix,
                        family: "IPv4",
                    });
                }

                let mask = prefix_mask_u32(prefix);
                Ok(Self::V4 {
                    network: u32::from(address) & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) => {
                if prefix > 128 {
                    return Err(QueryError::InvalidCidrPrefix {
                        prefix,
                        family: "IPv6",
                    });
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

impl Comparison {
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> bool {
        event
            .field(&self.field)
            .is_some_and(|field| match self.operator {
                Operator::Eq => equals(field, &self.value),
                Operator::NotEq => !equals(field, &self.value),
                Operator::Lt => compare_field_value(field, &self.value, &self.field)
                    .is_some_and(std::cmp::Ordering::is_lt),
                Operator::Lte => compare_field_value(field, &self.value, &self.field)
                    .is_some_and(std::cmp::Ordering::is_le),
                Operator::Gt => compare_field_value(field, &self.value, &self.field)
                    .is_some_and(std::cmp::Ordering::is_gt),
                Operator::Gte => compare_field_value(field, &self.value, &self.field)
                    .is_some_and(std::cmp::Ordering::is_ge),
                Operator::Contains => contains(field, &self.value, CaseMode::Sensitive),
                Operator::ContainsCi => contains(field, &self.value, CaseMode::Insensitive),
                Operator::In => in_list(field, &self.value),
                Operator::Regex | Operator::NotRegex => false,
            })
    }
}

impl RegexComparison {
    fn new(field: String, pattern: RegexPattern, negated: bool) -> Result<Self, QueryError> {
        let regex = RegexBuilder::new(&pattern.value)
            .case_insensitive(pattern.case_insensitive)
            .build()
            .map_err(|error| QueryError::InvalidRegex {
                pattern: pattern.value,
                message: error.to_string(),
            })?;

        Ok(Self {
            field,
            regex,
            negated,
        })
    }

    #[must_use]
    pub fn evaluate(&self, event: &Event) -> bool {
        let matched = event
            .field(&self.field)
            .and_then(FieldValue::as_text)
            .is_some_and(|text| self.regex.is_match(&text));

        matched != self.negated
    }
}

fn equals(field: FieldValue<'_>, literal: &Literal) -> bool {
    match literal {
        Literal::Number(value) => field.as_u64() == Some(*value),
        Literal::String(value) => field.as_text().is_some_and(|text| text == *value),
        Literal::Bool(value) => {
            matches!(field, FieldValue::Bool(field_value) if field_value == *value)
        }
        Literal::List(_) => false,
    }
}

fn compare_field_value(
    field: FieldValue<'_>,
    literal: &Literal,
    field_name: &str,
) -> Option<std::cmp::Ordering> {
    compare_timestamps(field, literal, field_name).or_else(|| compare_values(field, literal))
}

fn compare_timestamps(
    field: FieldValue<'_>,
    literal: &Literal,
    field_name: &str,
) -> Option<std::cmp::Ordering> {
    if !is_timestamp_field(field_name) {
        return None;
    }

    let Literal::String(value) = literal else {
        return None;
    };

    let field_time = parse_timestamp(&field.as_text()?)?;
    let literal_time = parse_timestamp(value)?;

    Some(field_time.cmp(&literal_time))
}

fn compare_values(field: FieldValue<'_>, literal: &Literal) -> Option<std::cmp::Ordering> {
    match literal {
        Literal::Number(value) => field.as_u64().map(|field_value| field_value.cmp(value)),
        Literal::String(value) => field.as_text().map(|field_value| field_value.cmp(value)),
        Literal::Bool(_) | Literal::List(_) => None,
    }
}

fn is_timestamp_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "timestamp" | "event.timestamp" | "winlog.timestamp"
    ) || field_name.ends_with(".TimeCreated.SystemTime")
        || field_name.ends_with(".TimeCreated.#attributes.SystemTime")
}

fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok().or_else(|| {
        if has_timezone_designator(value) {
            return None;
        }

        OffsetDateTime::parse(&format!("{value}Z"), &Rfc3339).ok()
    })
}

fn has_timezone_designator(value: &str) -> bool {
    let Some((_, time_part)) = value.split_once('T') else {
        return value.ends_with('Z') || value.ends_with('z');
    };

    time_part.ends_with('Z')
        || time_part.ends_with('z')
        || time_part.contains('+')
        || time_part.contains('-')
}

fn contains(field: FieldValue<'_>, literal: &Literal, case_mode: CaseMode) -> bool {
    let Literal::String(needle) = literal else {
        return false;
    };
    let Some(haystack) = field.as_text() else {
        return false;
    };

    match case_mode {
        CaseMode::Sensitive => haystack.contains(needle),
        CaseMode::Insensitive => haystack.to_lowercase().contains(&needle.to_lowercase()),
    }
}

fn in_list(field: FieldValue<'_>, literal: &Literal) -> bool {
    let Literal::List(values) = literal else {
        return false;
    };

    values.iter().any(|value| equals(field, value))
}

#[derive(Debug, Clone, Copy)]
enum CaseMode {
    Sensitive,
    Insensitive,
}

#[derive(Debug)]
struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse_or(&mut self) -> Result<Expr, QueryError> {
        let mut expression = self.parse_and()?;

        while self.consume_keyword("or") {
            let right = self.parse_and()?;
            expression = Expr::Or(Box::new(expression), Box::new(right));
        }

        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<Expr, QueryError> {
        let mut expression = self.parse_not()?;

        while self.consume_keyword("and") {
            let right = self.parse_not()?;
            expression = Expr::And(Box::new(expression), Box::new(right));
        }

        Ok(expression)
    }

    fn parse_not(&mut self) -> Result<Expr, QueryError> {
        if self.consume_keyword("not") {
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }

        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, QueryError> {
        if self.consume_symbol(Symbol::LeftParen) {
            let expression = self.parse_or()?;
            self.expect_symbol(Symbol::RightParen)?;
            return Ok(expression);
        }

        if self.consume_keyword("exists") {
            self.expect_symbol(Symbol::LeftParen)?;
            let field = self.expect_ident("field name")?;
            self.expect_symbol(Symbol::RightParen)?;
            return Ok(Expr::Exists(field));
        }

        if self.consume_keyword("cidr_contains") || self.consume_keyword("ip_in_cidr") {
            return self.parse_cidr_contains();
        }

        self.parse_comparison()
    }

    fn parse_cidr_contains(&mut self) -> Result<Expr, QueryError> {
        self.expect_symbol(Symbol::LeftParen)?;
        let field = self.expect_ident("field name")?;
        self.expect_symbol(Symbol::Comma)?;
        let cidr = self.expect_string_literal()?;
        self.expect_symbol(Symbol::RightParen)?;

        CidrContains::new(field, &cidr).map(Expr::CidrContains)
    }

    fn parse_comparison(&mut self) -> Result<Expr, QueryError> {
        let field = self.expect_ident("field name")?;
        let operator = self.expect_operator()?;

        if matches!(operator, Operator::Regex | Operator::NotRegex) {
            let pattern = self.expect_regex_pattern()?;
            return RegexComparison::new(field, pattern, operator == Operator::NotRegex)
                .map(Expr::Regex);
        }

        let value = if operator == Operator::In {
            self.expect_list()?
        } else {
            self.expect_literal()?
        };

        Ok(Expr::Comparison(Comparison {
            field,
            operator,
            value,
        }))
    }

    fn parse_pipeline(&mut self) -> Result<Vec<String>, QueryError> {
        let command = self.expect_ident("pipeline command")?;

        if !command.eq_ignore_ascii_case("keep") {
            return Err(QueryError::UnsupportedPipeline { command });
        }

        self.parse_keep_fields()
    }

    fn parse_keep_fields(&mut self) -> Result<Vec<String>, QueryError> {
        if !matches!(self.peek(), Some(Token::Ident(_))) {
            return Err(QueryError::EmptyKeep);
        }

        let mut fields = vec![self.expect_ident("field name")?];

        while self.consume_symbol(Symbol::Comma) {
            fields.push(self.expect_ident("field name")?);
        }

        Ok(fields)
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        if self.peek().is_some_and(
            |token| matches!(token, Token::Ident(value) if value.eq_ignore_ascii_case(keyword)),
        ) {
            self.position += 1;
            return true;
        }

        false
    }

    fn consume_symbol(&mut self, symbol: Symbol) -> bool {
        if self
            .peek()
            .is_some_and(|token| matches!(token, Token::Symbol(value) if *value == symbol))
        {
            self.position += 1;
            return true;
        }

        false
    }

    fn expect_symbol(&mut self, symbol: Symbol) -> Result<(), QueryError> {
        if self.consume_symbol(symbol) {
            return Ok(());
        }

        Err(QueryError::Expected {
            expected: format!("{symbol:?}"),
            found: self.peek_label(),
        })
    }

    fn expect_ident(&mut self, expected: &str) -> Result<String, QueryError> {
        match self.next() {
            Some(Token::Ident(value)) => Ok(value),
            other => Err(QueryError::Expected {
                expected: expected.to_owned(),
                found: token_label(other.as_ref()),
            }),
        }
    }

    fn expect_operator(&mut self) -> Result<Operator, QueryError> {
        match self.next() {
            Some(Token::Operator(operator)) => Ok(operator),
            Some(Token::Ident(value)) => match value.as_str() {
                "contains" => Ok(Operator::Contains),
                "contains_ci" => Ok(Operator::ContainsCi),
                "in" => Ok(Operator::In),
                _ => Err(QueryError::UnexpectedToken { token: value }),
            },
            other => Err(QueryError::Expected {
                expected: "operator".to_owned(),
                found: token_label(other.as_ref()),
            }),
        }
    }

    fn expect_regex_pattern(&mut self) -> Result<RegexPattern, QueryError> {
        match self.next() {
            Some(Token::String(value)) => Ok(RegexPattern {
                value,
                case_insensitive: false,
            }),
            Some(Token::Regex(value)) => Ok(value),
            other => Err(QueryError::Expected {
                expected: "regex pattern".to_owned(),
                found: token_label(other.as_ref()),
            }),
        }
    }

    fn expect_string_literal(&mut self) -> Result<String, QueryError> {
        match self.next() {
            Some(Token::String(value)) => Ok(value),
            other => Err(QueryError::Expected {
                expected: "string literal".to_owned(),
                found: token_label(other.as_ref()),
            }),
        }
    }

    fn expect_list(&mut self) -> Result<Literal, QueryError> {
        self.expect_symbol(Symbol::LeftParen)?;
        let mut values = vec![self.expect_literal()?];

        while self.consume_symbol(Symbol::Comma) {
            values.push(self.expect_literal()?);
        }

        self.expect_symbol(Symbol::RightParen)?;
        Ok(Literal::List(values))
    }

    fn expect_literal(&mut self) -> Result<Literal, QueryError> {
        match self.next() {
            Some(Token::String(value)) => Ok(Literal::String(value)),
            Some(Token::Number(value)) => Ok(Literal::Number(value)),
            Some(Token::Ident(value)) if value.eq_ignore_ascii_case("true") => {
                Ok(Literal::Bool(true))
            }
            Some(Token::Ident(value)) if value.eq_ignore_ascii_case("false") => {
                Ok(Literal::Bool(false))
            }
            other => Err(QueryError::Expected {
                expected: "literal".to_owned(),
                found: token_label(other.as_ref()),
            }),
        }
    }

    fn expect_end(&self) -> Result<(), QueryError> {
        if self.position == self.tokens.len() {
            return Ok(());
        }

        Err(QueryError::UnexpectedToken {
            token: self.peek_label(),
        })
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();

        if token.is_some() {
            self.position += 1;
        }

        token
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn peek_label(&self) -> String {
        token_label(self.peek())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    String(String),
    Regex(RegexPattern),
    Number(u64),
    Operator(Operator),
    Symbol(Symbol),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegexPattern {
    value: String,
    case_insensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Symbol {
    LeftParen,
    RightParen,
    Comma,
    Pipe,
}

fn tokenize(query: &str) -> Result<Vec<Token>, QueryError> {
    let mut tokens = Vec::new();
    let mut chars = query.char_indices().peekable();

    while let Some((_, character)) = chars.peek().copied() {
        match character {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::Symbol(Symbol::LeftParen));
            }
            ')' => {
                chars.next();
                tokens.push(Token::Symbol(Symbol::RightParen));
            }
            ',' => {
                chars.next();
                tokens.push(Token::Symbol(Symbol::Comma));
            }
            '|' => {
                chars.next();
                tokens.push(Token::Symbol(Symbol::Pipe));
            }
            '"' => tokens.push(Token::String(read_string(&mut chars)?)),
            '/' => tokens.push(Token::Regex(read_regex_literal(&mut chars)?)),
            '0'..='9' => tokens.push(Token::Number(read_number(&mut chars)?)),
            '=' | '!' | '<' | '>' => tokens.push(Token::Operator(read_operator(&mut chars)?)),
            _ if is_ident_start(character) => tokens.push(Token::Ident(read_ident(&mut chars))),
            _ => {
                return Err(QueryError::UnexpectedToken {
                    token: character.to_string(),
                });
            }
        }
    }

    Ok(tokens)
}

fn read_string(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Result<String, QueryError> {
    chars.next();
    let mut value = String::new();

    while let Some((_, character)) = chars.next() {
        match character {
            '"' => return Ok(value),
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    return Err(QueryError::UnterminatedString);
                };
                value.push(escaped);
            }
            _ => value.push(character),
        }
    }

    Err(QueryError::UnterminatedString)
}

fn read_regex_literal(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Result<RegexPattern, QueryError> {
    chars.next();
    let mut value = String::new();
    let mut case_insensitive = false;

    while let Some((_, character)) = chars.next() {
        match character {
            '/' => {
                while let Some((_, flag)) = chars.peek().copied() {
                    if !flag.is_ascii_alphabetic() {
                        break;
                    }

                    chars.next();

                    if flag == 'i' {
                        case_insensitive = true;
                    } else {
                        return Err(QueryError::UnsupportedRegexFlag { flag });
                    }
                }

                return Ok(RegexPattern {
                    value,
                    case_insensitive,
                });
            }
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    return Err(QueryError::UnterminatedRegex);
                };

                if escaped == '/' {
                    value.push('/');
                } else {
                    value.push('\\');
                    value.push(escaped);
                }
            }
            _ => value.push(character),
        }
    }

    Err(QueryError::UnterminatedRegex)
}

fn read_number(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Result<u64, QueryError> {
    let literal = read_while(chars, |character| character.is_ascii_digit());

    literal
        .parse()
        .map_err(|_| QueryError::InvalidNumber { literal })
}

fn read_operator(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Result<Operator, QueryError> {
    let first = chars
        .next()
        .expect("operator reader starts on an operator")
        .1;
    let second = chars.peek().map(|(_, character)| *character);

    match (first, second) {
        ('=', Some('=')) => {
            chars.next();
            Ok(Operator::Eq)
        }
        ('=', Some('~')) => {
            chars.next();
            Ok(Operator::Regex)
        }
        ('!', Some('=')) => {
            chars.next();
            Ok(Operator::NotEq)
        }
        ('!', Some('~')) => {
            chars.next();
            Ok(Operator::NotRegex)
        }
        ('<', Some('=')) => {
            chars.next();
            Ok(Operator::Lte)
        }
        ('>', Some('=')) => {
            chars.next();
            Ok(Operator::Gte)
        }
        ('<', _) => Ok(Operator::Lt),
        ('>', _) => Ok(Operator::Gt),
        _ => Err(QueryError::UnexpectedToken {
            token: first.to_string(),
        }),
    }
}

fn read_ident(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>) -> String {
    read_while(chars, is_ident_continue)
}

fn read_while(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    predicate: impl Fn(char) -> bool,
) -> String {
    let mut value = String::new();

    while let Some((_, character)) = chars.peek().copied() {
        if !predicate(character) {
            break;
        }

        value.push(character);
        chars.next();
    }

    value
}

fn is_ident_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_'
}

fn is_ident_continue(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-' | '#')
}

fn token_label(token: Option<&Token>) -> String {
    match token {
        Some(Token::Ident(value) | Token::String(value)) => value.clone(),
        Some(Token::Regex(value)) => format!("/{}/", value.value),
        Some(Token::Number(value)) => value.to_string(),
        Some(Token::Operator(operator)) => format!("{operator:?}"),
        Some(Token::Symbol(symbol)) => format!("{symbol:?}"),
        None => "end of query".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use crate::event::Event;
    use crate::input::DiscoveredInput;

    use super::*;

    #[test]
    fn parses_boolean_precedence() {
        let expression =
            parse_query("event.id == 4625 or event.id == 4624 and channel == \"Security\"")
                .expect("query should parse");

        assert!(matches!(expression, Expr::Or(_, _)));
    }

    #[test]
    fn tokenizes_complete_stql_lexicon() {
        let tokens = tokenize(
            "Event.System.TimeCreated.#attributes.SystemTime >= \"2026-06-27T00:00:00Z\" \
             and provider =~ /power\\/shell/i | keep event.id, source.file_path",
        )
        .expect("query should tokenize");

        assert_eq!(
            tokens,
            vec![
                Token::Ident("Event.System.TimeCreated.#attributes.SystemTime".to_owned()),
                Token::Operator(Operator::Gte),
                Token::String("2026-06-27T00:00:00Z".to_owned()),
                Token::Ident("and".to_owned()),
                Token::Ident("provider".to_owned()),
                Token::Operator(Operator::Regex),
                Token::Regex(RegexPattern {
                    value: "power/shell".to_owned(),
                    case_insensitive: true,
                }),
                Token::Symbol(Symbol::Pipe),
                Token::Ident("keep".to_owned()),
                Token::Ident("event.id".to_owned()),
                Token::Symbol(Symbol::Comma),
                Token::Ident("source.file_path".to_owned()),
            ],
            "lexer should recognize identifiers, operators, strings, regex literals, and pipeline symbols"
        );
    }

    #[test]
    fn parses_documented_stql_statements() {
        let statements = [
            "event.id == 4625 and channel == \"Security\"",
            "event.id == 4625 or event.id == 4624",
            "not exists(Event.EventData.TargetUserName)",
            "record_id > 1000",
            "Event.EventData.TargetUserName contains \"admin\"",
            "Event.EventData.CommandLine contains_ci \"powershell\"",
            "event.id in (4624, 4625)",
            "provider =~ \"(?i)powershell\"",
            "provider !~ \"(?i)defender\"",
            "timestamp >= \"2026-06-27T00:00:00Z\"",
            "timestamp >= \"2026-03-21T06:00:00Z\" and timestamp < \"2026-03-21T07:00:00Z\"",
            "timestamp >= \"2026-03-21T01:00:00-05:00\"",
            "timestamp >= \"2026-03-21T06:00:00\"",
            "provider =~ /powershell/i",
            r"Event.EventData.CommandLine =~ /cmd\.exe \/c/",
            "channel in (\"Security\", \"System\")",
            "exists(field.name)",
            "event.id == 4624 | keep timestamp, event.id, computer, Event.EventData.TargetUserName",
        ];

        for statement in statements {
            parse_search_query(statement).unwrap_or_else(|error| {
                panic!("documented STQL should parse: {statement}: {error}")
            });
        }
    }

    #[test]
    fn evaluates_all_comparison_operators_and_literal_forms() {
        let event = rich_test_event();
        let matching_statements = [
            "event.id == 4625",
            "event.id != 4624",
            "record_id < 2000",
            "record_id <= 1234",
            "record_id > 1000",
            "record_id >= 1234",
            "Event.EventData.TargetUserName contains \"admin\"",
            "Event.EventData.CommandLine contains_ci \"POWERSHELL\"",
            "channel in (\"Security\", \"System\")",
            "event.id in (4624, 4625)",
            "Event.EventData.Enabled == true",
            "Event.EventData.Enabled != false",
            "Event.EventData.Enabled in (false, true)",
            "provider =~ \"(?i)powershell\"",
            "provider !~ /defender/i",
            "timestamp >= \"2026-06-27T11:59:59Z\"",
            "timestamp <= \"2026-06-27T12:00:00Z\"",
            "Event.System.TimeCreated.#attributes.SystemTime == \"2026-06-27T12:00:00Z\"",
        ];

        for statement in matching_statements {
            let expression = parse_query(statement)
                .unwrap_or_else(|error| panic!("STQL should parse: {statement}: {error}"));
            assert!(
                expression.evaluate(&event),
                "STQL should match fixture: {statement}"
            );
        }
    }

    #[test]
    fn evaluates_cidr_helper_functions() {
        let event = rich_test_event();
        let matching = [
            "cidr_contains(Event.EventData.SourceIp, \"10.12.34.0/24\")",
            "ip_in_cidr(Event.EventData.SourceIp, \"10.0.0.0/8\")",
            "cidr_contains(Event.EventData.SourceIpV6, \"2001:db8::/32\")",
        ];
        let non_matching = [
            "cidr_contains(Event.EventData.SourceIp, \"192.168.0.0/16\")",
            "cidr_contains(Event.EventData.SourceIpV6, \"2001:db9::/32\")",
            "cidr_contains(Event.EventData.TargetUserName, \"10.0.0.0/8\")",
        ];

        for statement in matching {
            let expression = parse_query(statement)
                .unwrap_or_else(|error| panic!("CIDR STQL should parse: {statement}: {error}"));
            assert!(
                expression.evaluate(&event),
                "CIDR STQL should match fixture: {statement}"
            );
        }

        for statement in non_matching {
            let expression = parse_query(statement)
                .unwrap_or_else(|error| panic!("CIDR STQL should parse: {statement}: {error}"));
            assert!(
                !expression.evaluate(&event),
                "CIDR STQL should not match fixture: {statement}"
            );
        }
    }

    #[test]
    fn rejects_invalid_cidr_helpers() {
        let invalid = [
            (
                "cidr_contains(Event.EventData.SourceIp, \"10.0.0.0\")",
                QueryError::InvalidCidr {
                    value: "10.0.0.0".to_owned(),
                },
            ),
            (
                "cidr_contains(Event.EventData.SourceIp, \"10.0.0.0/33\")",
                QueryError::InvalidCidrPrefix {
                    prefix: 33,
                    family: "IPv4",
                },
            ),
            (
                "cidr_contains(Event.EventData.SourceIpV6, \"2001:db8::/129\")",
                QueryError::InvalidCidrPrefix {
                    prefix: 129,
                    family: "IPv6",
                },
            ),
        ];

        for (statement, expected) in invalid {
            let error = parse_query(statement).expect_err("invalid CIDR query should fail");
            assert_eq!(error, expected, "unexpected CIDR error for {statement}");
        }
    }

    #[test]
    fn evaluates_boolean_precedence_parentheses_and_not() {
        let event = rich_test_event();
        let matching = [
            "event.id == 1 or event.id == 4625 and channel == \"Security\"",
            "(event.id == 1 or event.id == 4625) and channel == \"Security\"",
            "not exists(Event.EventData.Missing)",
            "not (event.id == 1)",
        ];
        let non_matching = [
            "(event.id == 1 or event.id == 4625) and channel == \"System\"",
            "not (event.id == 4625)",
        ];

        for statement in matching {
            let expression = parse_query(statement)
                .unwrap_or_else(|error| panic!("STQL should parse: {statement}: {error}"));
            assert!(
                expression.evaluate(&event),
                "STQL should match fixture: {statement}"
            );
        }

        for statement in non_matching {
            let expression = parse_query(statement)
                .unwrap_or_else(|error| panic!("STQL should parse: {statement}: {error}"));
            assert!(
                !expression.evaluate(&event),
                "STQL should not match fixture: {statement}"
            );
        }
    }

    #[test]
    fn evaluates_chained_and_or_with_documented_precedence() {
        let alice_logon = rich_test_event();
        let bob_logon = test_event(json!({
            "Event": {
                "System": {
                    "EventID": 456,
                    "EventRecordID": 1234,
                    "Channel": "Security",
                    "Provider": { "Name": "Microsoft-Windows-Security-Auditing" }
                },
                "EventData": {
                    "TargetUserName": "bob.admin"
                }
            }
        }));
        let expression = parse_query(
            "event.id == 123 or event.id == 4625 and Event.EventData.TargetUserName == \"alice.admin\"",
        )
        .expect("query should parse");

        assert!(
            expression.evaluate(&alice_logon),
            "and should bind tighter than or for matching right branch"
        );
        assert!(
            !expression.evaluate(&bob_logon),
            "right branch should require both event id and user match"
        );
    }

    #[test]
    fn evaluates_arbitrarily_nested_parentheses_for_grouping() {
        let event = rich_test_event();
        let matching = [
            "((((event.id == 4625))))",
            "((event.id == 1 or (event.id == 4625 and (channel == \"Security\"))))",
            "(((event.id == 1 or event.id == 2) or ((event.id == 4625)))) and (((Event.EventData.TargetUserName == \"alice.admin\")))",
        ];
        let non_matching = [
            "((event.id == 1 or event.id == 4625) and (channel == \"System\" or Event.EventData.TargetUserName == \"bob.admin\"))",
            "(((event.id == 4625 and channel == \"System\") or (Event.EventData.TargetUserName == \"bob.admin\")))",
        ];

        for statement in matching {
            let expression = parse_query(statement)
                .unwrap_or_else(|error| panic!("nested STQL should parse: {statement}: {error}"));
            assert!(
                expression.evaluate(&event),
                "nested STQL should match fixture: {statement}"
            );
        }

        for statement in non_matching {
            let expression = parse_query(statement)
                .unwrap_or_else(|error| panic!("nested STQL should parse: {statement}: {error}"));
            assert!(
                !expression.evaluate(&event),
                "nested STQL should not match fixture: {statement}"
            );
        }
    }

    #[test]
    fn rejects_invalid_stql_syntax() {
        let invalid = [
            ("", QueryError::Empty),
            (
                "event.id = 4625",
                QueryError::UnexpectedToken {
                    token: "=".to_owned(),
                },
            ),
            ("event.id == \"unterminated", QueryError::UnterminatedString),
            ("provider =~ /unterminated", QueryError::UnterminatedRegex),
            (
                "provider =~ /powershell/x",
                QueryError::UnsupportedRegexFlag { flag: 'x' },
            ),
            (
                "event.id == 4625 extra",
                QueryError::UnexpectedToken {
                    token: "extra".to_owned(),
                },
            ),
            (
                "event.id in ()",
                QueryError::Expected {
                    expected: "literal".to_owned(),
                    found: "RightParen".to_owned(),
                },
            ),
            ("event.id == 4625 | keep", QueryError::EmptyKeep),
            (
                "event.id == 4625 | table timestamp",
                QueryError::UnsupportedPipeline {
                    command: "table".to_owned(),
                },
            ),
        ];

        for (statement, expected) in invalid {
            let error =
                parse_search_query(statement).expect_err(&format!("STQL should fail: {statement}"));
            assert_eq!(error, expected, "unexpected error for STQL: {statement}");
        }
    }

    #[test]
    fn rejects_invalid_regex_patterns() {
        let error = parse_search_query("provider =~ \"(\"").expect_err("regex should fail");

        assert!(
            matches!(
                error,
                QueryError::InvalidRegex {
                    ref pattern,
                    message: _
                } if pattern == "("
            ),
            "invalid regex should report the rejected pattern"
        );
    }

    #[test]
    fn evaluates_numeric_and_string_predicates() {
        let event = test_event(json!({
            "Event": {
                "System": { "EventID": 4625, "Channel": "Security" },
                "EventData": { "TargetUserName": "alice.admin" }
            }
        }));
        let expression = parse_query(
            "event.id == 4625 and Event.EventData.TargetUserName contains_ci \"ADMIN\"",
        )
        .expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    #[test]
    fn evaluates_exists_and_not() {
        let event = test_event(json!({ "Event": { "System": { "EventID": 1 } } }));
        let expression =
            parse_query("exists(event.id) and not exists(channel)").expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    #[test]
    fn evaluates_in_lists() {
        let event = test_event(json!({ "Event": { "System": { "EventID": 6005 } } }));
        let expression = parse_query("event.id in (6005, 6006, 6008)").expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    #[test]
    fn evaluates_quoted_regex_matches() {
        let event = test_event(json!({
            "Event": {
                "System": { "Provider": { "Name": "Microsoft-Windows-PowerShell" } }
            }
        }));
        let expression = parse_query("provider =~ \"(?i)powershell\"").expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    #[test]
    fn evaluates_slash_delimited_regex_matches() {
        let event = test_event(json!({
            "Event": {
                "System": { "Provider": { "Name": "Microsoft-Windows-PowerShell" } }
            }
        }));
        let expression = parse_query("provider =~ /powershell/i").expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    #[test]
    fn preserves_regex_escapes_and_escaped_delimiters() {
        let event = test_event(json!({
            "Event": {
                "EventData": { "CommandLine": "cmd.exe /c whoami" }
            }
        }));
        let expression = parse_query(r"Event.EventData.CommandLine =~ /cmd\.exe \/c/")
            .expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    #[test]
    fn rejects_unsupported_regex_flags() {
        let error = parse_query("provider =~ /powershell/x").expect_err("query should fail");

        assert_eq!(error, QueryError::UnsupportedRegexFlag { flag: 'x' });
    }

    #[test]
    fn evaluates_typed_timestamp_comparisons() {
        let event = test_event(json!({
            "Event": {
                "System": {
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-06-27T12:00:00Z"
                        }
                    }
                }
            }
        }));
        let expression =
            parse_query("timestamp >= \"2026-06-27T07:00:00-05:00\"").expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    #[test]
    fn parses_keep_pipeline_fields() {
        let query = parse_search_query(
            "event.id == 4624 | keep timestamp, event.id, Event.EventData.TargetUserName",
        )
        .expect("search query should parse");

        assert_eq!(
            query.keep_fields,
            vec!["timestamp", "event.id", "Event.EventData.TargetUserName"]
        );
    }

    #[test]
    fn rejects_unknown_pipeline_commands() {
        let error = parse_search_query("event.id == 4624 | table timestamp")
            .expect_err("query should fail");

        assert_eq!(
            error,
            QueryError::UnsupportedPipeline {
                command: "table".to_owned()
            }
        );
    }

    #[test]
    fn treats_offsetless_timestamps_as_utc() {
        let event = test_event(json!({
            "Event": {
                "System": {
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-06-27T12:00:00Z"
                        }
                    }
                }
            }
        }));
        let expression =
            parse_query("timestamp >= \"2026-06-27T12:00:00\"").expect("query should parse");

        assert!(expression.evaluate(&event));
    }

    fn test_event(raw: serde_json::Value) -> Event {
        let input = DiscoveredInput {
            path: PathBuf::from("fixture.evtx"),
            collection_root: PathBuf::from("."),
        };

        Event::from_raw(&input, None, raw)
    }

    fn rich_test_event() -> Event {
        test_event(json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "EventRecordID": 1234,
                    "Channel": "Security",
                    "Computer": "WIN-01",
                    "Provider": {
                        "#attributes": {
                            "Name": "Microsoft-Windows-PowerShell"
                        }
                    },
                    "TimeCreated": {
                        "#attributes": {
                            "SystemTime": "2026-06-27T12:00:00Z"
                        }
                    }
                },
                "EventData": {
                    "TargetUserName": "alice.admin",
                    "CommandLine": "cmd.exe /c powershell.exe",
                    "SourceIp": "10.12.34.56",
                    "SourceIpV6": "2001:db8::10",
                    "Enabled": true
                }
            }
        }))
    }
}
