#![forbid(unsafe_code)]

//! A small, capability-free template engine for compatible report templates.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use rustleaks_core::model::{ByteText, Finding};

use crate::{ReportError, Reporter};

/// The explicitly supported, capability-free template language.
pub const SAFE_TEMPLATE_PROFILE: &str = "rustleaks-safe-template-v1";

const MAX_TEMPLATE_NESTING: usize = 128;

/// Resource ceilings applied while parsing and rendering a template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemplateLimits {
    /// Maximum number of template source bytes.
    pub max_source_bytes: usize,
    /// Maximum number of evaluated actions and range iterations.
    pub max_actions: usize,
    /// Maximum number of bytes sent to the destination.
    pub max_output_bytes: usize,
}

impl TemplateLimits {
    /// Creates an explicit set of resource ceilings.
    #[must_use]
    pub const fn new(max_source_bytes: usize, max_actions: usize, max_output_bytes: usize) -> Self {
        Self {
            max_source_bytes,
            max_actions,
            max_output_bytes,
        }
    }
}

impl Default for TemplateLimits {
    fn default() -> Self {
        Self::new(1024 * 1024, 1_000_000, 64 * 1024 * 1024)
    }
}

/// A structured template construction or execution failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TemplateError {
    /// A path-based constructor received an empty path.
    #[error("template path cannot be empty")]
    EmptyPath,
    /// A template file could not be read.
    #[error("could not read template ({kind:?})")]
    Read {
        /// Stable I/O error classification; platform prose is intentionally omitted.
        kind: io::ErrorKind,
    },
    /// The source exceeded its configured byte ceiling.
    #[error("template source exceeds the {limit}-byte limit")]
    SourceLimit {
        /// Configured source-byte ceiling.
        limit: usize,
    },
    /// Parsing failed at a source byte offset.
    #[error("template parse error at byte {offset}: {message}")]
    Parse {
        /// Zero-based template source byte offset.
        offset: usize,
        /// Stable parser diagnostic.
        message: &'static str,
    },
    /// A helper or language feature is outside the safe profile.
    #[error(
        "template profile {SAFE_TEMPLATE_PROFILE}: function \"{name}\" not defined or unsupported at byte {offset}"
    )]
    UnsupportedFeature {
        /// The rejected helper or construct.
        name: String,
        /// Zero-based template source byte offset.
        offset: usize,
    },
    /// Execution referenced a variable, field, or deterministic value that was unavailable.
    #[error("template value {name} is unavailable")]
    MissingValue {
        /// Stable value name.
        name: String,
    },
    /// An action received an incompatible value.
    #[error("template {operation} received an incompatible value")]
    Type {
        /// Stable operation name.
        operation: &'static str,
    },
    /// Checked template arithmetic overflowed or could not represent its input.
    #[error("template arithmetic failed in {operation}")]
    Arithmetic {
        /// Stable operation name.
        operation: &'static str,
    },
    /// The action/iteration budget was exhausted.
    #[error("template exceeded the {limit}-action limit")]
    ActionLimit {
        /// Configured action ceiling.
        limit: usize,
    },
    /// The output byte budget was exhausted.
    #[error("template exceeded the {limit}-byte output limit")]
    OutputLimit {
        /// Configured output ceiling.
        limit: usize,
    },
    /// A fallible allocation failed.
    #[error("template allocation failed")]
    Allocation,
    /// The destination rejected rendered bytes.
    #[error("could not write template report: {0}")]
    Io(#[from] io::Error),
}

/// A parsed reusable reporter for [`SAFE_TEMPLATE_PROFILE`].
#[derive(Debug)]
pub struct TemplateReporter {
    nodes: Vec<Node>,
    limits: TemplateLimits,
}

impl TemplateReporter {
    /// Parses a byte-preserving template using explicit resource ceilings.
    ///
    /// # Errors
    ///
    /// Returns a structured source-limit, syntax, unsupported-feature, or
    /// allocation error.
    pub fn from_bytes(source: &[u8], limits: TemplateLimits) -> Result<Self, TemplateError> {
        if source.len() > limits.max_source_bytes {
            return Err(TemplateError::SourceLimit {
                limit: limits.max_source_bytes,
            });
        }
        let parts = scan_parts(source)?;
        let mut parser = Parser { parts, next: 0 };
        let nodes = parser.parse_nodes(false, 0)?;
        if parser.next != parser.parts.len() {
            return Err(TemplateError::Parse {
                offset: parser.parts[parser.next].offset,
                message: "unexpected trailing action",
            });
        }
        Ok(Self { nodes, limits })
    }

    /// Parses a UTF-8 template using explicit resource ceilings.
    ///
    /// Literal rendering remains byte-oriented; this is a convenience wrapper
    /// around [`Self::from_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the same structured errors as [`Self::from_bytes`].
    pub fn from_str(source: &str, limits: TemplateLimits) -> Result<Self, TemplateError> {
        Self::from_bytes(source.as_bytes(), limits)
    }

    /// Reads and parses a template without reading beyond the source ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::EmptyPath`] for an empty path and a structured
    /// read, limit, parse, or allocation error otherwise.
    pub fn from_path(
        path: impl AsRef<Path>,
        limits: TemplateLimits,
    ) -> Result<Self, TemplateError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(TemplateError::EmptyPath);
        }
        let mut file =
            File::open(path).map_err(|error| TemplateError::Read { kind: error.kind() })?;
        let mut source = Vec::new();
        let initial = limits.max_source_bytes.min(8192);
        source
            .try_reserve(initial)
            .map_err(|_| TemplateError::Allocation)?;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| TemplateError::Read { kind: error.kind() })?;
            if count == 0 {
                break;
            }
            let new_len = source
                .len()
                .checked_add(count)
                .ok_or(TemplateError::SourceLimit {
                    limit: limits.max_source_bytes,
                })?;
            if new_len > limits.max_source_bytes {
                return Err(TemplateError::SourceLimit {
                    limit: limits.max_source_bytes,
                });
            }
            source
                .try_reserve(count)
                .map_err(|_| TemplateError::Allocation)?;
            source.extend_from_slice(&buffer[..count]);
        }
        Self::from_bytes(&source, limits)
    }

    /// Returns the active ceilings.
    #[must_use]
    pub const fn limits(&self) -> TemplateLimits {
        self.limits
    }

    /// Renders findings without closing or flushing the destination.
    ///
    /// Findings and tags retain caller order and duplicates. No newline is
    /// added beyond bytes present in the template.
    ///
    /// # Errors
    ///
    /// Returns a structured execution, resource, allocation, or destination
    /// error. A destination may contain a prefix after an error.
    pub fn render(
        &self,
        writer: &mut dyn Write,
        findings: &[Finding],
    ) -> Result<(), TemplateError> {
        let mut output = CountingWriter {
            inner: writer,
            written: 0,
            limit: self.limits.max_output_bytes,
        };
        let mut state = RenderState {
            variables: Vec::new(),
            actions: 0,
            action_limit: self.limits.max_actions,
            output_limit: self.limits.max_output_bytes,
        };
        state
            .variables
            .try_reserve(variable_capacity(&self.nodes))
            .map_err(|_| TemplateError::Allocation)?;
        render_nodes(
            &self.nodes,
            &Value::Findings(findings),
            &mut state,
            &mut output,
        )
    }
}

impl Reporter for TemplateReporter {
    fn write(&self, writer: &mut dyn Write, findings: &[Finding]) -> Result<(), ReportError> {
        self.render(writer, findings).map_err(ReportError::from)
    }
}

#[derive(Debug)]
enum Node {
    Literal(Vec<u8>),
    Output(Expr),
    Assign {
        name: String,
        value: Expr,
    },
    Range {
        variables: Vec<String>,
        value: Expr,
        body: Vec<Node>,
    },
    With {
        value: Expr,
        body: Vec<Node>,
    },
    If {
        condition: Expr,
        body: Vec<Node>,
    },
}

#[derive(Debug)]
enum Expr {
    Dot,
    Field(Field),
    Variable(String),
    Integer(i64),
    Bytes(Vec<u8>),
    Call {
        helper: Helper,
        arguments: Vec<Expr>,
    },
}

#[derive(Clone, Copy, Debug)]
enum Helper {
    Len,
    Eq,
    Ne,
    Quote,
    Sub,
    Now,
    Date,
}

#[derive(Clone, Copy, Debug)]
enum Field {
    RuleId,
    Description,
    StartLine,
    EndLine,
    StartColumn,
    EndColumn,
    Line,
    Match,
    Secret,
    File,
    SymlinkFile,
    Commit,
    Link,
    Entropy,
    Author,
    Email,
    Date,
    Message,
    Tags,
    Fingerprint,
}

#[derive(Debug)]
struct Part {
    offset: usize,
    kind: PartKind,
}

#[derive(Debug)]
enum PartKind {
    Literal(Vec<u8>),
    Action(Vec<u8>),
}

fn scan_parts(source: &[u8]) -> Result<Vec<Part>, TemplateError> {
    let mut parts = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = find_bytes(&source[cursor..], b"{{") {
        let open = cursor + relative;
        push_part(
            &mut parts,
            Part {
                offset: cursor,
                kind: PartKind::Literal(copy_bytes(&source[cursor..open])?),
            },
        )?;

        let left_trim = source.get(open + 2) == Some(&b'-')
            && source
                .get(open + 3)
                .is_some_and(|byte| is_trim_space(*byte));
        if left_trim {
            if let Some(Part {
                kind: PartKind::Literal(literal),
                ..
            }) = parts.last_mut()
            {
                while literal.last().is_some_and(|byte| is_trim_space(*byte)) {
                    literal.pop();
                }
            }
        }
        let action_start = open + if left_trim { 3 } else { 2 };
        let close = find_action_close(source, action_start).ok_or(TemplateError::Parse {
            offset: open,
            message: "unclosed action",
        })?;
        let right_trim = close > action_start
            && source.get(close - 1) == Some(&b'-')
            && close
                .checked_sub(2)
                .and_then(|index| source.get(index))
                .is_some_and(|byte| is_trim_space(*byte));
        let action_end = if right_trim { close - 1 } else { close };
        push_part(
            &mut parts,
            Part {
                offset: action_start,
                kind: PartKind::Action(copy_bytes(&source[action_start..action_end])?),
            },
        )?;
        cursor = close + 2;
        if right_trim {
            while source.get(cursor).is_some_and(|byte| is_trim_space(*byte)) {
                cursor += 1;
            }
        }
    }
    push_part(
        &mut parts,
        Part {
            offset: cursor,
            kind: PartKind::Literal(copy_bytes(&source[cursor..])?),
        },
    )?;
    Ok(parts)
}

fn find_action_close(source: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    let mut quoted = false;
    let mut escaped = false;
    while cursor + 1 < source.len() {
        let byte = source[cursor];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b'}' && source[cursor + 1] == b'}' {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn is_trim_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, TemplateError> {
    let mut owned = Vec::new();
    owned
        .try_reserve(bytes.len())
        .map_err(|_| TemplateError::Allocation)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn copy_ascii(bytes: &[u8], offset: usize) -> Result<String, TemplateError> {
    if !bytes.is_ascii() {
        return Err(TemplateError::Parse {
            offset,
            message: "identifiers must be ASCII",
        });
    }
    let mut text = String::new();
    text.try_reserve(bytes.len())
        .map_err(|_| TemplateError::Allocation)?;
    text.push_str(
        std::str::from_utf8(bytes).map_err(|_| TemplateError::Parse {
            offset,
            message: "invalid identifier",
        })?,
    );
    Ok(text)
}

fn push_part(parts: &mut Vec<Part>, part: Part) -> Result<(), TemplateError> {
    parts
        .try_reserve(1)
        .map_err(|_| TemplateError::Allocation)?;
    parts.push(part);
    Ok(())
}

struct Parser {
    parts: Vec<Part>,
    next: usize,
}

impl Parser {
    fn parse_nodes(
        &mut self,
        require_end: bool,
        nesting: usize,
    ) -> Result<Vec<Node>, TemplateError> {
        let mut nodes = Vec::new();
        while self.next < self.parts.len() {
            let part = &self.parts[self.next];
            match &part.kind {
                PartKind::Literal(bytes) => {
                    push_node(&mut nodes, Node::Literal(copy_bytes(bytes)?))?;
                    self.next += 1;
                }
                PartKind::Action(bytes) => {
                    let offset = part.offset;
                    let tokens = tokenize(bytes, offset)?;
                    if tokens.is_empty() {
                        return Err(TemplateError::Parse {
                            offset,
                            message: "empty action",
                        });
                    }
                    if token_ident(&tokens[0]) == Some("end") {
                        if tokens.len() != 1 {
                            return Err(TemplateError::Parse {
                                offset,
                                message: "end action has arguments",
                            });
                        }
                        if !require_end {
                            return Err(TemplateError::Parse {
                                offset,
                                message: "unexpected end action",
                            });
                        }
                        self.next += 1;
                        return Ok(nodes);
                    }
                    if token_ident(&tokens[0]) == Some("else") {
                        return Err(unsupported("else", offset)?);
                    }
                    if matches!(
                        token_ident(&tokens[0]),
                        Some("define" | "template" | "block")
                    ) {
                        return Err(unsupported(
                            token_ident(&tokens[0]).unwrap_or("template"),
                            offset,
                        )?);
                    }
                    if token_ident(&tokens[0]) == Some("range") {
                        ensure_nesting(nesting, offset)?;
                        let (variables, value) = parse_range(&tokens[1..], offset)?;
                        self.next += 1;
                        let body = self.parse_nodes(true, nesting + 1)?;
                        push_node(
                            &mut nodes,
                            Node::Range {
                                variables,
                                value,
                                body,
                            },
                        )?;
                        continue;
                    }
                    if token_ident(&tokens[0]) == Some("with") {
                        ensure_nesting(nesting, offset)?;
                        let value = parse_expression(&tokens[1..], offset)?;
                        self.next += 1;
                        let body = self.parse_nodes(true, nesting + 1)?;
                        push_node(&mut nodes, Node::With { value, body })?;
                        continue;
                    }
                    if token_ident(&tokens[0]) == Some("if") {
                        ensure_nesting(nesting, offset)?;
                        let condition = parse_expression(&tokens[1..], offset)?;
                        self.next += 1;
                        let body = self.parse_nodes(true, nesting + 1)?;
                        push_node(&mut nodes, Node::If { condition, body })?;
                        continue;
                    }
                    let node = parse_non_block_node(&tokens, offset)?;
                    push_node(&mut nodes, node)?;
                    self.next += 1;
                }
            }
        }
        if require_end {
            return Err(TemplateError::Parse {
                offset: self.parts.last().map_or(0, |part| part.offset),
                message: "missing end action",
            });
        }
        Ok(nodes)
    }
}

fn parse_non_block_node(tokens: &[Token], offset: usize) -> Result<Node, TemplateError> {
    if tokens.len() >= 3
        && matches!(tokens[0].kind, TokenKind::Variable(_))
        && matches!(tokens[1].kind, TokenKind::Assign)
    {
        let TokenKind::Variable(name) = &tokens[0].kind else {
            unreachable!();
        };
        return Ok(Node::Assign {
            name: clone_string(name)?,
            value: parse_expression(&tokens[2..], offset)?,
        });
    }
    Ok(Node::Output(parse_expression(tokens, offset)?))
}

fn ensure_nesting(nesting: usize, offset: usize) -> Result<(), TemplateError> {
    if nesting >= MAX_TEMPLATE_NESTING {
        return Err(TemplateError::Parse {
            offset,
            message: "template nesting limit exceeded",
        });
    }
    Ok(())
}

fn push_node(nodes: &mut Vec<Node>, node: Node) -> Result<(), TemplateError> {
    nodes
        .try_reserve(1)
        .map_err(|_| TemplateError::Allocation)?;
    nodes.push(node);
    Ok(())
}

fn clone_string(source: &str) -> Result<String, TemplateError> {
    let mut value = String::new();
    value
        .try_reserve(source.len())
        .map_err(|_| TemplateError::Allocation)?;
    value.push_str(source);
    Ok(value)
}

#[derive(Debug)]
struct Token {
    kind: TokenKind,
    offset: usize,
}

#[derive(Debug)]
enum TokenKind {
    Ident(String),
    Variable(String),
    Dot(Option<String>),
    Integer(i64),
    Bytes(Vec<u8>),
    LeftParen,
    RightParen,
    Comma,
    Pipe,
    Assign,
}

fn tokenize(action: &[u8], base: usize) -> Result<Vec<Token>, TemplateError> {
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < action.len() {
        if action[cursor].is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        let offset = base + cursor;
        let (kind, consumed) = match action[cursor] {
            b'(' => (TokenKind::LeftParen, 1),
            b')' => (TokenKind::RightParen, 1),
            b',' => (TokenKind::Comma, 1),
            b'|' => (TokenKind::Pipe, 1),
            b':' if action.get(cursor + 1) == Some(&b'=') => (TokenKind::Assign, 2),
            b'"' => {
                let (value, width) = parse_string_literal(&action[cursor..], offset)?;
                (TokenKind::Bytes(value), width)
            }
            b'$' => {
                let width = 1 + identifier_width(&action[cursor + 1..]);
                if width == 1 {
                    return Err(TemplateError::Parse {
                        offset,
                        message: "empty variable name",
                    });
                }
                (
                    TokenKind::Variable(copy_ascii(&action[cursor + 1..cursor + width], offset)?),
                    width,
                )
            }
            b'.' => {
                let width = 1 + identifier_width(&action[cursor + 1..]);
                let field = if width == 1 {
                    None
                } else {
                    Some(copy_ascii(&action[cursor + 1..cursor + width], offset)?)
                };
                (TokenKind::Dot(field), width)
            }
            b'-' | b'0'..=b'9' => {
                let mut width = usize::from(action[cursor] == b'-');
                while action.get(cursor + width).is_some_and(u8::is_ascii_digit) {
                    width += 1;
                }
                if width == usize::from(action[cursor] == b'-') {
                    return Err(TemplateError::Parse {
                        offset,
                        message: "invalid integer",
                    });
                }
                let number = std::str::from_utf8(&action[cursor..cursor + width])
                    .ok()
                    .and_then(|text| text.parse::<i64>().ok())
                    .ok_or(TemplateError::Parse {
                        offset,
                        message: "integer is out of range",
                    })?;
                (TokenKind::Integer(number), width)
            }
            byte if is_identifier_start(byte) => {
                let width = identifier_width(&action[cursor..]);
                (
                    TokenKind::Ident(copy_ascii(&action[cursor..cursor + width], offset)?),
                    width,
                )
            }
            _ => {
                return Err(TemplateError::Parse {
                    offset,
                    message: "unexpected action byte",
                });
            }
        };
        tokens
            .try_reserve(1)
            .map_err(|_| TemplateError::Allocation)?;
        tokens.push(Token { kind, offset });
        cursor += consumed;
    }
    Ok(tokens)
}

fn identifier_width(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
        .count()
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn parse_string_literal(source: &[u8], offset: usize) -> Result<(Vec<u8>, usize), TemplateError> {
    let mut value = Vec::new();
    let mut cursor = 1;
    while cursor < source.len() {
        match source[cursor] {
            b'"' => return Ok((value, cursor + 1)),
            b'\\' => {
                cursor += 1;
                let escaped = *source.get(cursor).ok_or(TemplateError::Parse {
                    offset,
                    message: "unterminated string escape",
                })?;
                match escaped {
                    b'a' => push_byte(&mut value, 0x07)?,
                    b'b' => push_byte(&mut value, 0x08)?,
                    b'f' => push_byte(&mut value, 0x0c)?,
                    b'n' => push_byte(&mut value, b'\n')?,
                    b'r' => push_byte(&mut value, b'\r')?,
                    b't' => push_byte(&mut value, b'\t')?,
                    b'v' => push_byte(&mut value, 0x0b)?,
                    b'\\' | b'"' => push_byte(&mut value, escaped)?,
                    b'x' => {
                        let byte = parse_hex(&source[cursor + 1..], 2, offset)?;
                        push_byte(
                            &mut value,
                            u8::try_from(byte).map_err(|_| TemplateError::Parse {
                                offset,
                                message: "invalid byte escape",
                            })?,
                        )?;
                        cursor += 2;
                    }
                    b'u' | b'U' => {
                        let digits = if escaped == b'u' { 4 } else { 8 };
                        let scalar = parse_hex(&source[cursor + 1..], digits, offset)?;
                        let character = char::from_u32(scalar).ok_or(TemplateError::Parse {
                            offset,
                            message: "invalid Unicode escape",
                        })?;
                        let mut encoded = [0_u8; 4];
                        push_bytes(&mut value, character.encode_utf8(&mut encoded).as_bytes())?;
                        cursor += digits;
                    }
                    _ => {
                        return Err(TemplateError::Parse {
                            offset,
                            message: "unsupported string escape",
                        });
                    }
                }
                cursor += 1;
            }
            byte => {
                push_byte(&mut value, byte)?;
                cursor += 1;
            }
        }
    }
    Err(TemplateError::Parse {
        offset,
        message: "unterminated string literal",
    })
}

fn parse_hex(bytes: &[u8], digits: usize, offset: usize) -> Result<u32, TemplateError> {
    if bytes.len() < digits {
        return Err(TemplateError::Parse {
            offset,
            message: "short hexadecimal escape",
        });
    }
    let mut value = 0_u32;
    for byte in &bytes[..digits] {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a' + 10),
            b'A'..=b'F' => u32::from(byte - b'A' + 10),
            _ => {
                return Err(TemplateError::Parse {
                    offset,
                    message: "invalid hexadecimal escape",
                });
            }
        };
        value = value * 16 + digit;
    }
    Ok(value)
}

fn push_byte(bytes: &mut Vec<u8>, byte: u8) -> Result<(), TemplateError> {
    bytes
        .try_reserve(1)
        .map_err(|_| TemplateError::Allocation)?;
    bytes.push(byte);
    Ok(())
}

fn push_bytes(target: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TemplateError> {
    target
        .try_reserve(bytes.len())
        .map_err(|_| TemplateError::Allocation)?;
    target.extend_from_slice(bytes);
    Ok(())
}

fn token_ident(token: &Token) -> Option<&str> {
    match &token.kind {
        TokenKind::Ident(name) => Some(name),
        _ => None,
    }
}

fn unsupported(name: &str, offset: usize) -> Result<TemplateError, TemplateError> {
    Ok(TemplateError::UnsupportedFeature {
        name: clone_string(name)?,
        offset,
    })
}

fn parse_range(tokens: &[Token], offset: usize) -> Result<(Vec<String>, Expr), TemplateError> {
    let assignment = tokens
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Assign));
    let mut variables = Vec::new();
    let expression = if let Some(assign) = assignment {
        let names = &tokens[..assign];
        match names {
            [
                Token {
                    kind: TokenKind::Variable(name),
                    ..
                },
            ] => {
                variables
                    .try_reserve(1)
                    .map_err(|_| TemplateError::Allocation)?;
                variables.push(clone_string(name)?);
            }
            [
                Token {
                    kind: TokenKind::Variable(first),
                    ..
                },
                Token {
                    kind: TokenKind::Comma,
                    ..
                },
                Token {
                    kind: TokenKind::Variable(second),
                    ..
                },
            ] => {
                variables
                    .try_reserve(2)
                    .map_err(|_| TemplateError::Allocation)?;
                variables.push(clone_string(first)?);
                variables.push(clone_string(second)?);
            }
            _ => {
                return Err(TemplateError::Parse {
                    offset,
                    message: "invalid range variable declaration",
                });
            }
        }
        parse_expression(&tokens[assign + 1..], offset)?
    } else {
        parse_expression(tokens, offset)?
    };
    Ok((variables, expression))
}

fn parse_expression(tokens: &[Token], offset: usize) -> Result<Expr, TemplateError> {
    if tokens.is_empty() {
        return Err(TemplateError::Parse {
            offset,
            message: "missing expression",
        });
    }
    let mut cursor = ExpressionCursor {
        tokens,
        next: 0,
        nesting: 0,
    };
    let expression = cursor.parse_pipeline(false)?;
    if cursor.next != tokens.len() {
        return Err(TemplateError::Parse {
            offset: tokens[cursor.next].offset,
            message: "unexpected expression token",
        });
    }
    Ok(expression)
}

struct ExpressionCursor<'a> {
    tokens: &'a [Token],
    next: usize,
    nesting: usize,
}

impl ExpressionCursor<'_> {
    fn parse_pipeline(&mut self, nested: bool) -> Result<Expr, TemplateError> {
        let mut expression = self.parse_command(nested)?;
        while self.next < self.tokens.len()
            && matches!(self.tokens[self.next].kind, TokenKind::Pipe)
        {
            self.next += 1;
            let helper_token = self.tokens.get(self.next).ok_or(TemplateError::Parse {
                offset: self.tokens.last().map_or(0, |token| token.offset),
                message: "pipeline is missing a helper",
            })?;
            let TokenKind::Ident(name) = &helper_token.kind else {
                return Err(TemplateError::Parse {
                    offset: helper_token.offset,
                    message: "pipeline stage must be a helper",
                });
            };
            let helper = parse_helper(name, helper_token.offset)?;
            self.next += 1;
            let mut arguments = self.parse_arguments(nested)?;
            arguments
                .try_reserve(1)
                .map_err(|_| TemplateError::Allocation)?;
            arguments.push(expression);
            expression = Expr::Call { helper, arguments };
        }
        Ok(expression)
    }

    fn parse_command(&mut self, nested: bool) -> Result<Expr, TemplateError> {
        let token = self.tokens.get(self.next).ok_or(TemplateError::Parse {
            offset: 0,
            message: "missing command",
        })?;
        if let TokenKind::Ident(name) = &token.kind {
            let helper = parse_helper(name, token.offset)?;
            self.next += 1;
            let arguments = self.parse_arguments(nested)?;
            return Ok(Expr::Call { helper, arguments });
        }
        let expression = self.parse_atom()?;
        if self.next < self.tokens.len()
            && !matches!(
                self.tokens[self.next].kind,
                TokenKind::Pipe | TokenKind::RightParen
            )
        {
            return Err(TemplateError::Parse {
                offset: self.tokens[self.next].offset,
                message: "value action has extra arguments",
            });
        }
        Ok(expression)
    }

    fn parse_arguments(&mut self, nested: bool) -> Result<Vec<Expr>, TemplateError> {
        let mut arguments = Vec::new();
        while self.next < self.tokens.len()
            && !matches!(self.tokens[self.next].kind, TokenKind::Pipe)
            && !(nested && matches!(self.tokens[self.next].kind, TokenKind::RightParen))
        {
            let argument = self.parse_atom()?;
            arguments
                .try_reserve(1)
                .map_err(|_| TemplateError::Allocation)?;
            arguments.push(argument);
        }
        Ok(arguments)
    }

    fn parse_atom(&mut self) -> Result<Expr, TemplateError> {
        let token = self.tokens.get(self.next).ok_or(TemplateError::Parse {
            offset: 0,
            message: "missing value",
        })?;
        self.next += 1;
        match &token.kind {
            TokenKind::Dot(None) => Ok(Expr::Dot),
            TokenKind::Dot(Some(name)) => Ok(Expr::Field(parse_field(name, token.offset)?)),
            TokenKind::Variable(name) => Ok(Expr::Variable(clone_string(name)?)),
            TokenKind::Integer(value) => Ok(Expr::Integer(*value)),
            TokenKind::Bytes(bytes) => Ok(Expr::Bytes(copy_bytes(bytes)?)),
            TokenKind::LeftParen => {
                ensure_nesting(self.nesting, token.offset)?;
                self.nesting += 1;
                let expression = self.parse_pipeline(true)?;
                let close = self.tokens.get(self.next).ok_or(TemplateError::Parse {
                    offset: token.offset,
                    message: "unclosed parenthesized expression",
                })?;
                if !matches!(close.kind, TokenKind::RightParen) {
                    return Err(TemplateError::Parse {
                        offset: close.offset,
                        message: "expected closing parenthesis",
                    });
                }
                self.next += 1;
                self.nesting -= 1;
                Ok(expression)
            }
            _ => Err(TemplateError::Parse {
                offset: token.offset,
                message: "expected value",
            }),
        }
    }
}

fn parse_helper(name: &str, offset: usize) -> Result<Helper, TemplateError> {
    match name {
        "len" => Ok(Helper::Len),
        "eq" => Ok(Helper::Eq),
        "ne" => Ok(Helper::Ne),
        "quote" => Ok(Helper::Quote),
        "sub" => Ok(Helper::Sub),
        "now" => Ok(Helper::Now),
        "date" => Ok(Helper::Date),
        _ => Err(unsupported(name, offset)?),
    }
}

fn parse_field(name: &str, offset: usize) -> Result<Field, TemplateError> {
    match name {
        "RuleID" => Ok(Field::RuleId),
        "Description" => Ok(Field::Description),
        "StartLine" => Ok(Field::StartLine),
        "EndLine" => Ok(Field::EndLine),
        "StartColumn" => Ok(Field::StartColumn),
        "EndColumn" => Ok(Field::EndColumn),
        "Line" => Ok(Field::Line),
        "Match" => Ok(Field::Match),
        "Secret" => Ok(Field::Secret),
        "File" => Ok(Field::File),
        "SymlinkFile" => Ok(Field::SymlinkFile),
        "Commit" => Ok(Field::Commit),
        "Link" => Ok(Field::Link),
        "Entropy" => Ok(Field::Entropy),
        "Author" => Ok(Field::Author),
        "Email" => Ok(Field::Email),
        "Date" => Ok(Field::Date),
        "Message" => Ok(Field::Message),
        "Tags" => Ok(Field::Tags),
        "Fingerprint" => Ok(Field::Fingerprint),
        _ => Err(unsupported(name, offset)?),
    }
}

#[derive(Debug)]
enum Value<'a> {
    Findings(&'a [Finding]),
    Finding(&'a Finding),
    Tags(&'a [ByteText]),
    Bytes(&'a [u8]),
    Owned(Vec<u8>),
    Usize(usize),
    Integer(i64),
    Float(f32),
    Bool(bool),
    Time,
}

impl Value<'_> {
    fn try_clone(&self) -> Result<Self, TemplateError> {
        Ok(match self {
            Self::Findings(value) => Self::Findings(value),
            Self::Finding(value) => Self::Finding(value),
            Self::Tags(value) => Self::Tags(value),
            Self::Bytes(value) => Self::Bytes(value),
            Self::Owned(value) => Self::Owned(copy_bytes(value)?),
            Self::Usize(value) => Self::Usize(*value),
            Self::Integer(value) => Self::Integer(*value),
            Self::Float(value) => Self::Float(*value),
            Self::Bool(value) => Self::Bool(*value),
            Self::Time => Self::Time,
        })
    }
}

struct RenderState<'a> {
    variables: Vec<(&'a str, Value<'a>)>,
    actions: usize,
    action_limit: usize,
    output_limit: usize,
}

impl RenderState<'_> {
    fn tick(&mut self) -> Result<(), TemplateError> {
        self.actions = self
            .actions
            .checked_add(1)
            .ok_or(TemplateError::ActionLimit {
                limit: self.action_limit,
            })?;
        if self.actions > self.action_limit {
            return Err(TemplateError::ActionLimit {
                limit: self.action_limit,
            });
        }
        Ok(())
    }
}

fn render_nodes<'a>(
    nodes: &'a [Node],
    dot: &Value<'a>,
    state: &mut RenderState<'a>,
    writer: &mut CountingWriter<'_>,
) -> Result<(), TemplateError> {
    for node in nodes {
        match node {
            Node::Literal(bytes) => writer.emit(bytes)?,
            Node::Output(expression) => {
                state.tick()?;
                let value = evaluate(expression, dot, state)?;
                write_value(value, writer)?;
            }
            Node::Assign { name, value } => {
                state.tick()?;
                let value = evaluate(value, dot, state)?;
                state.variables.push((name.as_str(), value));
            }
            Node::Range {
                variables,
                value,
                body,
            } => {
                state.tick()?;
                let sequence = evaluate(value, dot, state)?;
                match sequence {
                    Value::Findings(findings) => {
                        for (index, finding) in findings.iter().enumerate() {
                            state.tick()?;
                            render_range_item(
                                variables,
                                Value::Usize(index),
                                &Value::Finding(finding),
                                body,
                                state,
                                writer,
                            )?;
                        }
                    }
                    Value::Tags(tags) => {
                        for (index, tag) in tags.iter().enumerate() {
                            state.tick()?;
                            render_range_item(
                                variables,
                                Value::Usize(index),
                                &Value::Bytes(tag.as_bytes()),
                                body,
                                state,
                                writer,
                            )?;
                        }
                    }
                    _ => {
                        return Err(TemplateError::Type { operation: "range" });
                    }
                }
            }
            Node::With { value, body } => {
                state.tick()?;
                let value = evaluate(value, dot, state)?;
                if truthy(&value) {
                    let scope = state.variables.len();
                    render_nodes(body, &value, state, writer)?;
                    state.variables.truncate(scope);
                }
            }
            Node::If { condition, body } => {
                state.tick()?;
                if truthy(&evaluate(condition, dot, state)?) {
                    let scope = state.variables.len();
                    render_nodes(body, dot, state, writer)?;
                    state.variables.truncate(scope);
                }
            }
        }
    }
    Ok(())
}

fn render_range_item<'a>(
    variables: &'a [String],
    index: Value<'a>,
    item: &Value<'a>,
    body: &'a [Node],
    state: &mut RenderState<'a>,
    writer: &mut CountingWriter<'_>,
) -> Result<(), TemplateError> {
    let scope = state.variables.len();
    match variables {
        [] => {}
        [item_name] => state
            .variables
            .push((item_name.as_str(), item.try_clone()?)),
        [index_name, item_name] => {
            state.variables.push((index_name.as_str(), index));
            state
                .variables
                .push((item_name.as_str(), item.try_clone()?));
        }
        _ => return Err(TemplateError::Type { operation: "range" }),
    }
    let result = render_nodes(body, item, state, writer);
    state.variables.truncate(scope);
    result
}

fn evaluate<'a>(
    expression: &'a Expr,
    dot: &Value<'a>,
    state: &RenderState<'a>,
) -> Result<Value<'a>, TemplateError> {
    match expression {
        Expr::Dot => dot.try_clone(),
        Expr::Field(field) => select_field(dot, *field),
        Expr::Variable(name) => {
            if let Some((_, value)) = state
                .variables
                .iter()
                .rev()
                .find(|(candidate, _)| *candidate == name)
            {
                value.try_clone()
            } else {
                Err(missing(name)?)
            }
        }
        Expr::Integer(value) => Ok(Value::Integer(*value)),
        Expr::Bytes(bytes) => Ok(Value::Bytes(bytes)),
        Expr::Call { helper, arguments } => {
            let mut values = Vec::new();
            values
                .try_reserve(arguments.len())
                .map_err(|_| TemplateError::Allocation)?;
            for argument in arguments {
                values.push(evaluate(argument, dot, state)?);
            }
            evaluate_helper(*helper, &values, state.output_limit)
        }
    }
}

fn missing(name: &str) -> Result<TemplateError, TemplateError> {
    Ok(TemplateError::MissingValue {
        name: clone_string(name)?,
    })
}

fn select_field<'a>(value: &Value<'a>, field: Field) -> Result<Value<'a>, TemplateError> {
    let Value::Finding(finding) = value else {
        return Err(TemplateError::Type {
            operation: "field selection",
        });
    };
    let location = finding.location();
    Ok(match field {
        Field::RuleId => Value::Bytes(finding.rule_id().as_bytes()),
        Field::Description => Value::Bytes(finding.description().as_bytes()),
        Field::StartLine => Value::Usize(location.start_line()),
        Field::EndLine => Value::Usize(location.end_line()),
        Field::StartColumn => Value::Usize(location.start_column()),
        Field::EndColumn => Value::Usize(location.end_column()),
        Field::Line => Value::Bytes(finding.line().as_bytes()),
        Field::Match => Value::Bytes(finding.match_text().as_bytes()),
        Field::Secret => Value::Bytes(finding.secret().as_bytes()),
        Field::File => Value::Bytes(finding.file().as_bytes()),
        Field::SymlinkFile => Value::Bytes(finding.symlink_file().as_bytes()),
        Field::Commit => Value::Bytes(finding.commit().as_bytes()),
        Field::Link => Value::Bytes(finding.link().as_bytes()),
        Field::Entropy => Value::Float(finding.entropy()),
        Field::Author => Value::Bytes(finding.author().as_bytes()),
        Field::Email => Value::Bytes(finding.email().as_bytes()),
        Field::Date => Value::Bytes(finding.date().as_bytes()),
        Field::Message => Value::Bytes(finding.message().as_bytes()),
        Field::Tags => Value::Tags(finding.tags()),
        Field::Fingerprint => Value::Bytes(finding.fingerprint().as_bytes()),
    })
}

fn evaluate_helper<'a>(
    helper: Helper,
    arguments: &[Value<'a>],
    output_limit: usize,
) -> Result<Value<'a>, TemplateError> {
    match helper {
        Helper::Len => match arguments {
            [Value::Findings(values)] => usize_to_integer(values.len(), "len"),
            [Value::Tags(values)] => usize_to_integer(values.len(), "len"),
            [Value::Bytes(values)] => usize_to_integer(values.len(), "len"),
            [Value::Owned(values)] => usize_to_integer(values.len(), "len"),
            _ => Err(TemplateError::Type { operation: "len" }),
        },
        Helper::Sub => match arguments {
            [left, right] => {
                let left = integer(left, "sub")?;
                let right = integer(right, "sub")?;
                left.checked_sub(right)
                    .map(Value::Integer)
                    .ok_or(TemplateError::Arithmetic { operation: "sub" })
            }
            _ => Err(TemplateError::Type { operation: "sub" }),
        },
        Helper::Eq | Helper::Ne => match arguments {
            [left, right] => {
                let equal = values_equal(left, right)?;
                Ok(Value::Bool(if matches!(helper, Helper::Eq) {
                    equal
                } else {
                    !equal
                }))
            }
            _ => Err(TemplateError::Type {
                operation: if matches!(helper, Helper::Eq) {
                    "eq"
                } else {
                    "ne"
                },
            }),
        },
        Helper::Quote => match arguments {
            [value] => Ok(Value::Owned(go_quote(
                value_bytes(value, "quote")?,
                output_limit,
            )?)),
            _ => Err(TemplateError::Type { operation: "quote" }),
        },
        Helper::Now => {
            if arguments.is_empty() {
                Ok(Value::Time)
            } else {
                Err(TemplateError::Type { operation: "now" })
            }
        }
        Helper::Date => match arguments {
            [Value::Bytes(_) | Value::Owned(_), Value::Time] => Err(missing("injected clock")?),
            _ => Err(TemplateError::Type { operation: "date" }),
        },
    }
}

fn usize_to_integer(
    value: usize,
    operation: &'static str,
) -> Result<Value<'static>, TemplateError> {
    i64::try_from(value)
        .map(Value::Integer)
        .map_err(|_| TemplateError::Arithmetic { operation })
}

fn integer(value: &Value<'_>, operation: &'static str) -> Result<i64, TemplateError> {
    match value {
        Value::Integer(value) => Ok(*value),
        Value::Usize(value) => {
            i64::try_from(*value).map_err(|_| TemplateError::Arithmetic { operation })
        }
        _ => Err(TemplateError::Type { operation }),
    }
}

fn values_equal(left: &Value<'_>, right: &Value<'_>) -> Result<bool, TemplateError> {
    match (left, right) {
        (Value::Integer(left), Value::Integer(right)) => Ok(left == right),
        (Value::Usize(left), Value::Usize(right)) => Ok(left == right),
        (Value::Integer(left), Value::Usize(right))
        | (Value::Usize(right), Value::Integer(left)) => {
            Ok(i64::try_from(*right).is_ok_and(|right| *left == right))
        }
        (Value::Bytes(left), Value::Bytes(right)) => Ok(left == right),
        (Value::Owned(left), Value::Owned(right)) => Ok(left == right),
        (Value::Bytes(left), Value::Owned(right)) | (Value::Owned(right), Value::Bytes(left)) => {
            Ok(*left == right.as_slice())
        }
        (Value::Bool(left), Value::Bool(right)) => Ok(left == right),
        _ => Err(TemplateError::Type { operation: "eq/ne" }),
    }
}

fn value_bytes<'a>(
    value: &'a Value<'a>,
    operation: &'static str,
) -> Result<&'a [u8], TemplateError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        Value::Owned(bytes) => Ok(bytes),
        _ => Err(TemplateError::Type { operation }),
    }
}

fn truthy(value: &Value<'_>) -> bool {
    match value {
        Value::Findings(values) => !values.is_empty(),
        Value::Finding(_) | Value::Time => true,
        Value::Tags(values) => !values.is_empty(),
        Value::Bytes(values) => !values.is_empty(),
        Value::Owned(values) => !values.is_empty(),
        Value::Usize(value) => *value != 0,
        Value::Integer(value) => *value != 0,
        Value::Float(value) => *value != 0.0,
        Value::Bool(value) => *value,
    }
}

fn write_value(value: Value<'_>, writer: &mut CountingWriter<'_>) -> Result<(), TemplateError> {
    match value {
        Value::Bytes(bytes) => writer.emit(bytes),
        Value::Owned(bytes) => writer.emit(&bytes),
        Value::Usize(value) => writer.emit(value.to_string().as_bytes()),
        Value::Integer(value) => writer.emit(value.to_string().as_bytes()),
        Value::Float(value) => writer.emit(value.to_string().as_bytes()),
        Value::Bool(value) => writer.emit(if value { b"true" } else { b"false" }),
        _ => Err(TemplateError::Type {
            operation: "render",
        }),
    }
}

fn go_quote(bytes: &[u8], output_limit: usize) -> Result<Vec<u8>, TemplateError> {
    let maximum = bytes
        .len()
        .checked_mul(4)
        .and_then(|value| value.checked_add(2))
        .ok_or(TemplateError::OutputLimit {
            limit: output_limit,
        })?;
    if maximum > output_limit && bytes.len() > output_limit {
        return Err(TemplateError::OutputLimit {
            limit: output_limit,
        });
    }
    let mut quoted = Vec::new();
    quoted
        .try_reserve(maximum.min(output_limit))
        .map_err(|_| TemplateError::Allocation)?;
    push_limited(&mut quoted, b'"', output_limit)?;
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                append_quoted_valid(&mut quoted, valid, output_limit)?;
                break;
            }
            Err(error) => {
                let valid =
                    std::str::from_utf8(&remaining[..error.valid_up_to()]).map_err(|_| {
                        TemplateError::Type {
                            operation: "quote UTF-8",
                        }
                    })?;
                append_quoted_valid(&mut quoted, valid, output_limit)?;
                append_escape_byte(&mut quoted, remaining[error.valid_up_to()], output_limit)?;
                remaining = &remaining[error.valid_up_to() + 1..];
            }
        }
    }
    push_limited(&mut quoted, b'"', output_limit)?;
    Ok(quoted)
}

fn append_quoted_valid(
    output: &mut Vec<u8>,
    valid: &str,
    limit: usize,
) -> Result<(), TemplateError> {
    for character in valid.chars() {
        match character {
            '"' => append_limited(output, b"\\\"", limit)?,
            '\\' => append_limited(output, b"\\\\", limit)?,
            '\u{7}' => append_limited(output, b"\\a", limit)?,
            '\u{8}' => append_limited(output, b"\\b", limit)?,
            '\u{c}' => append_limited(output, b"\\f", limit)?,
            '\n' => append_limited(output, b"\\n", limit)?,
            '\r' => append_limited(output, b"\\r", limit)?,
            '\t' => append_limited(output, b"\\t", limit)?,
            '\u{b}' => append_limited(output, b"\\v", limit)?,
            character if character == ' ' || is_go_print(character) => {
                let mut bytes = [0_u8; 4];
                append_limited(output, character.encode_utf8(&mut bytes).as_bytes(), limit)?;
            }
            character if u32::from(character) <= 0xff => {
                append_hex_escape(output, b'x', u32::from(character), 2, limit)?;
            }
            character if u32::from(character) <= 0xffff => {
                append_hex_escape(output, b'u', u32::from(character), 4, limit)?;
            }
            character => {
                append_hex_escape(output, b'U', u32::from(character), 8, limit)?;
            }
        }
    }
    Ok(())
}

fn is_go_print(character: char) -> bool {
    let scalar = u32::from(character);
    // Rust's generated printable table cheaply rejects unassigned/private
    // scalars. The exclusions below then pin separator and format categories
    // to Go's strconv.IsPrint behavior instead of Rust Debug's presentation.
    let mut escaped = character.escape_debug();
    if escaped.next() != Some(character) || escaped.next().is_some() || character.is_control() {
        return false;
    }
    !matches!(
        scalar,
        0x00a0 | 0x00ad | 0x0600..=0x0605 | 0x061c | 0x06dd | 0x070f
            | 0x0890..=0x0891 | 0x08e2 | 0x1680 | 0x180e | 0x2000..=0x200f
            | 0x2028..=0x202f | 0x205f..=0x2064 | 0x2066..=0x206f | 0x3000
            | 0xd800..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd
            | 0x13430..=0x1343f | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a
            | 0xe0001 | 0xe0020..=0xe007f | 0xf0000..=0xffffd
            | 0x0010_0000..=0x0010_fffd
    )
}

fn append_escape_byte(output: &mut Vec<u8>, byte: u8, limit: usize) -> Result<(), TemplateError> {
    append_hex_escape(output, b'x', u32::from(byte), 2, limit)
}

fn append_hex_escape(
    output: &mut Vec<u8>,
    prefix: u8,
    value: u32,
    digits: usize,
    limit: usize,
) -> Result<(), TemplateError> {
    append_limited(output, b"\\", limit)?;
    push_limited(output, prefix, limit)?;
    for shift in (0..digits).rev() {
        let digit = ((value >> (shift * 4)) & 0xf) as u8;
        push_limited(
            output,
            if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            },
            limit,
        )?;
    }
    Ok(())
}

fn push_limited(output: &mut Vec<u8>, byte: u8, limit: usize) -> Result<(), TemplateError> {
    if output.len() >= limit {
        return Err(TemplateError::OutputLimit { limit });
    }
    output
        .try_reserve(1)
        .map_err(|_| TemplateError::Allocation)?;
    output.push(byte);
    Ok(())
}

fn append_limited(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), TemplateError> {
    let new_len = output
        .len()
        .checked_add(bytes.len())
        .ok_or(TemplateError::OutputLimit { limit })?;
    if new_len > limit {
        return Err(TemplateError::OutputLimit { limit });
    }
    output
        .try_reserve(bytes.len())
        .map_err(|_| TemplateError::Allocation)?;
    output.extend_from_slice(bytes);
    Ok(())
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    written: usize,
    limit: usize,
}

impl CountingWriter<'_> {
    fn emit(&mut self, bytes: &[u8]) -> Result<(), TemplateError> {
        let new_total = self
            .written
            .checked_add(bytes.len())
            .ok_or(TemplateError::OutputLimit { limit: self.limit })?;
        if new_total > self.limit {
            return Err(TemplateError::OutputLimit { limit: self.limit });
        }
        self.inner.write_all(bytes)?;
        self.written = new_total;
        Ok(())
    }
}

fn variable_capacity(nodes: &[Node]) -> usize {
    fn visit(nodes: &[Node], count: &mut usize) {
        for node in nodes {
            match node {
                Node::Assign { .. } => *count = count.saturating_add(1),
                Node::Range {
                    variables, body, ..
                } => {
                    *count = count.saturating_add(variables.len());
                    visit(body, count);
                }
                Node::With { body, .. } | Node::If { body, .. } => visit(body, count),
                Node::Literal(_) | Node::Output(_) => {}
            }
        }
    }
    let mut count = 0;
    visit(nodes, &mut count);
    count
}

impl fmt::Display for TemplateReporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SAFE_TEMPLATE_PROFILE)
    }
}
