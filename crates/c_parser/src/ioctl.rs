// SPDX-License-Identifier: Apache-2.0
//! What a driver's ioctl interface is made of, as its C source spells it:
//! object-like macros (the `_IOW(...)` command numbers and the constants they
//! use), struct and union definitions with what their layout depends on
//! (packing, bit-field widths, anonymous members), designated initializers
//! (`.unlocked_ioctl = widget_ioctl` in a `struct file_operations`), and, per
//! function, the `switch`es it dispatches with and the calls it makes.
//!
//! This module only records what the source says; `bhf kernel syzlang`
//! decides what it means. Kernel annotations (`__user`, `__iomem`, `__packed`,
//! ...) are masked before parsing so tree-sitter sees plain C, with byte
//! offsets and line numbers unchanged.

use crate::{
    bit_field_width, collect_type_defs, field_descriptor, function_identifier, function_params,
    is_c_keyword, macro_wrapped_name, strip_c_comments, type_identifier_text,
    typedef_underlying_text, AstDepthGuard, CEnumDef, CParamDescriptor, CParseError, CTypeDefs,
    CTypedefDef,
};

/// Everything [`parse_ioctl_facts`] found in one source file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CIoctlFacts {
    pub macros: Vec<CMacroDef>,
    pub records: Vec<CRecordDef>,
    pub typedefs: Vec<CTypedefDef>,
    pub enums: Vec<CEnumDef>,
    pub initializers: Vec<CInitializer>,
    pub functions: Vec<CDispatchFunction>,
}

/// An object-like `#define NAME value`, continuation lines joined, comments
/// dropped and whitespace collapsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CMacroDef {
    pub name: String,
    pub value: String,
    pub line: u32,
}

/// A struct or union definition (one with a body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CRecordDef {
    /// The tag, or the typedef name of an anonymous `typedef struct { } T;`.
    /// A record nested anonymously in another is named
    /// `<outer>.<member>`, or `<outer>.anon<N>` when it has no member name
    /// (a C11 anonymous struct or union): a name no C identifier can take.
    pub name: String,
    pub union: bool,
    /// `__packed`, `__attribute__((packed))` or `__attribute__((__packed__))`
    /// on the definition.
    pub packed: bool,
    pub fields: Vec<CRecordField>,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CRecordField {
    /// `None` for an unnamed bit-field (`__u32 : 3;`) and for an anonymous
    /// struct or union member.
    pub name: Option<String>,
    /// As the type model spells member types: `__u32`, `char[16]`,
    /// `void *`, `struct widget_cfg`, `union widget_xfer.anon0`.
    pub c_type: String,
    /// The width expression of a bit-field (`4`, `WIDGET_BITS`).
    pub bit_width: Option<String>,
}

/// A variable defined with a brace initializer, and its designated members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CInitializer {
    pub variable: String,
    /// The declared type, qualifiers and storage class left out
    /// (`struct file_operations`).
    pub type_name: String,
    pub line: u32,
    /// `.member = value` pairs, in source order. Positional elements and
    /// nested designators (`.a.b = x`, `[3] = x`) are left out.
    pub fields: Vec<(String, CValue)>,
}

/// An initializer value or call argument, as far as its shape says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CValue {
    Identifier(String),
    /// `&name`.
    AddressOf(String),
    /// A string literal (adjacent literals concatenated), unescaped.
    String(String),
    /// Anything else, as written (whitespace collapsed).
    Other(String),
}

/// A function definition and how it dispatches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CDispatchFunction {
    pub name: String,
    pub line: u32,
    pub params: Vec<CParamDescriptor>,
    /// Every `switch` in the body, in source order (an outer one before
    /// the ones nested in it).
    pub switches: Vec<CSwitch>,
    /// Calls of a named function in the body, in source order.
    pub calls: Vec<CCall>,
}

/// A `switch` statement: what it switches on and its own `case` labels
/// (not those of a `switch` nested in it), whitespace collapsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSwitch {
    pub condition: String,
    pub case_labels: Vec<String>,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CCall {
    pub callee: String,
    pub args: Vec<CValue>,
    pub line: u32,
}

/// The facts of one C source file. Fails only when tree-sitter cannot run;
/// code it cannot parse contributes what it can.
pub fn parse_ioctl_facts(source: &str) -> Result<CIoctlFacts, CParseError> {
    let masked = mask_kernel_annotations(source);
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .map_err(|_| CParseError::Grammar)?;
    let tree = parser.parse(&masked, None).ok_or(CParseError::Parse)?;
    let root = tree.root_node();
    let bytes = masked.as_bytes();

    let mut defs = CTypeDefs::default();
    collect_type_defs(root, bytes, &mut defs);
    let mut facts = CIoctlFacts {
        macros: object_macros(source),
        typedefs: defs.typedefs,
        enums: defs.enums,
        ..CIoctlFacts::default()
    };
    let context = Walk {
        source: bytes,
        original: source.as_bytes(),
    };
    context.collect(root, &mut facts);
    Ok(facts)
}

/// Kernel annotations that are empty (or attribute-only) to the compiler.
const KERNEL_ANNOTATIONS: &[&str] = &[
    "__user",
    "__kernel",
    "__iomem",
    "__force",
    "__rcu",
    "__percpu",
    "__bitwise",
    "__must_check",
    "__init",
    "__exit",
    "__initdata",
    "__initconst",
    "__ro_after_init",
    "__read_mostly",
    "__always_inline",
    "__maybe_unused",
    "__always_unused",
    "__cold",
    "__noreturn",
    "__randomize_layout",
    "__packed",
    "notrace",
];

/// Kernel annotations that take an argument list (`__aligned(8)`).
const KERNEL_ANNOTATION_CALLS: &[&str] = &[
    "__aligned",
    "__counted_by",
    "__section",
    "__printf",
    "__cleanup",
    "__must_hold",
    "__acquires",
    "__releases",
    "__nonstring",
];

/// `source` with the [`KERNEL_ANNOTATIONS`] (and the argument lists of the
/// [`KERNEL_ANNOTATION_CALLS`]) outside comments and literals replaced by
/// spaces, so every byte offset and line stays where it was.
fn mask_kernel_annotations(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        match b {
            b'/' if next == Some(b'*') => {
                i = find_from(bytes, i + 2, b"*/").map_or(bytes.len(), |end| end + 2);
            }
            b'/' if next == Some(b'/') => {
                i = bytes[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(bytes.len(), |at| i + at);
            }
            b'"' | b'\'' => i = skip_literal(bytes, i),
            _ if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &source[start..i];
                if KERNEL_ANNOTATIONS.contains(&word) {
                    blank(&mut out, start, i);
                } else if KERNEL_ANNOTATION_CALLS.contains(&word) {
                    let mut end = i;
                    while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                        end += 1;
                    }
                    if bytes.get(end) == Some(&b'(') {
                        if let Some(close) = matching_paren(bytes, end) {
                            blank(&mut out, start, close + 1);
                            i = close + 1;
                            continue;
                        }
                    }
                    blank(&mut out, start, i);
                }
            }
            _ => i += 1,
        }
    }
    // Only ASCII bytes were replaced by ASCII spaces, so the text stays UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| source.to_owned())
}

fn blank(out: &mut [u8], start: usize, end: usize) {
    for byte in &mut out[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn find_from(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| from + at)
}

/// The index just past the string or character literal starting at `start`.
fn skip_literal(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'\n' => return i,
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// The `)` that closes the `(` at `open`, outside literals.
fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                i = skip_literal(bytes, i);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\n' if depth > 64 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

/// The object-like `#define`s of `source`.
fn object_macros(source: &str) -> Vec<CMacroDef> {
    let stripped = strip_c_comments(source);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut macros = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let start = index;
        let mut text = lines[index].trim_end().to_owned();
        while text.ends_with('\\') && index + 1 < lines.len() {
            text.pop();
            index += 1;
            text.push(' ');
            text.push_str(lines[index].trim_end());
        }
        index += 1;
        let Some(rest) = text.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start();
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, value) = rest.split_at(name_len);
        // A function-like macro has its `(` right after the name.
        if name.is_empty()
            || name.starts_with(|c: char| c.is_ascii_digit())
            || value.starts_with('(')
        {
            continue;
        }
        macros.push(CMacroDef {
            name: name.to_owned(),
            value: collapse(value),
            line: u32::try_from(start + 1).unwrap_or(u32::MAX),
        });
    }
    macros
}

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn line_of(node: tree_sitter::Node<'_>) -> u32 {
    u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX)
}

/// One parsed file: the masked text tree-sitter parsed, and the original
/// (for the packing annotations the mask removed).
struct Walk<'a> {
    source: &'a [u8],
    original: &'a [u8],
}

impl Walk<'_> {
    fn text(&self, node: tree_sitter::Node<'_>) -> String {
        node.utf8_text(self.source)
            .map(collapse)
            .unwrap_or_default()
    }

    fn collect(&self, node: tree_sitter::Node<'_>, facts: &mut CIoctlFacts) {
        let Some(_depth_guard) = AstDepthGuard::enter() else {
            return;
        };
        match node.kind() {
            "struct_specifier" | "union_specifier" => {
                if let Some(name) = self.record_name(node) {
                    self.record(node, name, &mut facts.records);
                }
            }
            "function_definition" => {
                if let Some(function) = self.function(node) {
                    facts.functions.push(function);
                }
            }
            "declaration" => self.initializers(node, &mut facts.initializers),
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect(child, facts);
        }
    }

    /// The name of a top-level record definition: its tag, or the alias of
    /// `typedef struct { } alias;`. Anonymous records nested in another are
    /// named by [`Self::record`] of the outer one.
    fn record_name(&self, node: tree_sitter::Node<'_>) -> Option<String> {
        node.child_by_field_name("body")?;
        if let Some(tag) = node.child_by_field_name("name") {
            let tag = self.text(tag);
            return (!tag.is_empty() && !is_c_keyword(&tag)).then_some(tag);
        }
        let parent = node.parent()?;
        if parent.kind() != "type_definition"
            || parent.child_by_field_name("type").map(|t| t.id()) != Some(node.id())
        {
            return None;
        }
        let alias = type_identifier_text(parent.child_by_field_name("declarator")?, self.source)?;
        (!is_c_keyword(&alias)).then_some(alias)
    }

    /// Record the definition `node` under `name`, and the anonymous records
    /// nested in it.
    fn record(&self, node: tree_sitter::Node<'_>, name: String, records: &mut Vec<CRecordDef>) {
        let Some(_depth_guard) = AstDepthGuard::enter() else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let at = records.len();
        records.push(CRecordDef {
            name: name.clone(),
            union: node.kind() == "union_specifier",
            packed: self.packed(node, body),
            fields: Vec::new(),
            line: line_of(node),
        });
        let mut fields = Vec::new();
        let mut anonymous = 0usize;
        let mut cursor = body.walk();
        for member in body.children(&mut cursor) {
            if member.kind() != "field_declaration" {
                continue;
            }
            let Some(type_node) = member.child_by_field_name("type") else {
                continue;
            };
            let bit_width = bit_field_width(member, self.source);
            let mut declarators = Vec::new();
            let mut members = member.walk();
            for part in member.children(&mut members) {
                if matches!(
                    part.kind(),
                    "field_identifier"
                        | "pointer_declarator"
                        | "array_declarator"
                        | "function_declarator"
                ) {
                    declarators.push(part);
                }
            }
            let nested = matches!(type_node.kind(), "struct_specifier" | "union_specifier")
                && type_node.child_by_field_name("body").is_some();
            let base_type = if nested {
                let keyword = if type_node.kind() == "union_specifier" {
                    "union"
                } else {
                    "struct"
                };
                let nested_name = match type_node.child_by_field_name("name") {
                    // A named nested definition is a top-level record of its
                    // own; the walk records it.
                    Some(tag) => self.text(tag),
                    None => {
                        let member_name = declarators
                            .first()
                            .and_then(|part| field_descriptor(*part, self.source, "int"))
                            .map(|descriptor| descriptor.name);
                        let nested_name = match member_name {
                            Some(member_name) => format!("{name}.{member_name}"),
                            None => {
                                anonymous += 1;
                                format!("{name}.anon{}", anonymous - 1)
                            }
                        };
                        self.record(type_node, nested_name.clone(), records);
                        nested_name
                    }
                };
                format!("{keyword} {nested_name}")
            } else {
                collapse(&typedef_underlying_text(
                    type_node.utf8_text(self.source).unwrap_or_default(),
                ))
            };
            if base_type.is_empty() {
                continue;
            }
            if declarators.is_empty() {
                // An unnamed bit-field, or an anonymous struct or union whose
                // members belong to the enclosing record.
                if bit_width.is_some() || nested {
                    fields.push(CRecordField {
                        name: None,
                        c_type: base_type,
                        bit_width,
                    });
                }
                continue;
            }
            for part in declarators {
                if let Some(descriptor) = field_descriptor(part, self.source, &base_type) {
                    fields.push(CRecordField {
                        // tree-sitter recovers `__u8 : 4;` with an empty
                        // (missing) member name.
                        name: Some(descriptor.name).filter(|name| !name.is_empty()),
                        c_type: collapse(&descriptor.c_type),
                        bit_width: bit_width.clone(),
                    });
                }
            }
        }
        records[at].fields = fields;
    }

    /// Whether the definition is packed: `__packed` or a `packed` attribute
    /// between `struct` and the body, or between the body and the end of the
    /// declaration. Read from the original text, before the mask.
    fn packed(&self, node: tree_sitter::Node<'_>, body: tree_sitter::Node<'_>) -> bool {
        let before = &self.original[node.start_byte()..body.start_byte()];
        let after_end = self.original[body.end_byte()..]
            .iter()
            .position(|&b| matches!(b, b';' | b'{' | b'}'))
            .map_or(self.original.len(), |at| body.end_byte() + at);
        let after = &self.original[body.end_byte()..after_end];
        names_packing(before) || names_packing(after)
    }

    fn function(&self, node: tree_sitter::Node<'_>) -> Option<CDispatchFunction> {
        let declarator = node.child_by_field_name("declarator")?;
        let name = macro_wrapped_name(declarator, self.source).or_else(|| {
            function_identifier(declarator)
                .and_then(|id| id.utf8_text(self.source).ok().map(str::to_owned))
        })?;
        if is_c_keyword(&name) {
            return None;
        }
        let mut function = CDispatchFunction {
            line: function_identifier(declarator).map_or_else(|| line_of(node), line_of),
            name,
            params: function_params(declarator, self.source),
            switches: Vec::new(),
            calls: Vec::new(),
        };
        if let Some(body) = node.child_by_field_name("body") {
            self.body(body, &mut function);
        }
        Some(function)
    }

    fn body(&self, node: tree_sitter::Node<'_>, function: &mut CDispatchFunction) {
        let Some(_depth_guard) = AstDepthGuard::enter() else {
            return;
        };
        match node.kind() {
            "switch_statement" => {
                let condition = node
                    .child_by_field_name("condition")
                    .map(|condition| self.text(condition))
                    .unwrap_or_default();
                let condition = condition
                    .strip_prefix('(')
                    .and_then(|inner| inner.strip_suffix(')'))
                    .map_or(condition.clone(), |inner| inner.trim().to_owned());
                let mut case_labels = Vec::new();
                if let Some(body) = node.child_by_field_name("body") {
                    self.case_labels(body, &mut case_labels);
                }
                function.switches.push(CSwitch {
                    condition,
                    case_labels,
                    line: line_of(node),
                });
            }
            "call_expression" => {
                let callee = node
                    .child_by_field_name("function")
                    .filter(|callee| callee.kind() == "identifier")
                    .map(|callee| self.text(callee));
                if let Some(callee) = callee {
                    let mut args = Vec::new();
                    if let Some(list) = node.child_by_field_name("arguments") {
                        let mut cursor = list.walk();
                        for arg in list.named_children(&mut cursor) {
                            if arg.kind() != "comment" {
                                args.push(self.value(arg));
                            }
                        }
                    }
                    function.calls.push(CCall {
                        callee,
                        args,
                        line: line_of(node),
                    });
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.body(child, function);
        }
    }

    /// The `case` labels under `node` that belong to the `switch` whose body
    /// it is.
    fn case_labels(&self, node: tree_sitter::Node<'_>, labels: &mut Vec<String>) {
        let Some(_depth_guard) = AstDepthGuard::enter() else {
            return;
        };
        if node.kind() == "case_statement" {
            if let Some(value) = node.child_by_field_name("value") {
                labels.push(self.text(value));
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "switch_statement" {
                self.case_labels(child, labels);
            }
        }
    }

    fn initializers(&self, node: tree_sitter::Node<'_>, out: &mut Vec<CInitializer>) {
        let Some(type_node) = node.child_by_field_name("type") else {
            return;
        };
        let type_name = collapse(&typedef_underlying_text(
            type_node.utf8_text(self.source).unwrap_or_default(),
        ));
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "init_declarator" {
                continue;
            }
            let (Some(declarator), Some(value)) = (
                child.child_by_field_name("declarator"),
                child.child_by_field_name("value"),
            ) else {
                continue;
            };
            if declarator.kind() != "identifier" || value.kind() != "initializer_list" {
                continue;
            }
            let mut fields = Vec::new();
            let mut pairs = value.walk();
            for pair in value.named_children(&mut pairs) {
                if pair.kind() != "initializer_pair" {
                    continue;
                }
                let mut designators = pair
                    .children_by_field_name("designator", &mut pair.walk())
                    .collect::<Vec<_>>()
                    .into_iter();
                let (Some(designator), None) = (designators.next(), designators.next()) else {
                    continue;
                };
                if designator.kind() != "field_designator" {
                    continue;
                }
                let Some(member) = designator.named_child(0) else {
                    continue;
                };
                let Some(member_value) = pair.child_by_field_name("value") else {
                    continue;
                };
                fields.push((self.text(member), self.value(member_value)));
            }
            out.push(CInitializer {
                variable: self.text(declarator),
                type_name: type_name.clone(),
                line: line_of(node),
                fields,
            });
        }
    }

    fn value(&self, node: tree_sitter::Node<'_>) -> CValue {
        match node.kind() {
            "identifier" => CValue::Identifier(self.text(node)),
            "pointer_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| self.text(op) == "&") =>
            {
                match node.child_by_field_name("argument") {
                    Some(argument) if argument.kind() == "identifier" => {
                        CValue::AddressOf(self.text(argument))
                    }
                    _ => CValue::Other(self.text(node)),
                }
            }
            "string_literal" => string_value(node, self.source)
                .map_or_else(|| CValue::Other(self.text(node)), CValue::String),
            "concatenated_string" => {
                let mut text = String::new();
                let mut cursor = node.walk();
                for part in node.named_children(&mut cursor) {
                    match (part.kind(), string_value(part, self.source)) {
                        ("string_literal", Some(piece)) => text.push_str(&piece),
                        _ => return CValue::Other(self.text(node)),
                    }
                }
                CValue::String(text)
            }
            _ => CValue::Other(self.text(node)),
        }
    }
}

fn string_value(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    crate::c_string_literal_value(node.utf8_text(source).ok()?)
}

/// Whether declaration text outside a record body packs the record:
/// `__packed`, or `packed`/`__packed__` inside an `__attribute__`.
fn names_packing(text: &[u8]) -> bool {
    let text = String::from_utf8_lossy(text);
    let words: Vec<&str> = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect();
    words.contains(&"__packed")
        || (words
            .iter()
            .any(|word| *word == "__attribute__" || *word == "__attribute")
            && words
                .iter()
                .any(|word| *word == "packed" || *word == "__packed__"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: Option<&str>, c_type: &str, bit_width: Option<&str>) -> CRecordField {
        CRecordField {
            name: name.map(str::to_owned),
            c_type: c_type.to_owned(),
            bit_width: bit_width.map(str::to_owned),
        }
    }

    fn record<'a>(facts: &'a CIoctlFacts, name: &str) -> &'a CRecordDef {
        facts
            .records
            .iter()
            .find(|record| record.name == name)
            .unwrap_or_else(|| panic!("no record {name}: {:#?}", facts.records))
    }

    #[test]
    fn object_like_macros_join_continuations_and_drop_comments() {
        let src = "#define WIDGET_IOC_MAGIC 'W' /* the type byte */\n\
                   #define WIDGET_IOC_SET_CONFIG _IOW(WIDGET_IOC_MAGIC, 1, \\\n\
                   \tstruct widget_config) // set it\n\
                   #define widget_max(a, b) ((a) > (b) ? (a) : (b))\n\
                   #  define WIDGET_NAME_LEN   16\n";
        let facts = parse_ioctl_facts(src).unwrap();
        assert_eq!(
            facts.macros,
            vec![
                CMacroDef {
                    name: "WIDGET_IOC_MAGIC".into(),
                    value: "'W'".into(),
                    line: 1,
                },
                CMacroDef {
                    name: "WIDGET_IOC_SET_CONFIG".into(),
                    value: "_IOW(WIDGET_IOC_MAGIC, 1, struct widget_config)".into(),
                    line: 2,
                },
                CMacroDef {
                    name: "WIDGET_NAME_LEN".into(),
                    value: "16".into(),
                    line: 5,
                },
            ]
        );
    }

    #[test]
    fn records_keep_packing_bit_widths_unions_and_anonymous_members() {
        let src = "struct widget_reg {\n\
                   \t__u16 addr;\n\
                   \t__u8 width : 4;\n\
                   \t__u8 : 4;\n\
                   \t__be32 value;\n\
                   } __attribute__((packed));\n\
                   struct __packed widget_hdr { __u8 kind; __u32 len; };\n\
                   struct widget_packed_cfg { __u32 a; };\n\
                   struct widget_xfer {\n\
                   \t__u32 slot;\n\
                   \t__u8 data[4][WIDGET_NAME_LEN];\n\
                   \tunion {\n\
                   \t\t__u32 crc;\n\
                   \t\t__u8 tag[4];\n\
                   \t};\n\
                   \tstruct { __u16 lo, hi; } range;\n\
                   \tvoid __user *reply;\n\
                   \tconst char __user *label;\n\
                   };\n\
                   typedef struct { __u32 id; } widget_id_t;\n\
                   union widget_any { __u32 word; __u64 wide; };\n";
        let facts = parse_ioctl_facts(src).unwrap();

        let reg = record(&facts, "widget_reg");
        assert!(reg.packed && !reg.union);
        assert_eq!(
            reg.fields,
            vec![
                field(Some("addr"), "__u16", None),
                field(Some("width"), "__u8", Some("4")),
                field(None, "__u8", Some("4")),
                field(Some("value"), "__be32", None),
            ]
        );
        assert!(record(&facts, "widget_hdr").packed);
        assert!(
            !record(&facts, "widget_packed_cfg").packed,
            "a tag that merely contains `packed` is not packing"
        );

        let xfer = record(&facts, "widget_xfer");
        assert!(!xfer.packed && !xfer.union);
        assert_eq!(
            xfer.fields,
            vec![
                field(Some("slot"), "__u32", None),
                field(Some("data"), "__u8[4][WIDGET_NAME_LEN]", None),
                field(None, "union widget_xfer.anon0", None),
                field(Some("range"), "struct widget_xfer.range", None),
                field(Some("reply"), "void *", None),
                field(Some("label"), "char *", None),
            ]
        );
        let anon = record(&facts, "widget_xfer.anon0");
        assert!(anon.union);
        assert_eq!(
            anon.fields,
            vec![
                field(Some("crc"), "__u32", None),
                field(Some("tag"), "__u8[4]", None),
            ]
        );
        assert_eq!(
            record(&facts, "widget_xfer.range").fields,
            vec![
                field(Some("lo"), "__u16", None),
                field(Some("hi"), "__u16", None),
            ]
        );
        assert_eq!(
            record(&facts, "widget_id_t").fields,
            vec![field(Some("id"), "__u32", None)]
        );
        assert!(record(&facts, "widget_any").union);
        assert_eq!(xfer.line, 9);
    }

    #[test]
    fn designated_initializers_name_their_members() {
        let src = "static const struct file_operations widget_fops = {\n\
                   \t.owner = THIS_MODULE,\n\
                   \t.unlocked_ioctl = widget_ioctl,\n\
                   \t.compat_ioctl = compat_ptr_ioctl,\n\
                   };\n\
                   static struct miscdevice widget_misc = {\n\
                   \t.minor = MISC_DYNAMIC_MINOR,\n\
                   \t.name = \"wid\" \"get\",\n\
                   \t.fops = &widget_fops,\n\
                   };\n\
                   static int plain = 3;\n";
        let facts = parse_ioctl_facts(src).unwrap();
        assert_eq!(
            facts.initializers,
            vec![
                CInitializer {
                    variable: "widget_fops".into(),
                    type_name: "struct file_operations".into(),
                    line: 1,
                    fields: vec![
                        ("owner".into(), CValue::Identifier("THIS_MODULE".into())),
                        (
                            "unlocked_ioctl".into(),
                            CValue::Identifier("widget_ioctl".into())
                        ),
                        (
                            "compat_ioctl".into(),
                            CValue::Identifier("compat_ptr_ioctl".into())
                        ),
                    ],
                },
                CInitializer {
                    variable: "widget_misc".into(),
                    type_name: "struct miscdevice".into(),
                    line: 6,
                    fields: vec![
                        (
                            "minor".into(),
                            CValue::Identifier("MISC_DYNAMIC_MINOR".into())
                        ),
                        ("name".into(), CValue::String("widget".into())),
                        ("fops".into(), CValue::AddressOf("widget_fops".into())),
                    ],
                },
            ]
        );
    }

    #[test]
    fn functions_record_their_switches_and_calls() {
        let src = "static long widget_ioctl(struct file *file, unsigned int cmd,\n\
                   \t\t\t unsigned long arg)\n\
                   {\n\
                   \tvoid __user *argp = (void __user *)arg;\n\
                   \tswitch (cmd) {\n\
                   \tcase WIDGET_IOC_RESET:\n\
                   \t\treturn 0;\n\
                   \tcase WIDGET_IOC_SET_CONFIG: {\n\
                   \t\tswitch (mode) { case 1: break; }\n\
                   \t\treturn widget_set(file, argp);\n\
                   \t}\n\
                   \tdefault:\n\
                   \t\treturn widget_do_xfer(file->private_data, cmd, arg);\n\
                   \t}\n\
                   }\n\
                   static int widget_probe(void)\n\
                   {\n\
                   \tdevice_create(widget_class, NULL, devt, NULL, \"widget%d\", 0);\n\
                   \treturn register_chrdev(0, \"widget\", &widget_fops);\n\
                   }\n";
        let facts = parse_ioctl_facts(src).unwrap();
        let ioctl = &facts.functions[0];
        assert_eq!(ioctl.name, "widget_ioctl");
        assert_eq!(ioctl.line, 1);
        assert_eq!(
            ioctl
                .params
                .iter()
                .map(|p| (p.name.as_str(), p.c_type.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("file", "struct file *"),
                ("cmd", "unsigned int"),
                ("arg", "unsigned long"),
            ]
        );
        assert_eq!(
            ioctl.switches,
            vec![
                CSwitch {
                    condition: "cmd".into(),
                    case_labels: vec!["WIDGET_IOC_RESET".into(), "WIDGET_IOC_SET_CONFIG".into()],
                    line: 5,
                },
                CSwitch {
                    condition: "mode".into(),
                    case_labels: vec!["1".into()],
                    line: 9,
                },
            ]
        );
        assert_eq!(
            ioctl
                .calls
                .iter()
                .map(|call| (call.callee.as_str(), call.args.clone(), call.line))
                .collect::<Vec<_>>(),
            vec![
                (
                    "widget_set",
                    vec![
                        CValue::Identifier("file".into()),
                        CValue::Identifier("argp".into())
                    ],
                    10
                ),
                (
                    "widget_do_xfer",
                    vec![
                        CValue::Other("file->private_data".into()),
                        CValue::Identifier("cmd".into()),
                        CValue::Identifier("arg".into())
                    ],
                    13
                ),
            ]
        );
        let probe = &facts.functions[1];
        assert_eq!(probe.name, "widget_probe");
        assert_eq!(
            probe.calls[0].args[4],
            CValue::String("widget%d".into()),
            "{:?}",
            probe.calls
        );
        assert_eq!(probe.calls[1].callee, "register_chrdev");
        assert_eq!(
            probe.calls[1].args[2],
            CValue::AddressOf("widget_fops".into())
        );
    }

    #[test]
    fn typedefs_and_enums_come_along() {
        let src = "typedef __u32 widget_word_t;\n\
                   typedef struct widget_cfg widget_cfg_t;\n\
                   enum widget_mode { WIDGET_IDLE, WIDGET_RUN };\n";
        let facts = parse_ioctl_facts(src).unwrap();
        let typedefs: Vec<(&str, &str)> = facts
            .typedefs
            .iter()
            .map(|t| (t.name.as_str(), t.underlying.as_str()))
            .collect();
        assert_eq!(
            typedefs,
            vec![
                ("widget_word_t", "__u32"),
                ("widget_cfg_t", "struct widget_cfg")
            ]
        );
        assert_eq!(facts.enums[0].name, "widget_mode");
    }

    #[test]
    fn kernel_annotations_keep_lines_and_strings() {
        let src = "static char banner[] = \"__user stays\";\n\
                   struct widget_out { __u8 __iomem *regs; };\n";
        let facts = parse_ioctl_facts(src).unwrap();
        assert_eq!(
            record(&facts, "widget_out").fields,
            vec![field(Some("regs"), "__u8 *", None)]
        );
        assert_eq!(record(&facts, "widget_out").line, 2);
    }
}
