// SPDX-License-Identifier: Apache-2.0

//! CMSIS-SVD device descriptions: where a part's peripherals are.
//!
//! A vendor's SVD file (CMSIS-SVD, the XML format silicon vendors ship for
//! debuggers and header generators) lists each peripheral with its base
//! address and one or more address blocks: the byte ranges its registers
//! occupy. [`Svd::windows`] turns those into the [`PeripheralWindow`]s a
//! machine serves through its MMIO models, so that only the addresses a real
//! peripheral answers are registers, and a load or store anywhere else in
//! the peripheral region is an invalid access, as on the bus of the part.
//!
//! What is read: the device's `name`; each `peripheral`'s `name`,
//! `baseAddress`, `addressBlock`s (`offset`, `size`, `usage`) and
//! `interrupt`s (`name`, `value`); `derivedFrom`, whose peripheral's address
//! blocks a peripheral with none of its own inherits; and peripheral arrays
//! (`dim`, `dimIncrement`, `dimIndex`, with `%s` in the name). Registers,
//! fields and everything else are skipped unread, so a vendor file of many
//! megabytes is read in one pass. Numbers are CMSIS-SVD's
//! `scaledNonNegativeInteger`: decimal, `0x` hexadecimal or `#` binary, with
//! an optional `k`, `m`, `g` or `t` scale.
//!
//! The XML reader is this module's own: elements, attributes, text, the
//! five predefined entities and character references, CDATA sections,
//! comments, processing instructions and a DOCTYPE, which is all SVD files
//! use. It is not a validating parser.

use crate::mmio::PeripheralWindow;
use std::collections::HashMap;
use thiserror::Error;

/// The system space the core answers itself (the private peripheral bus):
/// a peripheral an SVD places there (the System Control Block, the NVIC) is
/// no MMIO window.
const SYSTEM_BASE: u64 = 0xe000_0000;
const SYSTEM_END: u64 = 0xe010_0000;
/// The longest chain of `derivedFrom`s followed.
const MAX_DERIVATION: usize = 32;
/// Most elements a peripheral array expands to.
const MAX_DIM: u64 = 1024;

/// A device an SVD file describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Svd {
    /// The device's `name`.
    pub device: Option<String>,
    /// Its peripherals, in file order, arrays expanded and derived ones
    /// with the address blocks they inherit.
    pub peripherals: Vec<SvdPeripheral>,
}

/// One peripheral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvdPeripheral {
    pub name: String,
    pub base: u32,
    /// Its address blocks, relative to `base`.
    pub blocks: Vec<AddressBlock>,
    pub interrupts: Vec<SvdInterrupt>,
    /// The peripheral it is derived from.
    pub derived_from: Option<String>,
}

/// What an address block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockUsage {
    Registers,
    /// Memory the peripheral serves, such as a packet buffer.
    Buffer,
    /// Addresses no register answers.
    Reserved,
}

/// A range of a peripheral's addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressBlock {
    pub offset: u32,
    pub size: u32,
    pub usage: BlockUsage,
}

/// An interrupt a peripheral raises: `value` is its IRQ number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvdInterrupt {
    pub name: String,
    pub value: u32,
}

/// Why an SVD file could not be read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SvdError {
    #[error("line {line}: {message}")]
    Xml { line: usize, message: String },
    #[error(
        "the document is not an SVD device description: its root element is <{root}>, not <device>"
    )]
    NotSvd { root: String },
    #[error("line {line}: <{element}> {value:?} is not a number")]
    Number {
        line: usize,
        element: &'static str,
        value: String,
    },
    #[error("a peripheral has no <name>")]
    UnnamedPeripheral,
    #[error("peripheral {peripheral} has no <baseAddress>")]
    NoBaseAddress { peripheral: String },
    #[error("peripheral {peripheral} is derived from {base}, which the file does not describe")]
    UnknownBase { peripheral: String, base: String },
    #[error("peripheral {peripheral}'s derivedFrom chain goes round in a circle or runs too deep")]
    DerivationCycle { peripheral: String },
    #[error("peripheral array {peripheral}: {message}")]
    BadArray { peripheral: String, message: String },
}

impl Svd {
    /// Read an SVD file's text.
    pub fn parse(text: &str) -> Result<Self, SvdError> {
        let raw = Reader::new(text).device()?;
        let mut peripherals = Vec::new();
        for peripheral in &raw.peripherals {
            peripherals.extend(peripheral.expand()?);
        }
        resolve_derivations(&mut peripherals)?;
        Ok(Self {
            device: raw.device,
            peripherals,
        })
    }

    /// The peripheral windows: each address block that is not reserved, at
    /// its peripheral's base plus its offset, lowest first. A block in the
    /// system space, which the core answers itself, an empty one and one
    /// past the end of the address space are left out.
    pub fn windows(&self) -> Vec<PeripheralWindow> {
        let mut windows: Vec<PeripheralWindow> = self
            .peripherals
            .iter()
            .flat_map(|peripheral| {
                peripheral
                    .blocks
                    .iter()
                    .filter(|block| block.usage != BlockUsage::Reserved && block.size > 0)
                    .filter_map(move |block| {
                        let base = u64::from(peripheral.base) + u64::from(block.offset);
                        let end = base + u64::from(block.size);
                        let system = base < SYSTEM_END && end > SYSTEM_BASE;
                        (end <= 1 << 32 && !system).then(|| PeripheralWindow {
                            name: peripheral.name.clone(),
                            base: base as u32,
                            size: block.size,
                        })
                    })
            })
            .collect();
        windows.sort_by_key(|window| (window.base, window.size));
        windows.dedup();
        windows
    }

    /// The peripherals with no address block, own or inherited, so no
    /// window.
    pub fn unplaced(&self) -> Vec<&str> {
        self.peripherals
            .iter()
            .filter(|peripheral| peripheral.blocks.is_empty())
            .map(|peripheral| peripheral.name.as_str())
            .collect()
    }

    /// The name of IRQ `irq`, from the first peripheral that raises it.
    pub fn interrupt_name(&self, irq: u32) -> Option<&str> {
        self.peripherals
            .iter()
            .flat_map(|peripheral| &peripheral.interrupts)
            .find(|interrupt| interrupt.value == irq)
            .map(|interrupt| interrupt.name.as_str())
    }
}

/// A derived peripheral with no address block of its own takes its base's.
fn resolve_derivations(peripherals: &mut [SvdPeripheral]) -> Result<(), SvdError> {
    let index: HashMap<String, usize> = peripherals
        .iter()
        .enumerate()
        .map(|(at, peripheral)| (peripheral.name.clone(), at))
        .rev()
        .collect();
    for at in 0..peripherals.len() {
        if !peripherals[at].blocks.is_empty() {
            continue;
        }
        let mut current = at;
        let mut depth = 0;
        while let Some(base) = peripherals[current].derived_from.clone() {
            // `derivedFrom` may name the peripheral with a path.
            let name = base.rsplit('.').next().unwrap_or(&base);
            let Some(&next) = index.get(name) else {
                return Err(SvdError::UnknownBase {
                    peripheral: peripherals[current].name.clone(),
                    base,
                });
            };
            depth += 1;
            if next == current || depth > MAX_DERIVATION {
                return Err(SvdError::DerivationCycle {
                    peripheral: peripherals[at].name.clone(),
                });
            }
            current = next;
            if !peripherals[current].blocks.is_empty() {
                break;
            }
        }
        if current != at {
            peripherals[at].blocks = peripherals[current].blocks.clone();
        }
    }
    Ok(())
}

/// A CMSIS-SVD `scaledNonNegativeInteger`.
fn number(text: &str) -> Option<u64> {
    let text = text.trim();
    let text = text.strip_prefix('+').unwrap_or(text);
    let (digits, radix) =
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (hex, 16)
        } else if let Some(binary) = text.strip_prefix('#') {
            (binary, 2)
        } else {
            (text, 10)
        };
    let (digits, scale) = match digits.chars().last() {
        Some('k' | 'K') if radix != 16 => (&digits[..digits.len() - 1], 1u64 << 10),
        Some('m' | 'M') => (&digits[..digits.len() - 1], 1 << 20),
        Some('g' | 'G') => (&digits[..digits.len() - 1], 1 << 30),
        Some('t' | 'T') => (&digits[..digits.len() - 1], 1 << 40),
        _ => (digits, 1),
    };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()?.checked_mul(scale)
}

/// The `dimIndex` of an array of `dim` elements: `A-D`, `0-3`, a comma
/// list, or by default `0` to `dim - 1`.
fn dim_index(index: Option<&str>, dim: u64) -> Option<Vec<String>> {
    let Some(index) = index.map(str::trim).filter(|index| !index.is_empty()) else {
        return Some((0..dim).map(|at| at.to_string()).collect());
    };
    if let Some((first, last)) = index.split_once('-') {
        let (first, last) = (first.trim(), last.trim());
        if let (Ok(first), Ok(last)) = (first.parse::<u64>(), last.parse::<u64>()) {
            return (first <= last).then(|| (first..=last).map(|at| at.to_string()).collect());
        }
        let (mut first, mut last) = (first.chars(), last.chars());
        if let (Some(a), None, Some(z), None) =
            (first.next(), first.next(), last.next(), last.next())
        {
            if a.is_ascii_uppercase() && z.is_ascii_uppercase() && a <= z {
                return Some((a..=z).map(String::from).collect());
            }
        }
        return None;
    }
    Some(
        index
            .split(',')
            .map(|item| item.trim().to_owned())
            .collect(),
    )
}

// ---- reading the document ----------------------------------------------

/// A peripheral as the file gives it, before arrays and derivations.
#[derive(Default)]
struct RawPeripheral {
    name: Option<String>,
    base: Option<u32>,
    derived_from: Option<String>,
    blocks: Vec<AddressBlock>,
    interrupts: Vec<SvdInterrupt>,
    dim: Option<u64>,
    dim_increment: Option<u64>,
    dim_index: Option<String>,
}

impl RawPeripheral {
    fn expand(&self) -> Result<Vec<SvdPeripheral>, SvdError> {
        let name = self.name.clone().ok_or(SvdError::UnnamedPeripheral)?;
        let base = self.base.ok_or_else(|| SvdError::NoBaseAddress {
            peripheral: name.clone(),
        })?;
        let one = |name: String, base: u32| SvdPeripheral {
            name,
            base,
            blocks: self.blocks.clone(),
            interrupts: self.interrupts.clone(),
            derived_from: self.derived_from.clone(),
        };
        let Some(dim) = self.dim.filter(|_| name.contains("%s")) else {
            return Ok(vec![one(name, base)]);
        };
        let bad = |message: &str| SvdError::BadArray {
            peripheral: name.clone(),
            message: message.to_owned(),
        };
        if dim == 0 || dim > MAX_DIM {
            return Err(bad("its dim is zero or too large"));
        }
        let increment = self
            .dim_increment
            .ok_or_else(|| bad("it has no dimIncrement"))?;
        let indexes = dim_index(self.dim_index.as_deref(), dim)
            .filter(|indexes| indexes.len() as u64 == dim)
            .ok_or_else(|| bad("its dimIndex does not give dim names"))?;
        indexes
            .iter()
            .enumerate()
            .map(|(at, index)| {
                let base = u64::from(base) + at as u64 * increment;
                let base = u32::try_from(base).map_err(|_| bad("it runs past 4 GiB"))?;
                // `UART[%s]` names elements UART0, UART1, ...
                let name = name.replace("[%s]", index).replace("%s", index);
                Ok(one(name, base))
            })
            .collect()
    }
}

struct RawDevice {
    device: Option<String>,
    peripherals: Vec<RawPeripheral>,
}

/// An event of the XML document.
enum Event<'a> {
    Start {
        name: &'a str,
        attributes: Vec<(&'a str, String)>,
        empty: bool,
    },
    End {
        name: &'a str,
    },
    Text(String),
    Eof,
}

struct Reader<'a> {
    text: &'a str,
    at: usize,
}

/// An element's name without its namespace prefix.
fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

impl<'a> Reader<'a> {
    fn new(text: &'a str) -> Self {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        Self { text, at: 0 }
    }

    fn line(&self, at: usize) -> usize {
        1 + self.text[..at.min(self.text.len())]
            .bytes()
            .filter(|&byte| byte == b'\n')
            .count()
    }

    fn error(&self, at: usize, message: impl Into<String>) -> SvdError {
        SvdError::Xml {
            line: self.line(at),
            message: message.into(),
        }
    }

    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    /// Skip past `end`, which must follow.
    fn skip_past(&mut self, end: &str, what: &str) -> Result<&'a str, SvdError> {
        let start = self.at;
        match self.rest().find(end) {
            Some(offset) => {
                let skipped = &self.text[start..start + offset];
                self.at = start + offset + end.len();
                Ok(skipped)
            }
            None => Err(self.error(start, format!("{what} is not closed"))),
        }
    }

    fn next(&mut self) -> Result<Event<'a>, SvdError> {
        loop {
            if self.at >= self.text.len() {
                return Ok(Event::Eof);
            }
            let rest = self.rest();
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                let raw = &rest[..end];
                let start = self.at;
                self.at += end;
                return Ok(Event::Text(
                    decode(raw).ok_or_else(|| self.error(start, "a bad entity reference"))?,
                ));
            }
            if rest.starts_with("<!--") {
                self.at += 4;
                self.skip_past("-->", "a comment")?;
                continue;
            }
            if rest.starts_with("<![CDATA[") {
                self.at += 9;
                let text = self.skip_past("]]>", "a CDATA section")?;
                return Ok(Event::Text(text.to_owned()));
            }
            if rest.starts_with("<?") {
                self.at += 2;
                self.skip_past("?>", "a processing instruction")?;
                continue;
            }
            if rest.starts_with("<!") {
                self.skip_declaration()?;
                continue;
            }
            return self.tag();
        }
    }

    /// `<!DOCTYPE ...>`, with an internal subset in brackets.
    fn skip_declaration(&mut self) -> Result<(), SvdError> {
        let start = self.at;
        let mut depth = 0usize;
        for (offset, byte) in self.rest().bytes().enumerate() {
            match byte {
                b'[' => depth += 1,
                b']' => depth = depth.saturating_sub(1),
                b'>' if depth == 0 => {
                    self.at += offset + 1;
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(self.error(start, "a declaration is not closed"))
    }

    fn tag(&mut self) -> Result<Event<'a>, SvdError> {
        let start = self.at;
        let rest = self.rest();
        let closing = rest.starts_with("</");
        let body_start = if closing { 2 } else { 1 };
        // The tag ends at the first '>' outside a quoted attribute value.
        let mut quote = None;
        let mut end = None;
        for (offset, byte) in rest.bytes().enumerate().skip(body_start) {
            match (quote, byte) {
                (None, b'"' | b'\'') => quote = Some(byte),
                (Some(open), _) if open == byte => quote = None,
                (None, b'>') => {
                    end = Some(offset);
                    break;
                }
                _ => {}
            }
        }
        let end = end.ok_or_else(|| self.error(start, "a tag is not closed"))?;
        self.at += end + 1;
        let mut body = &rest[body_start..end];
        if closing {
            let name = body.trim();
            if name.is_empty() {
                return Err(self.error(start, "an end tag has no name"));
            }
            return Ok(Event::End { name: local(name) });
        }
        let empty = body.ends_with('/');
        if empty {
            body = &body[..body.len() - 1];
        }
        let name_end = body
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(body.len());
        let name = &body[..name_end];
        if name.is_empty() {
            return Err(self.error(start, "a tag has no name"));
        }
        let attributes = self.attributes(&body[name_end..], start)?;
        Ok(Event::Start {
            name: local(name),
            attributes,
            empty,
        })
    }

    fn attributes(&self, mut text: &'a str, at: usize) -> Result<Vec<(&'a str, String)>, SvdError> {
        let mut attributes = Vec::new();
        loop {
            text = text.trim_start();
            if text.is_empty() {
                return Ok(attributes);
            }
            let (name, after) = text
                .split_once('=')
                .ok_or_else(|| self.error(at, "an attribute has no value"))?;
            let after = after.trim_start();
            let quote = after
                .chars()
                .next()
                .filter(|c| *c == '"' || *c == '\'')
                .ok_or_else(|| self.error(at, "an attribute value is not quoted"))?;
            let value_end = after[1..]
                .find(quote)
                .ok_or_else(|| self.error(at, "an attribute value is not closed"))?;
            let value = decode(&after[1..1 + value_end])
                .ok_or_else(|| self.error(at, "a bad entity reference"))?;
            attributes.push((local(name.trim()), value));
            text = &after[1 + value_end + 1..];
        }
    }

    /// Read the whole document as a device description.
    fn device(mut self) -> Result<RawDevice, SvdError> {
        let mut stack: Vec<&'a str> = Vec::new();
        let mut text = String::new();
        let mut device = RawDevice {
            device: None,
            peripherals: Vec::new(),
        };
        let mut peripheral: Option<RawPeripheral> = None;
        let mut block: Option<(Option<u64>, Option<u64>, BlockUsage)> = None;
        let mut interrupt: (Option<String>, Option<u64>) = (None, None);
        let mut seen_root = false;
        loop {
            let at = self.at;
            match self.next()? {
                Event::Eof => break,
                Event::Text(chunk) => {
                    if !stack.is_empty() {
                        text.push_str(&chunk);
                    } else if !chunk.trim().is_empty() {
                        return Err(self.error(at, "text outside the root element"));
                    }
                }
                Event::Start {
                    name,
                    attributes,
                    empty,
                } => {
                    if stack.is_empty() {
                        if seen_root {
                            return Err(self.error(at, "a second root element"));
                        }
                        seen_root = true;
                        if name != "device" {
                            return Err(SvdError::NotSvd {
                                root: name.to_owned(),
                            });
                        }
                    }
                    text.clear();
                    let path = path_of(&stack, name);
                    match path {
                        Path::Peripheral => {
                            peripheral = Some(RawPeripheral {
                                derived_from: attributes
                                    .into_iter()
                                    .find(|(key, _)| *key == "derivedFrom")
                                    .map(|(_, value)| value),
                                ..RawPeripheral::default()
                            });
                        }
                        Path::Block => block = Some((None, None, BlockUsage::Registers)),
                        Path::Interrupt => interrupt = (None, None),
                        _ => {}
                    }
                    if empty {
                        self.close(
                            &stack,
                            name,
                            "",
                            at,
                            &mut device,
                            &mut peripheral,
                            &mut block,
                            &mut interrupt,
                        )?;
                    } else {
                        stack.push(name);
                    }
                }
                Event::End { name } => {
                    let Some(open) = stack.pop() else {
                        return Err(self.error(at, format!("</{name}> closes nothing")));
                    };
                    if open != name {
                        return Err(self.error(at, format!("</{name}> closes <{open}>")));
                    }
                    let value = std::mem::take(&mut text);
                    self.close(
                        &stack,
                        name,
                        value.trim(),
                        at,
                        &mut device,
                        &mut peripheral,
                        &mut block,
                        &mut interrupt,
                    )?;
                }
            }
        }
        if let Some(open) = stack.last() {
            return Err(self.error(self.text.len(), format!("<{open}> is not closed")));
        }
        if !seen_root {
            return Err(SvdError::NotSvd {
                root: "(none)".to_owned(),
            });
        }
        Ok(device)
    }

    /// The element `name`, inside `stack`, ends with text `value`.
    #[allow(clippy::too_many_arguments)]
    fn close(
        &self,
        stack: &[&str],
        name: &str,
        value: &str,
        at: usize,
        device: &mut RawDevice,
        peripheral: &mut Option<RawPeripheral>,
        block: &mut Option<(Option<u64>, Option<u64>, BlockUsage)>,
        interrupt: &mut (Option<String>, Option<u64>),
    ) -> Result<(), SvdError> {
        let read = |element: &'static str| {
            number(value).ok_or_else(|| SvdError::Number {
                line: self.line(at),
                element,
                value: value.to_owned(),
            })
        };
        let word = |element: &'static str| {
            read(element).and_then(|number| {
                u32::try_from(number).map_err(|_| SvdError::Number {
                    line: self.line(at),
                    element,
                    value: value.to_owned(),
                })
            })
        };
        match path_of(stack, name) {
            Path::DeviceName => device.device = Some(value.to_owned()),
            Path::Peripheral => {
                if let Some(done) = peripheral.take() {
                    device.peripherals.push(done);
                }
            }
            Path::PeripheralField(field) => {
                if let Some(peripheral) = peripheral.as_mut() {
                    match field {
                        "name" => peripheral.name = Some(value.to_owned()),
                        "baseAddress" => peripheral.base = Some(word("baseAddress")?),
                        "dim" => peripheral.dim = Some(read("dim")?),
                        "dimIncrement" => peripheral.dim_increment = Some(read("dimIncrement")?),
                        "dimIndex" => peripheral.dim_index = Some(value.to_owned()),
                        _ => {}
                    }
                }
            }
            Path::Block => {
                if let (Some(peripheral), Some((offset, size, usage))) =
                    (peripheral.as_mut(), block.take())
                {
                    let offset = offset.unwrap_or(0);
                    let size = size.unwrap_or(0);
                    peripheral.blocks.push(AddressBlock {
                        offset: u32::try_from(offset).map_err(|_| SvdError::Number {
                            line: self.line(at),
                            element: "offset",
                            value: offset.to_string(),
                        })?,
                        size: u32::try_from(size).map_err(|_| SvdError::Number {
                            line: self.line(at),
                            element: "size",
                            value: size.to_string(),
                        })?,
                        usage,
                    });
                }
            }
            Path::BlockField(field) => {
                if let Some((offset, size, usage)) = block.as_mut() {
                    match field {
                        "offset" => *offset = Some(read("offset")?),
                        "size" => *size = Some(read("size")?),
                        "usage" => {
                            *usage = match value {
                                "reserved" => BlockUsage::Reserved,
                                "buffer" => BlockUsage::Buffer,
                                _ => BlockUsage::Registers,
                            }
                        }
                        _ => {}
                    }
                }
            }
            Path::Interrupt => {
                if let (Some(peripheral), (Some(name), Some(value))) =
                    (peripheral.as_mut(), std::mem::take(interrupt))
                {
                    if let Ok(value) = u32::try_from(value) {
                        peripheral.interrupts.push(SvdInterrupt { name, value });
                    }
                }
            }
            Path::InterruptField(field) => match field {
                "name" => interrupt.0 = Some(value.to_owned()),
                "value" => interrupt.1 = Some(read("value")?),
                _ => {}
            },
            Path::Other => {}
        }
        Ok(())
    }
}

/// Where an element is, as far as an SVD's peripherals go.
enum Path<'a> {
    DeviceName,
    Peripheral,
    PeripheralField(&'a str),
    Block,
    BlockField(&'a str),
    Interrupt,
    InterruptField(&'a str),
    Other,
}

/// The place of element `name` inside the open elements `stack`.
fn path_of<'a>(stack: &[&str], name: &'a str) -> Path<'a> {
    match (stack, name) {
        (["device"], "name") => Path::DeviceName,
        (["device", "peripherals"], "peripheral") => Path::Peripheral,
        (["device", "peripherals", "peripheral"], "addressBlock") => Path::Block,
        (["device", "peripherals", "peripheral"], "interrupt") => Path::Interrupt,
        (["device", "peripherals", "peripheral"], field) => Path::PeripheralField(field),
        (["device", "peripherals", "peripheral", "addressBlock"], field) => Path::BlockField(field),
        (["device", "peripherals", "peripheral", "interrupt"], field) => {
            Path::InterruptField(field)
        }
        _ => Path::Other,
    }
}

/// Text with its entity and character references replaced; `None` for a
/// reference that is not one.
fn decode(raw: &str) -> Option<String> {
    if !raw.contains('&') {
        return Some(raw.to_owned());
    }
    let mut text = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('&') {
        text.push_str(&rest[..start]);
        let end = rest[start..].find(';')? + start;
        let reference = &rest[start + 1..end];
        let decoded = match reference {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = reference
                    .strip_prefix("#x")
                    .or_else(|| reference.strip_prefix("#X"))
                {
                    u32::from_str_radix(hex, 16).ok()?
                } else {
                    reference.strip_prefix('#')?.parse().ok()?
                };
                char::from_u32(code)?
            }
        };
        text.push(decoded);
        rest = &rest[end + 1..];
    }
    text.push_str(rest);
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_scaled_non_negative_integers() {
        assert_eq!(number("0x40011000"), Some(0x4001_1000));
        assert_eq!(number("0X1f"), Some(0x1f));
        assert_eq!(number(" 1024 "), Some(1024));
        assert_eq!(number("+8"), Some(8));
        assert_eq!(number("#1010"), Some(10));
        assert_eq!(number("1K"), Some(1024));
        assert_eq!(number("4k"), Some(4096));
        assert_eq!(number("2M"), Some(2 << 20));
        // A hex digit is not a scale.
        assert_eq!(number("0x1b"), Some(0x1b));
        for bad in ["", "0x", "#", "#102", "ten", "-1", "1.5"] {
            assert_eq!(number(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn array_indexes_are_ranges_lists_or_counts() {
        assert_eq!(
            dim_index(None, 3),
            Some(vec!["0".into(), "1".into(), "2".into()])
        );
        assert_eq!(
            dim_index(Some("A-C"), 3),
            Some(vec!["A".into(), "B".into(), "C".into()])
        );
        assert_eq!(
            dim_index(Some("4-5"), 2),
            Some(vec!["4".into(), "5".into()])
        );
        assert_eq!(
            dim_index(Some("tx, rx"), 2),
            Some(vec!["tx".into(), "rx".into()])
        );
        assert_eq!(dim_index(Some("C-A"), 3), None);
    }

    #[test]
    fn entities_and_character_references_decode() {
        assert_eq!(
            decode("a &lt;b&gt; &amp; &quot;c&apos; &#65;&#x42;").as_deref(),
            Some("a <b> & \"c' AB")
        );
        assert_eq!(decode("&bogus;"), None);
        assert_eq!(decode("&amp"), None);
    }

    fn parse(text: &str) -> Result<Svd, SvdError> {
        Svd::parse(text)
    }

    #[test]
    fn a_minimal_document_with_comments_cdata_and_single_quotes_reads() {
        let svd = parse(
            "\u{feff}<?xml version='1.0'?>\n<!DOCTYPE device [ <!ENTITY x 'y'> ]>\n\
             <!-- a comment with <tags> -->\n<device schemaVersion='1.3'>\
             <name><![CDATA[PART<1>]]></name><peripherals>\
             <peripheral><name>P</name><baseAddress>0x40000000</baseAddress>\
             <addressBlock><offset>0</offset><size>0x10</size><usage>buffer</usage></addressBlock>\
             <registers><register><name>R</name><addressOffset>0x4</addressOffset></register>\
             </registers></peripheral><peripheral><name>Q</name><baseAddress>0x40001000\
             </baseAddress><addressBlock><offset>0</offset><size>4</size></addressBlock>\
             <interrupt><name>Q_IRQ</name><value>3</value></interrupt><empty/></peripheral>\
             </peripherals></device>\n",
        )
        .unwrap();
        assert_eq!(svd.device.as_deref(), Some("PART<1>"));
        assert_eq!(svd.peripherals.len(), 2);
        assert_eq!(svd.peripherals[0].blocks[0].usage, BlockUsage::Buffer);
        assert_eq!(
            svd.peripherals[1].base, 0x4000_1000,
            "text split by a newline"
        );
        assert_eq!(svd.interrupt_name(3), Some("Q_IRQ"));
        assert_eq!(svd.windows().len(), 2);
    }

    #[test]
    fn a_peripheral_with_no_block_is_unplaced() {
        let svd = parse(
            "<device><peripherals><peripheral><name>LONE</name>\
             <baseAddress>0x40000000</baseAddress></peripheral></peripherals></device>",
        )
        .unwrap();
        assert_eq!(svd.unplaced(), ["LONE"]);
        assert!(svd.windows().is_empty());
    }

    #[test]
    fn a_derivation_may_come_before_its_base_and_through_another() {
        let svd = parse(
            "<device><peripherals>\
             <peripheral derivedFrom='B'><name>C</name><baseAddress>0x40002000</baseAddress></peripheral>\
             <peripheral derivedFrom='A'><name>B</name><baseAddress>0x40001000</baseAddress></peripheral>\
             <peripheral><name>A</name><baseAddress>0x40000000</baseAddress>\
             <addressBlock><offset>0x10</offset><size>0x20</size></addressBlock></peripheral>\
             </peripherals></device>",
        )
        .unwrap();
        let windows: Vec<(String, u32, u32)> = svd
            .windows()
            .into_iter()
            .map(|window| (window.name, window.base, window.size))
            .collect();
        assert_eq!(
            windows,
            [
                ("A".to_owned(), 0x4000_0010, 0x20),
                ("B".to_owned(), 0x4000_1010, 0x20),
                ("C".to_owned(), 0x4000_2010, 0x20),
            ]
        );
    }

    #[test]
    fn broken_documents_are_refused_with_where_and_why() {
        let cases = [
            ("<device><name>X</device>", "closes <name>"),
            ("<device><peripherals>", "is not closed"),
            ("<device><!-- open", "comment is not closed"),
            ("<device a=1></device>", "not quoted"),
            ("<device>&nope;</device>", "entity"),
            ("<device></device><device></device>", "second root"),
        ];
        for (text, says) in cases {
            let error = parse(text).unwrap_err();
            assert!(matches!(error, SvdError::Xml { .. }), "{text}: {error}");
            assert!(error.to_string().contains(says), "{text}: {error}");
        }
        assert_eq!(
            parse("<?xml version='1.0'?>\n<html></html>").unwrap_err(),
            SvdError::NotSvd {
                root: "html".to_owned()
            }
        );
        let error = parse(
            "<device>\n<peripherals><peripheral><name>P</name>\n<baseAddress>zz</baseAddress>\
             </peripheral></peripherals></device>",
        )
        .unwrap_err();
        assert_eq!(
            error,
            SvdError::Number {
                line: 3,
                element: "baseAddress",
                value: "zz".to_owned()
            }
        );
        let unknown = parse(
            "<device><peripherals><peripheral derivedFrom='GONE'><name>P</name>\
             <baseAddress>0x40000000</baseAddress></peripheral></peripherals></device>",
        )
        .unwrap_err();
        assert!(matches!(unknown, SvdError::UnknownBase { .. }), "{unknown}");
        let circle = parse(
            "<device><peripherals>\
             <peripheral derivedFrom='B'><name>A</name><baseAddress>0</baseAddress></peripheral>\
             <peripheral derivedFrom='A'><name>B</name><baseAddress>0</baseAddress></peripheral>\
             </peripherals></device>",
        )
        .unwrap_err();
        assert!(
            matches!(circle, SvdError::DerivationCycle { .. }),
            "{circle}"
        );
        let no_base = parse(
            "<device><peripherals><peripheral><name>P</name></peripheral></peripherals></device>",
        )
        .unwrap_err();
        assert!(
            matches!(no_base, SvdError::NoBaseAddress { .. }),
            "{no_base}"
        );
    }

    #[test]
    fn a_peripheral_array_needs_an_increment_and_matching_names() {
        let array = |extra: &str| {
            parse(&format!(
                "<device><peripherals><peripheral><dim>2</dim>{extra}<name>U%s</name>\
                 <baseAddress>0x40000000</baseAddress><addressBlock><offset>0</offset>\
                 <size>4</size></addressBlock></peripheral></peripherals></device>"
            ))
        };
        let svd = array("<dimIncrement>0x100</dimIncrement>").unwrap();
        let names: Vec<(&str, u32)> = svd
            .peripherals
            .iter()
            .map(|p| (p.name.as_str(), p.base))
            .collect();
        assert_eq!(names, [("U0", 0x4000_0000), ("U1", 0x4000_0100)]);
        for bad in ["", "<dimIncrement>4</dimIncrement><dimIndex>A-C</dimIndex>"] {
            let error = array(bad).unwrap_err();
            assert!(matches!(error, SvdError::BadArray { .. }), "{bad}: {error}");
        }
    }
}
