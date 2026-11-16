// SPDX-License-Identifier: Apache-2.0

//! The message a C runtime prints when an `assert` fails, just before it
//! aborts. A replay that ran without the runtrace shim (which records the
//! failed assertion itself) still sees it: the expression, file and line are
//! in this text.

/// The C runtime whose `assert` printed the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionRuntime {
    /// `prog: file:line: function: Assertion `expr' failed.`
    Glibc,
    /// `Assertion failed: expr, file path, line N`, from the Microsoft CRT
    /// (and MinGW, which uses it).
    Msvc,
    /// `Assertion failed: (expr), function f, file path, line N.`, from the
    /// BSD and macOS libcs.
    Bsd,
    /// `Assertion failed: expr (file: function: line)`.
    Musl,
}

/// A failed assertion, as its runtime printed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionFailure {
    pub runtime: AssertionRuntime,
    /// The asserted expression, as the source spells it.
    pub expression: String,
    pub file: Option<String>,
    pub line: Option<u64>,
    /// The enclosing function; the Microsoft CRT does not print it.
    pub function: Option<String>,
}

/// The first failed assertion `text` (a harness's stderr) reports.
pub fn parse_assertion(text: &str) -> Option<AssertionFailure> {
    text.lines()
        .find_map(|line| parse_glibc(line).or_else(|| parse_assertion_failed(line)))
}

/// `prog: file:line: function: Assertion `expr' failed.` (the function is
/// left out when the compiler gives none).
fn parse_glibc(line: &str) -> Option<AssertionFailure> {
    let (head, rest) = line.split_once("Assertion `")?;
    let expression = rest.strip_suffix("' failed.")?;
    let parts: Vec<&str> = head.trim_end().trim_end_matches(':').split(": ").collect();
    let at = parts.iter().rposition(|part| file_line(part).is_some())?;
    let (file, line) = file_line(parts[at])?;
    let function = parts[at + 1..].join(": ");
    Some(AssertionFailure {
        runtime: AssertionRuntime::Glibc,
        expression: expression.to_owned(),
        file: Some(file.to_owned()),
        line: Some(line),
        function: (!function.is_empty()).then_some(function),
    })
}

/// `file:line`, split at its last colon.
fn file_line(text: &str) -> Option<(&str, u64)> {
    let (file, line) = text.rsplit_once(':')?;
    let line = line.parse().ok()?;
    (!file.is_empty()).then_some((file, line))
}

/// The `Assertion failed: ...` forms of the Microsoft CRT, the BSDs and musl.
fn parse_assertion_failed(line: &str) -> Option<AssertionFailure> {
    let (_, rest) = line.split_once("Assertion failed: ")?;
    let rest = rest.trim_end();
    if let Some((before, number)) = rest.rsplit_once(", line ") {
        let line = number.trim_end_matches('.').parse().ok()?;
        let (before, file) = before.rsplit_once(", file ")?;
        let (runtime, expression, function) = match before.rsplit_once(", function ") {
            Some((expression, function)) => {
                let expression = expression
                    .strip_prefix('(')
                    .and_then(|inner| inner.strip_suffix(')'))
                    .unwrap_or(expression);
                (AssertionRuntime::Bsd, expression, Some(function.to_owned()))
            }
            None => (AssertionRuntime::Msvc, before, None),
        };
        return Some(AssertionFailure {
            runtime,
            expression: expression.to_owned(),
            file: Some(file.to_owned()),
            line: Some(line),
            function,
        });
    }
    let (expression, location) = rest.strip_suffix(')')?.rsplit_once(" (")?;
    let mut parts = location.rsplitn(3, ": ");
    let line = parts.next()?.parse().ok()?;
    let function = parts.next()?;
    let file = parts.next()?;
    Some(AssertionFailure {
        runtime: AssertionRuntime::Musl,
        expression: expression.to_owned(),
        file: Some(file.to_owned()),
        line: Some(line),
        function: Some(function.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_glibc_assertion() {
        let stderr = "bhf: running input\n\
                      main: /src/fmt.c:14: int check_header(const unsigned char *, size_t): \
                      Assertion `data[0] != 'Z'' failed.\n";
        let failure = parse_assertion(stderr).unwrap();
        assert_eq!(failure.runtime, AssertionRuntime::Glibc);
        assert_eq!(failure.expression, "data[0] != 'Z'");
        assert_eq!(failure.file.as_deref(), Some("/src/fmt.c"));
        assert_eq!(failure.line, Some(14));
        assert_eq!(
            failure.function.as_deref(),
            Some("int check_header(const unsigned char *, size_t)")
        );
    }

    #[test]
    fn parses_a_glibc_assertion_without_a_function() {
        let failure = parse_assertion("a.out: parse.c:9: Assertion `n < 4' failed.").unwrap();
        assert_eq!(failure.expression, "n < 4");
        assert_eq!(failure.file.as_deref(), Some("parse.c"));
        assert_eq!(failure.line, Some(9));
        assert_eq!(failure.function, None);
    }

    #[test]
    fn parses_an_msvc_assertion() {
        let stderr =
            "Assertion failed: len >= 2 && data[0] != 'Z', file C:\\src\\fmt.c, line 14\r\n";
        let failure = parse_assertion(stderr).unwrap();
        assert_eq!(failure.runtime, AssertionRuntime::Msvc);
        assert_eq!(failure.expression, "len >= 2 && data[0] != 'Z'");
        assert_eq!(failure.file.as_deref(), Some("C:\\src\\fmt.c"));
        assert_eq!(failure.line, Some(14));
        assert_eq!(failure.function, None);
    }

    #[test]
    fn an_msvc_expression_may_hold_commas() {
        let failure = parse_assertion("Assertion failed: check(a, b), file x.c, line 3").unwrap();
        assert_eq!(failure.expression, "check(a, b)");
        assert_eq!(failure.file.as_deref(), Some("x.c"));
    }

    #[test]
    fn parses_a_bsd_assertion() {
        let failure =
            parse_assertion("Assertion failed: (n < 4), function parse, file parse.c, line 9.")
                .unwrap();
        assert_eq!(failure.runtime, AssertionRuntime::Bsd);
        assert_eq!(failure.expression, "n < 4");
        assert_eq!(failure.function.as_deref(), Some("parse"));
        assert_eq!(failure.file.as_deref(), Some("parse.c"));
        assert_eq!(failure.line, Some(9));
    }

    #[test]
    fn parses_a_musl_assertion() {
        let failure = parse_assertion("Assertion failed: n < 4 (parse.c: parse: 9)").unwrap();
        assert_eq!(failure.runtime, AssertionRuntime::Musl);
        assert_eq!(failure.expression, "n < 4");
        assert_eq!(failure.file.as_deref(), Some("parse.c"));
        assert_eq!(failure.function.as_deref(), Some("parse"));
        assert_eq!(failure.line, Some(9));
    }

    #[test]
    fn other_output_is_no_assertion() {
        assert_eq!(parse_assertion(""), None);
        assert_eq!(
            parse_assertion("==1==ERROR: AddressSanitizer: SEGV on unknown address"),
            None
        );
        assert_eq!(parse_assertion("Assertion failed: no location"), None);
    }
}
