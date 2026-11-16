// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExcludeCategory {
    Tests,
    Tools,
    Examples,
}

pub(crate) fn path_matches_exclusion(
    path: &Path,
    root: &Path,
    exclude_paths: &[String],
    exclude: &[ExcludeCategory],
) -> bool {
    let normalized = normalized_relative_path(path, root);
    if normalized.split('/').any(|component| {
        matches!(
            component,
            "generated_harnesses" | "harnesses" | "bhf_work" | "target" | ".git"
        )
    }) {
        return true;
    }
    exclude_paths
        .iter()
        .any(|pattern| !pattern.is_empty() && normalized.contains(&normalize_path_text(pattern)))
        || exclude
            .iter()
            .any(|category| category_matches_path(*category, &normalized))
}

fn normalized_relative_path(path: &Path, root: &Path) -> String {
    let base = if root.is_dir() {
        root
    } else {
        root.parent().unwrap_or_else(|| Path::new(""))
    };
    let relative = path.strip_prefix(base).unwrap_or(path);
    normalize_path_text(&relative.display().to_string())
}

fn normalize_path_text(value: &str) -> String {
    value.replace('\\', "/")
}

fn category_matches_path(category: ExcludeCategory, normalized_path: &str) -> bool {
    normalized_path.split('/').any(|component| match category {
        ExcludeCategory::Tests => matches!(component, "test" | "tests" | "regtests"),
        ExcludeCategory::Tools => component == "tools",
        ExcludeCategory::Examples => matches!(component, "example" | "examples"),
    })
}

/// Split a target spelling into its name and its parameter list, if any:
/// `ns::Codec::decode(int, char *)` -> (`ns::Codec::decode`, Some(`int, char *`)).
fn split_signature(spelling: &str) -> (&str, Option<&str>) {
    match spelling.find('(') {
        Some(open) => {
            let params = spelling[open + 1..]
                .rsplit_once(')')
                .map(|(inner, _)| inner)
                .unwrap_or(&spelling[open + 1..]);
            (spelling[..open].trim(), Some(params))
        }
        None => (spelling.trim(), None),
    }
}

/// Parameter lists compare without whitespace, so `const char*` and
/// `const char *` name the same overload.
fn squash_whitespace(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The last path segment of a qualified name (`ns::Codec::decode` -> `decode`,
/// `Root.Pkg.Op` -> `Op`).
fn leaf_name(name: &str) -> &str {
    let after_colons = name.rsplit("::").next().unwrap_or(name);
    after_colons.rsplit('.').next().unwrap_or(after_colons)
}

/// Whether `selected` names `name` exactly or as a trailing qualified suffix.
///
/// `name` is a discovered target name, optionally qualified and optionally
/// followed by a parameter list. The suffix must start at a qualifier boundary
/// (`::` for C++, `.` for the dotted lanes), so `Codec::decode` selects
/// `ns::Codec::decode` while `dec::decode` does not select `Codec::decode`. When
/// `selected` carries a parameter list it must equal the candidate's
/// (whitespace-insensitive); without one, every overload matches. A leading
/// global `::` on `selected` anchors it at the global namespace: `::Codec::decode`
/// matches only a `Codec::decode` that is not inside a namespace.
///
/// Callers try [`qualified_exact_matches`] over every candidate first, so an
/// exact spelling is never widened to the suffix matches of other scopes.
pub(crate) fn qualified_suffix_matches(name: &str, selected: &str, case_insensitive: bool) -> bool {
    qualified_name_matches(name, selected, case_insensitive, true)
}

/// Whether `selected` spells `name` in full: the same qualified name and, when
/// `selected` has a parameter list, the same parameters (whitespace-insensitive).
/// A leading global `::` on `selected` is allowed.
pub(crate) fn qualified_exact_matches(name: &str, selected: &str, case_insensitive: bool) -> bool {
    qualified_name_matches(name, selected, case_insensitive, false)
}

fn qualified_name_matches(
    name: &str,
    selected: &str,
    case_insensitive: bool,
    allow_suffix: bool,
) -> bool {
    let selected = selected.trim();
    let (selected, anchored) = match selected.strip_prefix("::") {
        Some(rest) => (rest, true),
        None => (selected, false),
    };
    if selected.is_empty() {
        return false;
    }
    let (name_base, name_params) = split_signature(name);
    let (selected_base, selected_params) = split_signature(selected);
    if selected_base.is_empty() {
        return false;
    }
    if let Some(selected_params) = selected_params {
        match name_params {
            Some(name_params)
                if squash_whitespace(name_params) == squash_whitespace(selected_params) => {}
            _ => return false,
        }
    }
    let equal = |left: &str, right: &str| {
        if case_insensitive {
            left.eq_ignore_ascii_case(right)
        } else {
            left == right
        }
    };
    if equal(name_base, selected_base) {
        return true;
    }
    if anchored || !allow_suffix {
        return false;
    }
    let Some(split) = name_base.len().checked_sub(selected_base.len()) else {
        return false;
    };
    if split == 0 || !name_base.is_char_boundary(split) {
        return false;
    }
    let (head, tail) = name_base.split_at(split);
    equal(tail, selected_base) && (head.ends_with("::") || head.ends_with('.'))
}

/// Levenshtein distance over chars.
fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (i, lc) in left.chars().enumerate() {
        current[0] = i + 1;
        for (j, rc) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(lc != *rc);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

/// Up to `limit` of `items` whose name (from `key`) is closest to `selected`,
/// best first, for a "did you mean" hint after a target lookup misses.
///
/// A candidate qualifies when its unqualified name equals the one asked for
/// (another class or namespace has it), is within a small edit distance of it
/// (a typo), or contains it (a prefix or suffix of the real name). Ties break on
/// the distance between the full names, then alphabetically. Comparison ignores
/// ASCII case and parameter lists. Items with the same name are listed once.
/// The console note for a selection filter (`--target`, `--harness-id`,
/// `--target-file`) that matched no discovered target, naming the closest
/// of `discovered`: by name for `--target`, by shared prefix for an id or a
/// path, where a copied id usually differs only in its hash tail.
pub(crate) fn unmatched_filter_note(flag: &str, selected: &str, discovered: &[String]) -> String {
    let mut note = format!("  {flag} '{selected}' matched no target");
    let closest: Vec<&str> = if flag == "--target" {
        closest_matches(selected, discovered, |name| name, 5)
            .into_iter()
            .map(String::as_str)
            .collect()
    } else {
        closest_by_prefix(selected, discovered, 3)
    };
    if !closest.is_empty() {
        note.push_str("; closest: ");
        note.push_str(&closest.join(", "));
    }
    note
}

/// Up to `limit` of `items`, the ones sharing the longest prefix with
/// `selected` first (ties keep their order), without duplicates.
fn closest_by_prefix<'a>(selected: &str, items: &'a [String], limit: usize) -> Vec<&'a str> {
    let shared = |item: &str| {
        selected
            .chars()
            .zip(item.chars())
            .take_while(|(a, b)| a.eq_ignore_ascii_case(b))
            .count()
    };
    let mut ranked: Vec<&str> = Vec::new();
    for item in items {
        if !ranked.contains(&item.as_str()) {
            ranked.push(item);
        }
    }
    ranked.sort_by_key(|item| std::cmp::Reverse(shared(item)));
    ranked.truncate(limit);
    ranked
}

pub(crate) fn closest_matches<'a, T>(
    selected: &str,
    items: &'a [T],
    key: impl Fn(&T) -> &str,
    limit: usize,
) -> Vec<&'a T> {
    let (selected_base, _) = split_signature(selected.trim());
    let selected_base = selected_base
        .strip_prefix("::")
        .unwrap_or(selected_base)
        .to_ascii_lowercase();
    let selected_leaf = leaf_name(&selected_base).to_owned();
    if selected_leaf.is_empty() || limit == 0 {
        return Vec::new();
    }
    let typo_budget = (selected_leaf.chars().count() / 3).max(1);
    // (tier, leaf distance, full-name distance, name): lower is closer.
    type Rank = (u8, usize, usize, String);
    let mut ranked: Vec<(Rank, &T)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        let name = key(item);
        if !seen.insert(name.to_owned()) {
            continue;
        }
        let (base, _) = split_signature(name);
        let base = base.to_ascii_lowercase();
        let leaf = leaf_name(&base);
        let leaf_distance = edit_distance(&selected_leaf, leaf);
        let tier = if leaf == selected_leaf {
            0
        } else if leaf_distance <= typo_budget {
            1
        } else if (leaf.len() >= 3 && selected_leaf.contains(leaf))
            || (selected_leaf.len() >= 3 && leaf.contains(selected_leaf.as_str()))
        {
            2
        } else {
            continue;
        };
        let full_distance = edit_distance(&selected_base, &base);
        ranked.push(((tier, leaf_distance, full_distance, name.to_owned()), item));
    }
    ranked.sort_by(|left, right| left.0.cmp(&right.0));
    ranked
        .into_iter()
        .take(limit)
        .map(|(_, item)| item)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_suffix_selects_at_a_qualifier_boundary_only() {
        let name = "widgets::Codec::decode(const unsigned char *, size_t)";
        assert!(qualified_suffix_matches(name, "Codec::decode", false));
        assert!(qualified_suffix_matches(
            name,
            "widgets::Codec::decode",
            false
        ));
        assert!(qualified_suffix_matches(
            name,
            "::widgets::Codec::decode",
            false
        ));
        assert!(qualified_suffix_matches(name, "decode", false));
        assert!(qualified_suffix_matches(
            name,
            "Codec::decode(const unsigned char*, size_t)",
            false
        ));
        // Not a boundary, a different overload, or a qualifier from inside the
        // parameter list.
        assert!(!qualified_suffix_matches(name, "dec::decode", false));
        assert!(!qualified_suffix_matches(name, "odec::decode", false));
        assert!(!qualified_suffix_matches(name, "Codec::decode(int)", false));
        assert!(!qualified_suffix_matches(name, "char *, size_t)", false));
        assert!(!qualified_suffix_matches(name, "Other::decode", false));
        assert!(!qualified_suffix_matches(name, "", false));
    }

    #[test]
    fn a_leading_global_qualifier_anchors_the_spelling() {
        let global = "Codec::decode(int)";
        let namespaced = "widgets::Codec::decode(int)";
        assert!(qualified_suffix_matches(global, "::Codec::decode", false));
        assert!(!qualified_suffix_matches(
            namespaced,
            "::Codec::decode",
            false
        ));
        assert!(!qualified_suffix_matches(namespaced, "::decode", false));
        assert!(qualified_suffix_matches("decode(int)", "::decode", false));
    }

    #[test]
    fn qualified_exact_requires_the_whole_name() {
        let name = "widgets::Codec::decode(const unsigned char *, size_t)";
        assert!(qualified_exact_matches(
            name,
            "widgets::Codec::decode",
            false
        ));
        assert!(qualified_exact_matches(
            name,
            "::widgets::Codec::decode(const unsigned char*,size_t)",
            false
        ));
        assert!(!qualified_exact_matches(name, "Codec::decode", false));
        assert!(!qualified_exact_matches(name, "decode", false));
        assert!(!qualified_exact_matches(
            name,
            "widgets::Codec::decode(int)",
            false
        ));
    }

    #[test]
    fn qualified_suffix_handles_dotted_and_case_insensitive_lanes() {
        assert!(qualified_suffix_matches("Root.Pkg.Op", "pkg.op", true));
        assert!(!qualified_suffix_matches("Root.Pkg.Op", "pkg.op", false));
        assert!(qualified_suffix_matches("Root.Pkg.Op", "Pkg.Op", false));
        assert!(!qualified_suffix_matches("Root.Pkg.Op", "kg.Op", false));
    }

    #[test]
    fn an_unmatched_filter_names_the_closest_targets() {
        let ids = vec![
            "H-C0005-9F8BF5B5".to_owned(),
            "H-C0009-12345678".to_owned(),
            "H-X0002-AAAAAAAA".to_owned(),
        ];
        let note = unmatched_filter_note("--harness-id", "H-C0005-4D137CA4", &ids);
        assert!(
            note.contains(
                "--harness-id 'H-C0005-4D137CA4' matched no target; closest: H-C0005-9F8BF5B5"
            ),
            "{note}"
        );
        let files = vec!["src/parse.c".to_owned(), "src/table.c".to_owned()];
        let note = unmatched_filter_note("--target-file", "src/pars.c", &files);
        assert!(
            note.contains("matched no target; closest: src/parse.c"),
            "{note}"
        );
        let names = vec!["parse_record".to_owned(), "store".to_owned()];
        let note = unmatched_filter_note("--target", "parse_recrd", &names);
        assert!(
            note.contains("matched no target; closest: parse_record"),
            "{note}"
        );
    }

    #[test]
    fn closest_matches_prefers_same_leaf_then_typos() {
        let names = vec![
            "widgets::Codec::decode".to_owned(),
            "widgets::Table::store".to_owned(),
            "widgets::Codec::encode".to_owned(),
            "other::Decoder::decode".to_owned(),
            "unrelated_helper".to_owned(),
        ];
        let picked: Vec<&String> = closest_matches("Codec::decod", &names, |n| n, 5);
        assert_eq!(
            picked,
            vec![&names[0], &names[3]],
            "one-edit typos of the leaf, ordered by full-name distance"
        );
        let same_leaf: Vec<&String> = closest_matches("Widget::decode", &names, |n| n, 1);
        assert_eq!(same_leaf, vec![&names[0]]);
        assert!(closest_matches("zzz", &names, |n| n, 5).is_empty());
    }

    #[test]
    fn edit_distance_counts_single_char_edits() {
        assert_eq!(edit_distance("decode", "decode"), 0);
        assert_eq!(edit_distance("decod", "decode"), 1);
        assert_eq!(edit_distance("encode", "decode"), 2);
        assert_eq!(edit_distance("", "abc"), 3);
    }
}
