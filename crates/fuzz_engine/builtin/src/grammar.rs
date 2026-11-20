// SPDX-License-Identifier: Apache-2.0

//! User-supplied context-free grammar for structure-aware generation and tree
//! mutation in the built-in engine, in the manner of Nautilus (Aschermann et
//! al., NDSS 2019).
//!
//! The 14 built-in structured mutators cover common text/binary shapes heuristically,
//! but a bespoke legacy format (a mil-STD binary message, a domain-specific config,
//! a custom wire protocol) has structure no fixed mutator knows. A grammar lets the
//! operator describe that structure once and have the engine synthesize deeply-valid
//! inputs — reaching parser code past the surface checks that reject random bytes.
//!
//! Format: a JSON object mapping each non-terminal name to a list of production
//! strings. In a production, `{NAME}` references another non-terminal and everything
//! else is literal text. The start symbol is `START` if present, else the first rule.
//! The CLI parses the JSON (this crate has no serde dependency) and hands the rules to
//! [`Grammar::from_rules`].
//!
//! # Derivation trees
//!
//! [`Grammar::generate_tree`] returns a [`Derivation`]: the production chosen at
//! each non-terminal and the subtree of every non-terminal it references, whose
//! [`Grammar::sentence`] is the input. The engine keeps each grammar input's
//! tree and mutates the tree, so every mutant is a sentence of the grammar,
//! where a byte mutation of a sentence rarely is one:
//!
//! - [`Grammar::replace_subtree`] derives one subtree afresh from its
//!   non-terminal (Nautilus' random and rules mutations);
//! - [`Grammar::splice`] puts in another tree's subtree of the same
//!   non-terminal (Nautilus' splicing mutation);
//! - [`Grammar::pump_recursion`] repeats a recursion the tree has, a
//!   non-terminal under itself (Nautilus' random recursive mutation), which
//!   reaches nesting-depth bugs.
//!
//! Every non-terminal's smallest derivation is computed once, when the grammar
//! is built: a derivation falls back to it to end within its byte and node
//! budget, so a generated or mutated tree is always complete and never cut off
//! mid-sentence.
//!
//! [`Grammar::parse`] reads a tree back from a sentence (an Earley parse), and
//! [`Grammar::minimize`] reduces a finding's tree while it still reproduces:
//! each subtree replaced by its rule's smallest derivation, a same-rule
//! subtree inside it, or a smaller production that keeps its children, so the
//! minimized input stays a sentence.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt;

use crate::rng::MutationRng;

/// Past this depth a derivation takes each non-terminal's smallest production,
/// so a self-recursive grammar (`"A": ["({A})", "x"]`) ends.
const MAX_DEPTH: usize = 48;
/// How far before [`MAX_DEPTH`] the derivation starts to collapse toward its
/// smallest productions.
const COLLAPSE_MARGIN: usize = 8;
/// The deepest smallest derivation a grammar may have: a deeper one is a chain of
/// hundreds of rules, and a derivation that deep would recurse past the stack.
const MAX_SMALLEST_HEIGHT: usize = 512;
/// The tallest tree a mutation hands back; a recursion pumped past it is
/// refused, so walking, copying or dropping a tree stays within the stack.
const MAX_TREE_HEIGHT: usize = 1024;
/// How many nodes a subtree replacement or a splice tries before it gives up:
/// one whose fresh subtree is the old one, or that the donor has no other
/// subtree for, is passed over.
const MUTATION_TRIES: usize = 16;
/// The most (ancestor, descendant) recursion pairs a pump picks from.
const MAX_RECURSION_PAIRS: usize = 256;
/// The longest input [`Grammar::parse`] parses.
const MAX_PARSE_LEN: usize = 64 * 1024;
/// The most Earley items, and tree-building steps, one parse may take: the
/// bound on an ambiguous grammar's chart.
const MAX_PARSE_WORK: usize = 1 << 22;
/// How many same-rule subtrees inside a node a minimization tries to hoist
/// into its place.
const MAX_HOISTS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Symbol {
    Literal(Vec<u8>),
    NonTerminal(usize),
}

/// A production as parsed, before its references are resolved to rule indices.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RawSymbol {
    Literal(Vec<u8>),
    NonTerminal(String),
}

/// The size of a derivation: the bytes of its sentence and its tree nodes.
/// Ordered by bytes, then nodes, so the smallest derivation is the shortest
/// sentence with the fewest nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Cost {
    len: usize,
    nodes: usize,
}

impl Cost {
    fn fits(self, budget: Cost) -> bool {
        self.len <= budget.len && self.nodes <= budget.nodes
    }

    fn plus(self, other: Cost) -> Cost {
        Cost {
            len: self.len.saturating_add(other.len),
            nodes: self.nodes.saturating_add(other.nodes),
        }
    }

    fn minus(self, other: Cost) -> Cost {
        Cost {
            len: self.len.saturating_sub(other.len),
            nodes: self.nodes.saturating_sub(other.nodes),
        }
    }
}

/// A non-terminal's smallest derivation: its size, the production it takes
/// and its tree's height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Smallest {
    cost: Cost,
    alt: usize,
    height: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grammar {
    names: Vec<String>,
    rules: Vec<Vec<Vec<Symbol>>>,
    start: usize,
    /// Per rule: its smallest derivation, `None` when it derives no finite
    /// sentence (it only recurses).
    smallest: Vec<Option<Smallest>>,
    /// Per rule and production: the size of the smallest derivation that takes
    /// that production, `None` when one of its non-terminals derives nothing.
    alt_cost: Vec<Vec<Option<Cost>>>,
}

/// A derivation tree of a [`Grammar`]: the production taken at a non-terminal
/// and, in order, the subtree of each non-terminal that production references.
/// Its sentence is [`Grammar::sentence`]. Every node records its sentence's
/// length, its node count and its height, so a mutation checks its byte and
/// node budget without walking the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    rule: usize,
    alt: usize,
    /// The literal bytes of this node's own production.
    own: usize,
    len: usize,
    nodes: usize,
    height: usize,
    children: Vec<Derivation>,
}

impl Derivation {
    /// The length of the tree's sentence, in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The tree's nodes, one per non-terminal derived.
    pub fn node_count(&self) -> usize {
        self.nodes
    }

    /// About the bytes of memory the tree holds, for a caller that bounds
    /// what it keeps.
    pub fn footprint(&self) -> usize {
        self.nodes.saturating_mul(std::mem::size_of::<Derivation>())
    }

    fn cost(&self) -> Cost {
        Cost {
            len: self.len,
            nodes: self.nodes,
        }
    }

    fn recount(&mut self) {
        self.len = self.own + self.children.iter().map(|c| c.len).sum::<usize>();
        self.nodes = 1 + self.children.iter().map(|c| c.nodes).sum::<usize>();
        self.height = 1 + self.children.iter().map(|c| c.height).max().unwrap_or(0);
    }

    /// The subtree at preorder index `k` (0 is this node), and its depth.
    fn nth(&self, mut k: usize) -> Option<(&Derivation, usize)> {
        let mut node = self;
        let mut depth = 0;
        'descend: loop {
            if k == 0 {
                return Some((node, depth));
            }
            k -= 1;
            for child in &node.children {
                if k < child.nodes {
                    node = child;
                    depth += 1;
                    continue 'descend;
                }
                k -= child.nodes;
            }
            return None;
        }
    }

    /// Replace the subtree at preorder index `k` with what `make` returns for
    /// it (given it and its depth), recounting every ancestor. False when `k`
    /// is past the tree or `make` returns `None`.
    fn replace_nth(
        &mut self,
        k: usize,
        depth: usize,
        make: &mut dyn FnMut(&Derivation, usize) -> Option<Derivation>,
    ) -> bool {
        if k == 0 {
            return match make(self, depth) {
                Some(replacement) => {
                    *self = replacement;
                    true
                }
                None => false,
            };
        }
        let mut k = k - 1;
        for child in self.children.iter_mut() {
            if k < child.nodes {
                let replaced = child.replace_nth(k, depth + 1, make);
                if replaced {
                    self.recount();
                }
                return replaced;
            }
            k -= child.nodes;
        }
        false
    }
}

/// The node budget of a derivation whose sentence is at most `max_len` bytes:
/// room for a few nodes per byte (whitespace and optional rules derive empty
/// subtrees), bounded so a mutation's tree walk stays cheap.
fn node_budget(max_len: usize) -> usize {
    max_len.saturating_mul(4).clamp(1024, 1 << 16)
}

fn budget(max_len: usize) -> Cost {
    Cost {
        len: max_len,
        nodes: node_budget(max_len),
    }
}

impl Grammar {
    /// Build a grammar from `(name, productions)` rules, each production a string in
    /// the `{NAME}`-reference format. `start` selects the start symbol (defaults to
    /// `START` if present, else the first rule). Returns an error for an empty
    /// grammar, an empty rule, a reference to an undefined non-terminal, or a
    /// grammar whose smallest derivation nests deeper than a derivation may.
    pub fn from_rules(
        rules: &[(String, Vec<String>)],
        start: Option<&str>,
    ) -> Result<Self, String> {
        if rules.is_empty() {
            return Err("grammar has no rules".to_owned());
        }
        let mut names: Vec<String> = Vec::with_capacity(rules.len());
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut raw: Vec<Vec<Vec<RawSymbol>>> = Vec::with_capacity(rules.len());
        for (name, productions) in rules {
            if productions.is_empty() {
                return Err(format!("grammar rule {name:?} has no productions"));
            }
            let alts = productions.iter().map(|p| parse_production(p)).collect();
            // A rule given twice keeps its last productions.
            match index.get(name) {
                Some(&at) => raw[at] = alts,
                None => {
                    index.insert(name.clone(), names.len());
                    names.push(name.clone());
                    raw.push(alts);
                }
            }
        }
        let mut resolved: Vec<Vec<Vec<Symbol>>> = Vec::with_capacity(raw.len());
        for (name, alts) in names.iter().zip(raw) {
            let mut rule = Vec::with_capacity(alts.len());
            for alt in alts {
                let mut symbols = Vec::with_capacity(alt.len());
                for symbol in alt {
                    symbols.push(match symbol {
                        RawSymbol::Literal(bytes) => Symbol::Literal(bytes),
                        RawSymbol::NonTerminal(nt) => match index.get(&nt) {
                            Some(&at) => Symbol::NonTerminal(at),
                            None => {
                                return Err(format!(
                                "grammar rule {name:?} references undefined non-terminal {{{nt}}}"
                            ))
                            }
                        },
                    });
                }
                rule.push(symbols);
            }
            resolved.push(rule);
        }
        let start = match start {
            Some(s) => *index
                .get(s)
                .ok_or_else(|| format!("start symbol {s:?} is not a defined rule"))?,
            None => index.get("START").copied().unwrap_or(0),
        };
        let smallest = smallest_derivations(&resolved);
        if let Some((at, deepest)) = smallest
            .iter()
            .enumerate()
            .filter_map(|(at, s)| s.map(|s| (at, s.height)))
            .max_by_key(|(_, height)| *height)
            .filter(|(_, height)| *height > MAX_SMALLEST_HEIGHT)
        {
            return Err(format!(
                "grammar rule {:?}'s smallest derivation nests {deepest} rules deep, past the \
                 {MAX_SMALLEST_HEIGHT} a derivation may",
                names[at]
            ));
        }
        let alt_cost = resolved
            .iter()
            .map(|alts| {
                alts.iter()
                    .map(|symbols| production_cost(symbols, &smallest))
                    .collect()
            })
            .collect();
        Ok(Self {
            names,
            rules: resolved,
            start,
            smallest,
            alt_cost,
        })
    }

    /// Synthesize one derivation from the start symbol into bytes, at most
    /// `max_len` of them. Returns `None` when the grammar has no sentence that
    /// short, or its derivation is empty.
    pub fn generate(&self, max_len: usize, rng: &mut MutationRng) -> Option<Vec<u8>> {
        let tree = self.generate_tree(max_len, rng)?;
        (!tree.is_empty()).then(|| self.sentence(&tree))
    }

    /// A random derivation tree from the start symbol whose sentence is at most
    /// `max_len` bytes. `None` when the grammar has no sentence that short (a
    /// grammar that only recurses has none).
    pub fn generate_tree(&self, max_len: usize, rng: &mut MutationRng) -> Option<Derivation> {
        let fits = self.smallest[self.start]?.cost.fits(budget(max_len));
        fits.then(|| self.derive(self.start, 0, budget(max_len), rng))
    }

    /// The sentence `tree` derives: its productions' literals, with each
    /// non-terminal's subtree in its place.
    pub fn sentence(&self, tree: &Derivation) -> Vec<u8> {
        let mut out = Vec::with_capacity(tree.len);
        self.write_sentence(tree, &mut out);
        out
    }

    fn write_sentence(&self, node: &Derivation, out: &mut Vec<u8>) {
        let mut children = node.children.iter();
        for symbol in &self.rules[node.rule][node.alt] {
            match symbol {
                Symbol::Literal(bytes) => out.extend_from_slice(bytes),
                Symbol::NonTerminal(_) => {
                    if let Some(child) = children.next() {
                        self.write_sentence(child, out);
                    }
                }
            }
        }
    }

    /// The name of the non-terminal a tree node derives.
    pub fn rule_name(&self, tree: &Derivation) -> &str {
        &self.names[tree.rule]
    }

    /// `tree` with one random subtree derived afresh from its non-terminal,
    /// the whole sentence at most `max_len` bytes. A subtree derived again as
    /// it was (a rule with one short production) is passed over for another
    /// node; `None` when every try gave the same subtree back.
    pub fn replace_subtree(
        &self,
        tree: &Derivation,
        max_len: usize,
        rng: &mut MutationRng,
    ) -> Option<Derivation> {
        let room = budget(max_len).minus(tree.cost());
        for _ in 0..MUTATION_TRIES {
            let k = rng.choose_index(tree.nodes)?;
            let (node, depth) = tree.nth(k)?;
            let fresh = self.derive(node.rule, depth, room.plus(node.cost()), rng);
            if fresh == *node {
                continue;
            }
            let mut fresh = Some(fresh);
            let mut out = tree.clone();
            if out.replace_nth(k, 0, &mut |_, _| fresh.take()) {
                return Some(out);
            }
        }
        None
    }

    /// `tree` with one subtree replaced by a subtree of `donor` that derives
    /// the same non-terminal, the whole sentence at most `max_len` bytes.
    /// `None` when no node of `tree` the tries pick has a different such
    /// subtree in `donor` that fits.
    pub fn splice(
        &self,
        tree: &Derivation,
        donor: &Derivation,
        max_len: usize,
        rng: &mut MutationRng,
    ) -> Option<Derivation> {
        let room = budget(max_len).minus(tree.cost());
        for _ in 0..MUTATION_TRIES {
            let k = rng.choose_index(tree.nodes)?;
            let (node, depth) = tree.nth(k)?;
            let budget = room.plus(node.cost());
            let mut candidates: Vec<&Derivation> = Vec::new();
            collect_rule(donor, node.rule, &mut candidates);
            candidates.retain(|candidate| {
                candidate.cost().fits(budget)
                    && *candidate != node
                    && depth + candidate.height <= MAX_TREE_HEIGHT
            });
            let Some(pick) = rng.choose_index(candidates.len()) else {
                continue;
            };
            let mut donated = Some(candidates[pick].clone());
            let mut out = tree.clone();
            if out.replace_nth(k, 0, &mut |_, _| donated.take()) {
                return Some(out);
            }
        }
        None
    }

    /// `tree` with a recursion repeated: a node whose subtree derives its own
    /// non-terminal again is put in place of that inner occurrence, two to five
    /// times over, as far as the sentence stays within `max_len` bytes and the
    /// tree within its height bound. `None` when the tree has no recursion or
    /// not even one repeat fits.
    pub fn pump_recursion(
        &self,
        tree: &Derivation,
        max_len: usize,
        rng: &mut MutationRng,
    ) -> Option<Derivation> {
        let mut pairs = Vec::new();
        let mut path = Vec::new();
        let mut next = 0;
        recursion_pairs(tree, &mut path, &mut next, &mut pairs);
        let (outer, inner) = pairs[rng.choose_index(pairs.len())?];
        let (outer_tree, depth) = tree.nth(outer)?;
        let offset = inner - outer;
        let room = budget(max_len).minus(tree.cost()).plus(outer_tree.cost());
        let repeats = 2 + rng.choose_index(4)?;
        // `pumped` holds the recursion once; each round puts the outer subtree
        // around it again.
        let mut pumped = outer_tree.clone();
        let mut grew = false;
        for _ in 1..repeats {
            let mut wider = outer_tree.clone();
            let mut inside = Some(pumped.clone());
            if !wider.replace_nth(offset, 0, &mut |_, _| inside.take()) {
                break;
            }
            if !wider.cost().fits(room) || depth + wider.height > MAX_TREE_HEIGHT {
                break;
            }
            pumped = wider;
            grew = true;
        }
        if !grew {
            return None;
        }
        let mut pumped = Some(pumped);
        let mut out = tree.clone();
        out.replace_nth(outer, 0, &mut |_, _| pumped.take())
            .then_some(out)
    }

    /// One tree mutation of `tree`: most often a subtree derived afresh, and
    /// otherwise a recursion pumped (a fresh subtree when the tree has none).
    pub fn mutate_tree(
        &self,
        tree: &Derivation,
        max_len: usize,
        rng: &mut MutationRng,
    ) -> Option<Derivation> {
        if rng.next_u64().is_multiple_of(4) {
            if let Some(pumped) = self.pump_recursion(tree, max_len, rng) {
                return Some(pumped);
            }
        }
        self.replace_subtree(tree, max_len, rng)
    }

    /// A derivation of `rule` within `budget`, which its smallest derivation
    /// fits. A production is drawn at random among those whose smallest
    /// derivation fits; near [`MAX_DEPTH`] the smallest production is taken.
    fn derive(&self, rule: usize, depth: usize, budget: Cost, rng: &mut MutationRng) -> Derivation {
        let smallest = self.smallest[rule].expect("derive is only called for a productive rule");
        let alt = if depth + COLLAPSE_MARGIN >= MAX_DEPTH {
            smallest.alt
        } else {
            let fitting: Vec<usize> = self.alt_cost[rule]
                .iter()
                .enumerate()
                .filter(|(_, cost)| cost.is_some_and(|cost| cost.fits(budget)))
                .map(|(alt, _)| alt)
                .collect();
            rng.choose_index(fitting.len())
                .map_or(smallest.alt, |pick| fitting[pick])
        };
        let symbols = &self.rules[rule][alt];
        let own: usize = symbols
            .iter()
            .map(|symbol| match symbol {
                Symbol::Literal(bytes) => bytes.len(),
                Symbol::NonTerminal(_) => 0,
            })
            .sum();
        let child_rules: Vec<usize> = symbols
            .iter()
            .filter_map(|symbol| match symbol {
                Symbol::NonTerminal(child) => Some(*child),
                Symbol::Literal(_) => None,
            })
            .collect();
        // What the children may use, less what the later ones need at least.
        let mut left = budget.minus(Cost { len: own, nodes: 1 });
        let mut reserved = child_rules
            .iter()
            .fold(Cost { len: 0, nodes: 0 }, |sum, &child| {
                sum.plus(self.smallest_cost(child))
            });
        let mut children = Vec::with_capacity(child_rules.len());
        for child in child_rules {
            reserved = reserved.minus(self.smallest_cost(child));
            let subtree = self.derive(child, depth + 1, left.minus(reserved), rng);
            left = left.minus(subtree.cost());
            children.push(subtree);
        }
        let mut node = Derivation {
            rule,
            alt,
            own,
            len: 0,
            nodes: 0,
            height: 0,
            children,
        };
        node.recount();
        node
    }

    fn smallest_cost(&self, rule: usize) -> Cost {
        self.smallest[rule].map_or(
            Cost {
                len: usize::MAX,
                nodes: usize::MAX,
            },
            |smallest| smallest.cost,
        )
    }

    /// The smallest derivation of a productive `rule`: its smallest
    /// production, with each non-terminal's smallest derivation in its place.
    fn smallest_tree(&self, rule: usize) -> Derivation {
        let smallest = self.smallest[rule].expect("only a productive rule has a tree");
        let children = self.rules[rule][smallest.alt]
            .iter()
            .filter_map(|symbol| match symbol {
                Symbol::NonTerminal(child) => Some(self.smallest_tree(*child)),
                Symbol::Literal(_) => None,
            })
            .collect();
        self.node(rule, smallest.alt, children)
    }

    /// A node taking production `alt` of `rule` over `children`, counted.
    fn node(&self, rule: usize, alt: usize, children: Vec<Derivation>) -> Derivation {
        let own = self.rules[rule][alt]
            .iter()
            .map(|symbol| match symbol {
                Symbol::Literal(bytes) => bytes.len(),
                Symbol::NonTerminal(_) => 0,
            })
            .sum();
        let mut node = Derivation {
            rule,
            alt,
            own,
            len: 0,
            nodes: 0,
            height: 0,
            children,
        };
        node.recount();
        node
    }

    /// A derivation tree of `input` from the start symbol: an Earley parse
    /// (with the Aycock-Horspool step for rules that derive the empty
    /// sentence), from whose chart one derivation is read back. An input
    /// that is no sentence of the grammar, or that the parse cannot settle
    /// within its bounds, is an error that says which.
    pub fn parse(&self, input: &[u8]) -> Result<Derivation, ParseError> {
        if input.len() > MAX_PARSE_LEN {
            return Err(ParseError::TooLong {
                len: input.len(),
                max: MAX_PARSE_LEN,
            });
        }
        let flat = self.flat_productions();
        let chart = Chart::fill(self, &flat, input)?;
        let mut reader = TreeReader {
            flat: &flat,
            chart: &chart,
            input,
            decisions: HashMap::new(),
            active: HashSet::new(),
            steps: 0,
        };
        let whole = (self.start, 0, input.len());
        if !reader.resolve(whole, 0) {
            return Err(if reader.steps > MAX_PARSE_WORK {
                ParseError::TooAmbiguous {
                    work: MAX_PARSE_WORK,
                }
            } else {
                ParseError::TooDeep {
                    max: MAX_TREE_HEIGHT,
                }
            });
        }
        let tree = reader.tree(self, whole);
        // The tree read back derives exactly the input.
        debug_assert_eq!(self.sentence(&tree), input);
        Ok(tree)
    }

    /// Each production as one symbol per byte of its literals.
    fn flat_productions(&self) -> Vec<Vec<Vec<Flat>>> {
        self.rules
            .iter()
            .map(|alts| {
                alts.iter()
                    .map(|symbols| {
                        symbols
                            .iter()
                            .flat_map(|symbol| match symbol {
                                Symbol::Literal(bytes) => {
                                    bytes.iter().map(|&byte| Flat::Byte(byte)).collect()
                                }
                                Symbol::NonTerminal(rule) => vec![Flat::Rule(*rule)],
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }

    /// Reduce `tree` while `holds` says its sentence still does what the
    /// original did (a finding still reproduces), as Nautilus and Perses
    /// minimize: for each node, outermost first, its rule's smallest
    /// derivation, a same-rule subtree inside it hoisted into its place, or
    /// another production of its rule that keeps the children it can, each
    /// tried only where it is smaller. Every candidate is a derivation, so the
    /// result is a sentence of the grammar. Stops after `max_runs` runs of
    /// `holds`; a candidate whose sentence is the current one is taken
    /// without a run.
    pub fn minimize<E>(
        &self,
        tree: &Derivation,
        max_runs: usize,
        mut holds: impl FnMut(&[u8]) -> Result<bool, E>,
    ) -> Result<GrammarMinimization, E> {
        let mut current = tree.clone();
        let mut sentence = self.sentence(&current);
        let (mut tried, mut kept) = (0, 0);
        'passes: loop {
            let mut changed = false;
            let mut k = 0;
            while k < current.nodes {
                let mut accepted = false;
                for candidate in self.reductions(&current, k) {
                    let candidate_sentence = self.sentence(&candidate);
                    if candidate_sentence != sentence {
                        if tried >= max_runs {
                            break 'passes;
                        }
                        tried += 1;
                        if !holds(&candidate_sentence)? {
                            continue;
                        }
                        kept += 1;
                    }
                    current = candidate;
                    sentence = candidate_sentence;
                    accepted = true;
                    changed = true;
                    break;
                }
                // A node just reduced may reduce again; otherwise move on.
                if !accepted {
                    k += 1;
                }
            }
            if !changed {
                break;
            }
        }
        Ok(GrammarMinimization {
            tree: current,
            tried,
            kept,
        })
    }

    /// The trees `tree` becomes with node `k` reduced, each smaller than it,
    /// most reduced first.
    fn reductions(&self, tree: &Derivation, k: usize) -> Vec<Derivation> {
        let Some((node, _)) = tree.nth(k) else {
            return Vec::new();
        };
        let mut replacements: Vec<Derivation> = Vec::new();
        if self.smallest[node.rule].is_some() {
            replacements.push(self.smallest_tree(node.rule));
        }
        let mut inside = Vec::new();
        for child in &node.children {
            collect_rule(child, node.rule, &mut inside);
        }
        inside.sort_by_key(|subtree| subtree.cost());
        replacements.extend(inside.into_iter().take(MAX_HOISTS).cloned());
        for alt in 0..self.rules[node.rule].len() {
            if alt != node.alt && self.alt_cost[node.rule][alt].is_some() {
                replacements.push(self.keeping_children(node, alt));
            }
        }
        replacements.retain(|replacement| replacement.cost() < node.cost());
        replacements.sort_by_key(|replacement| replacement.cost());
        replacements.dedup();
        replacements
            .into_iter()
            .filter_map(|replacement| {
                let mut replacement = Some(replacement);
                let mut out = tree.clone();
                out.replace_nth(k, 0, &mut |_, _| replacement.take())
                    .then_some(out)
            })
            .collect()
    }

    /// `node` with production `alt` of its rule instead, each of whose
    /// non-terminals takes the next of `node`'s children of its rule, in
    /// order, and its smallest derivation when none is left.
    fn keeping_children(&self, node: &Derivation, alt: usize) -> Derivation {
        let mut next = 0;
        let children = self.rules[node.rule][alt]
            .iter()
            .filter_map(|symbol| match symbol {
                Symbol::NonTerminal(rule) => Some(*rule),
                Symbol::Literal(_) => None,
            })
            .map(|rule| {
                match node.children[next.min(node.children.len())..]
                    .iter()
                    .position(|child| child.rule == rule)
                {
                    Some(offset) => {
                        next += offset + 1;
                        node.children[next - 1].clone()
                    }
                    None => self.smallest_tree(rule),
                }
            })
            .collect();
        self.node(node.rule, alt, children)
    }
}

/// What [`Grammar::minimize`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarMinimization {
    /// The smallest tree that still held.
    pub tree: Derivation,
    /// Candidates run.
    pub tried: usize,
    /// Candidates that held and were kept.
    pub kept: usize,
}

/// Why [`Grammar::parse`] has no tree for an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input is no sentence of the grammar: no parse reads past byte
    /// `at`.
    NotASentence {
        at: usize,
    },
    TooLong {
        len: usize,
        max: usize,
    },
    /// The grammar is so ambiguous for the input that the parse took more
    /// than `work` items or steps.
    TooAmbiguous {
        work: usize,
    },
    /// The input's derivation nests deeper than `max`.
    TooDeep {
        max: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::NotASentence { at } => write!(
                f,
                "the input is not a sentence of the grammar: no derivation reads past byte {at}"
            ),
            ParseError::TooLong { len, max } => write!(
                f,
                "the input is {len} bytes, past the {max} bytes a grammar parse takes"
            ),
            ParseError::TooAmbiguous { work } => write!(
                f,
                "the grammar is too ambiguous for the input: its parse took more than {work} steps"
            ),
            ParseError::TooDeep { max } => write!(
                f,
                "the input's derivation nests deeper than the {max} levels a tree may"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// A production symbol as the parser reads it: one byte, or a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flat {
    Byte(u8),
    Rule(usize),
}

/// An Earley item: a production of a rule, how many of its symbols are read,
/// and where it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Item {
    rule: usize,
    alt: usize,
    dot: usize,
    origin: usize,
}

/// An Earley chart: the items at each input position, and which rules were
/// completed there from which start.
struct Chart {
    items: Vec<HashSet<Item>>,
    completed: Vec<HashSet<(usize, usize)>>,
}

impl Chart {
    fn fill(grammar: &Grammar, flat: &[Vec<Vec<Flat>>], input: &[u8]) -> Result<Self, ParseError> {
        // A rule whose smallest sentence is empty derives the empty sentence.
        let nullable: Vec<bool> = grammar
            .smallest
            .iter()
            .map(|smallest| smallest.is_some_and(|s| s.cost.len == 0))
            .collect();
        let n = input.len();
        let mut order: Vec<Vec<Item>> = vec![Vec::new(); n + 1];
        let mut items: Vec<HashSet<Item>> = vec![HashSet::new(); n + 1];
        let mut completed: Vec<HashSet<(usize, usize)>> = vec![HashSet::new(); n + 1];
        // Per position, the items waiting on each rule there.
        let mut waiting: Vec<HashMap<usize, Vec<Item>>> = vec![HashMap::new(); n + 1];
        let mut total = 0usize;
        let mut furthest = 0;
        for alt in 0..flat[grammar.start].len() {
            let item = Item {
                rule: grammar.start,
                alt,
                dot: 0,
                origin: 0,
            };
            if items[0].insert(item) {
                order[0].push(item);
            }
        }
        for at in 0..=n {
            let mut next = 0;
            while next < order[at].len() {
                let item = order[at][next];
                next += 1;
                total += 1;
                if total > MAX_PARSE_WORK {
                    return Err(ParseError::TooAmbiguous {
                        work: MAX_PARSE_WORK,
                    });
                }
                if !order[at].is_empty() {
                    furthest = at;
                }
                let mut add = |position: usize, new: Item, order: &mut Vec<Vec<Item>>| {
                    if items[position].insert(new) {
                        order[position].push(new);
                    }
                };
                match flat[item.rule][item.alt].get(item.dot) {
                    Some(Flat::Rule(rule)) => {
                        waiting[at].entry(*rule).or_default().push(item);
                        for alt in 0..flat[*rule].len() {
                            let predicted = Item {
                                rule: *rule,
                                alt,
                                dot: 0,
                                origin: at,
                            };
                            add(at, predicted, &mut order);
                        }
                        if nullable[*rule] {
                            let skipped = Item {
                                dot: item.dot + 1,
                                ..item
                            };
                            add(at, skipped, &mut order);
                        }
                    }
                    Some(Flat::Byte(byte)) => {
                        if input.get(at) == Some(byte) {
                            let scanned = Item {
                                dot: item.dot + 1,
                                ..item
                            };
                            add(at + 1, scanned, &mut order);
                        }
                    }
                    None => {
                        completed[at].insert((item.rule, item.origin));
                        let parents = waiting[item.origin]
                            .get(&item.rule)
                            .cloned()
                            .unwrap_or_default();
                        for parent in parents {
                            let advanced = Item {
                                dot: parent.dot + 1,
                                ..parent
                            };
                            add(at, advanced, &mut order);
                        }
                    }
                }
            }
        }
        if !completed[n].contains(&(grammar.start, 0)) {
            return Err(ParseError::NotASentence { at: furthest });
        }
        Ok(Self { items, completed })
    }

    fn has(&self, at: usize, item: Item) -> bool {
        self.items[at].contains(&item)
    }
}

/// A rule over an input span: `(rule, start, end)`.
type Span = (usize, usize, usize);

/// Reads one derivation back out of a filled [`Chart`]: for a rule over a
/// span, a production completed there, and the split of the span between
/// its symbols. Each resolved (rule, start, end) is kept, so it is read once.
struct TreeReader<'a> {
    flat: &'a [Vec<Vec<Flat>>],
    chart: &'a Chart,
    input: &'a [u8],
    /// For each resolved (rule, start, end): its production and its
    /// children's (rule, start, end), in order.
    decisions: HashMap<Span, (usize, Vec<Span>)>,
    /// The spans being resolved, so a cycle of rules over one span is cut.
    active: HashSet<Span>,
    steps: usize,
}

impl TreeReader<'_> {
    fn resolve(&mut self, span: Span, depth: usize) -> bool {
        if self.decisions.contains_key(&span) {
            return true;
        }
        if depth > MAX_TREE_HEIGHT || self.steps > MAX_PARSE_WORK || !self.active.insert(span) {
            return false;
        }
        let (rule, start, end) = span;
        let mut found = None;
        for alt in 0..self.flat[rule].len() {
            let len = self.flat[rule][alt].len();
            let item = Item {
                rule,
                alt,
                dot: len,
                origin: start,
            };
            if !self.chart.has(end, item) {
                continue;
            }
            let mut children = Vec::new();
            if self.split(item, end, depth, &mut children) {
                children.reverse();
                found = Some((alt, children));
                break;
            }
        }
        self.active.remove(&span);
        match found {
            Some(decision) => {
                self.decisions.insert(span, decision);
                true
            }
            None => false,
        }
    }

    /// Whether `item`, in the chart at `at`, has a split of its span: its
    /// read symbols matched, right to left, onto the input and onto resolved
    /// children, which are pushed onto `children` last first.
    fn split(&mut self, item: Item, at: usize, depth: usize, children: &mut Vec<Span>) -> bool {
        self.steps += 1;
        if self.steps > MAX_PARSE_WORK {
            return false;
        }
        if item.dot == 0 {
            return at == item.origin;
        }
        let before = Item {
            dot: item.dot - 1,
            ..item
        };
        match self.flat[item.rule][item.alt][item.dot - 1] {
            Flat::Byte(byte) => {
                at > item.origin
                    && self.input[at - 1] == byte
                    && self.chart.has(at - 1, before)
                    && self.split(before, at - 1, depth, children)
            }
            Flat::Rule(rule) => {
                for from in (item.origin..=at).rev() {
                    if !self.chart.has(from, before)
                        || !self.chart.completed[at].contains(&(rule, from))
                        || !self.resolve((rule, from, at), depth + 1)
                    {
                        continue;
                    }
                    children.push((rule, from, at));
                    if self.split(before, from, depth, children) {
                        return true;
                    }
                    children.pop();
                }
                false
            }
        }
    }

    fn tree(&self, grammar: &Grammar, span: Span) -> Derivation {
        let (alt, children) = &self.decisions[&span];
        let children = children
            .iter()
            .map(|&child| self.tree(grammar, child))
            .collect();
        grammar.node(span.0, *alt, children)
    }
}

/// Every subtree of `node` that derives `rule`, in preorder.
fn collect_rule<'t>(node: &'t Derivation, rule: usize, out: &mut Vec<&'t Derivation>) {
    if node.rule == rule {
        out.push(node);
    }
    for child in &node.children {
        collect_rule(child, rule, out);
    }
}

/// The (ancestor, descendant) preorder index pairs of `node`'s tree that
/// derive the same non-terminal, at most [`MAX_RECURSION_PAIRS`]: for each
/// node, its nearest ancestor of its rule.
fn recursion_pairs(
    node: &Derivation,
    path: &mut Vec<(usize, usize)>,
    next: &mut usize,
    pairs: &mut Vec<(usize, usize)>,
) {
    let here = *next;
    *next += 1;
    if pairs.len() < MAX_RECURSION_PAIRS {
        if let Some(&(_, ancestor)) = path.iter().rev().find(|(rule, _)| *rule == node.rule) {
            pairs.push((ancestor, here));
        }
    }
    path.push((node.rule, here));
    for child in &node.children {
        recursion_pairs(child, path, next, pairs);
    }
    path.pop();
}

/// The size of the smallest derivation that takes `symbols` as its first
/// production, given each rule's smallest; `None` when a non-terminal in it
/// derives nothing.
fn production_cost(symbols: &[Symbol], smallest: &[Option<Smallest>]) -> Option<Cost> {
    let mut cost = Cost { len: 0, nodes: 1 };
    for symbol in symbols {
        cost = cost.plus(match symbol {
            Symbol::Literal(bytes) => Cost {
                len: bytes.len(),
                nodes: 0,
            },
            Symbol::NonTerminal(child) => smallest[*child]?.cost,
        });
    }
    Some(cost)
}

/// Each rule's smallest derivation, by Knuth's generalization of Dijkstra's
/// algorithm to grammars (1977): rules are settled in order of their smallest
/// size, and a production is weighed once every non-terminal it references is
/// settled. A settled rule's production only references rules settled before
/// it, so following smallest productions always ends.
fn smallest_derivations(rules: &[Vec<Vec<Symbol>>]) -> Vec<Option<Smallest>> {
    // Where each rule is referenced: (rule, production) once per reference.
    let mut users: Vec<Vec<(usize, usize)>> = vec![Vec::new(); rules.len()];
    let mut pending: Vec<Vec<usize>> = Vec::with_capacity(rules.len());
    let mut heap: BinaryHeap<Reverse<(Cost, usize, usize)>> = BinaryHeap::new();
    for (rule, alts) in rules.iter().enumerate() {
        let mut counts = Vec::with_capacity(alts.len());
        for (alt, symbols) in alts.iter().enumerate() {
            let mut count = 0;
            for symbol in symbols {
                if let Symbol::NonTerminal(child) = symbol {
                    users[*child].push((rule, alt));
                    count += 1;
                }
            }
            if count == 0 {
                let len = symbols
                    .iter()
                    .map(|symbol| match symbol {
                        Symbol::Literal(bytes) => bytes.len(),
                        Symbol::NonTerminal(_) => 0,
                    })
                    .sum();
                heap.push(Reverse((Cost { len, nodes: 1 }, rule, alt)));
            }
            counts.push(count);
        }
        pending.push(counts);
    }
    let mut smallest: Vec<Option<Smallest>> = vec![None; rules.len()];
    while let Some(Reverse((cost, rule, alt))) = heap.pop() {
        if smallest[rule].is_some() {
            continue;
        }
        let height = 1 + rules[rule][alt]
            .iter()
            .filter_map(|symbol| match symbol {
                Symbol::NonTerminal(child) => smallest[*child].map(|s| s.height),
                Symbol::Literal(_) => None,
            })
            .max()
            .unwrap_or(0);
        smallest[rule] = Some(Smallest { cost, alt, height });
        for &(user, user_alt) in &users[rule] {
            pending[user][user_alt] -= 1;
            if pending[user][user_alt] == 0 && smallest[user].is_none() {
                if let Some(cost) = production_cost(&rules[user][user_alt], &smallest) {
                    heap.push(Reverse((cost, user, user_alt)));
                }
            }
        }
    }
    smallest
}

/// Split a production string into literal runs and `{NAME}` non-terminal references.
/// A `{` that does not open a valid `{IDENT}` reference is treated as a literal byte,
/// so ordinary braces in the target format survive.
fn parse_production(s: &str) -> Vec<RawSymbol> {
    let mut symbols = Vec::new();
    let mut literal: Vec<u8> = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(rel) = s[i + 1..].find('}') {
                let name = &s[i + 1..i + 1 + rel];
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    if !literal.is_empty() {
                        symbols.push(RawSymbol::Literal(std::mem::take(&mut literal)));
                    }
                    symbols.push(RawSymbol::NonTerminal(name.to_owned()));
                    i += 1 + rel + 1;
                    continue;
                }
            }
        }
        literal.push(bytes[i]);
        i += 1;
    }
    if !literal.is_empty() {
        symbols.push(RawSymbol::Literal(literal));
    }
    symbols
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn rules(pairs: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        pairs
            .iter()
            .map(|(name, prods)| {
                (
                    (*name).to_owned(),
                    prods.iter().map(|p| (*p).to_owned()).collect(),
                )
            })
            .collect()
    }

    /// `EXPR := EXPR + TERM | TERM`, `TERM := 1 | 2 | ( EXPR )`.
    fn arithmetic() -> Grammar {
        Grammar::from_rules(
            &rules(&[
                ("START", &["{EXPR}"]),
                ("EXPR", &["{EXPR}+{TERM}", "{TERM}"]),
                ("TERM", &["1", "2", "({EXPR})"]),
            ]),
            None,
        )
        .unwrap()
    }

    /// A recursive-descent recognizer of [`arithmetic`]'s language, written
    /// apart from the grammar: `TERM ('+' TERM)*`.
    fn is_arithmetic(s: &[u8]) -> bool {
        fn expr(s: &[u8], i: &mut usize) -> bool {
            if !term(s, i) {
                return false;
            }
            while s.get(*i) == Some(&b'+') {
                *i += 1;
                if !term(s, i) {
                    return false;
                }
            }
            true
        }
        fn term(s: &[u8], i: &mut usize) -> bool {
            match s.get(*i) {
                Some(b'1' | b'2') => {
                    *i += 1;
                    true
                }
                Some(b'(') => {
                    *i += 1;
                    if !expr(s, i) || s.get(*i) != Some(&b')') {
                        return false;
                    }
                    *i += 1;
                    true
                }
                _ => false,
            }
        }
        let mut i = 0;
        expr(s, &mut i) && i == s.len()
    }

    /// An Earley recognizer over the grammar's bytes, with the Aycock-Horspool
    /// step for nullable non-terminals: whether `input` is a sentence of `g`,
    /// decided by parsing it rather than by the derivation that produced it.
    fn earley_accepts(g: &Grammar, input: &[u8]) -> bool {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        enum Sym {
            Byte(u8),
            Nt(usize),
        }
        let flat: Vec<Vec<Vec<Sym>>> = g
            .rules
            .iter()
            .map(|alts| {
                alts.iter()
                    .map(|symbols| {
                        symbols
                            .iter()
                            .flat_map(|symbol| match symbol {
                                Symbol::Literal(bytes) => {
                                    bytes.iter().map(|&b| Sym::Byte(b)).collect()
                                }
                                Symbol::NonTerminal(nt) => vec![Sym::Nt(*nt)],
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let mut nullable = vec![false; flat.len()];
        loop {
            let mut changed = false;
            for (rule, alts) in flat.iter().enumerate() {
                if !nullable[rule]
                    && alts.iter().any(|alt| {
                        alt.iter()
                            .all(|sym| matches!(sym, Sym::Nt(nt) if nullable[*nt]))
                    })
                {
                    nullable[rule] = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        type Item = (usize, usize, usize, usize); // rule, alt, dot, origin
        let mut sets: Vec<Vec<Item>> = vec![Vec::new(); input.len() + 1];
        let mut seen: Vec<HashSet<Item>> = vec![HashSet::new(); input.len() + 1];
        let mut add = |sets: &mut Vec<Vec<Item>>, at: usize, item: Item| {
            if seen[at].insert(item) {
                sets[at].push(item);
            }
        };
        for alt in 0..flat[g.start].len() {
            add(&mut sets, 0, (g.start, alt, 0, 0));
        }
        for at in 0..=input.len() {
            let mut next = 0;
            while next < sets[at].len() {
                let (rule, alt, dot, origin) = sets[at][next];
                next += 1;
                match flat[rule][alt].get(dot) {
                    Some(Sym::Nt(nt)) => {
                        for predicted in 0..flat[*nt].len() {
                            add(&mut sets, at, (*nt, predicted, 0, at));
                        }
                        if nullable[*nt] {
                            add(&mut sets, at, (rule, alt, dot + 1, origin));
                        }
                    }
                    Some(Sym::Byte(byte)) => {
                        if input.get(at) == Some(byte) {
                            add(&mut sets, at + 1, (rule, alt, dot + 1, origin));
                        }
                    }
                    None => {
                        let waiting: Vec<Item> = sets[origin]
                            .iter()
                            .copied()
                            .filter(|&(r, a, d, _)| flat[r][a].get(d) == Some(&Sym::Nt(rule)))
                            .collect();
                        for (r, a, d, o) in waiting {
                            add(&mut sets, at, (r, a, d + 1, o));
                        }
                    }
                }
            }
        }
        sets[input.len()].iter().any(|&(rule, alt, dot, origin)| {
            rule == g.start && origin == 0 && dot == flat[rule][alt].len()
        })
    }

    /// A JSON-like grammar with nesting, optional whitespace (empty
    /// productions) and several rules referenced from several places.
    fn nested() -> Grammar {
        Grammar::from_rules(
            &rules(&[
                ("START", &["{VALUE}"]),
                (
                    "VALUE",
                    &[
                        "{OBJECT}", "{ARRAY}", "{STRING}", "{NUMBER}", "true", "null",
                    ],
                ),
                ("OBJECT", &["{{WS}}", "{{WS}{MEMBERS}{WS}}"]),
                ("MEMBERS", &["{MEMBER}", "{MEMBER},{MEMBERS}"]),
                ("MEMBER", &["{STRING}{WS}:{WS}{VALUE}"]),
                ("ARRAY", &["[{WS}]", "[{WS}{ITEMS}{WS}]"]),
                ("ITEMS", &["{VALUE}", "{VALUE},{WS}{ITEMS}"]),
                ("STRING", &["\"{CHARS}\""]),
                ("CHARS", &["", "{CHAR}{CHARS}"]),
                ("CHAR", &["a", "b", "z"]),
                ("NUMBER", &["{DIGIT}", "-{DIGIT}{DIGITS}"]),
                ("DIGITS", &["", "{DIGIT}{DIGITS}"]),
                ("DIGIT", &["0", "1", "7"]),
                ("WS", &["", " ", "\n"]),
            ]),
            None,
        )
        .unwrap()
    }

    #[test]
    fn parse_production_splits_literals_and_references() {
        assert_eq!(
            parse_production("( {EXPR} )"),
            vec![
                RawSymbol::Literal(b"( ".to_vec()),
                RawSymbol::NonTerminal("EXPR".to_owned()),
                RawSymbol::Literal(b" )".to_vec()),
            ]
        );
        // A brace that is not a valid reference stays literal.
        assert_eq!(
            parse_production("{ raw }"),
            vec![RawSymbol::Literal(b"{ raw }".to_vec())]
        );
    }

    #[test]
    fn undefined_nonterminal_is_rejected() {
        let err = Grammar::from_rules(&rules(&[("START", &["{MISSING}"])]), None).unwrap_err();
        assert!(err.contains("MISSING"), "got: {err}");
    }

    #[test]
    fn generate_only_emits_grammar_terminals() {
        // A tiny arithmetic grammar: every byte produced must be one the grammar can
        // emit, so a parser for this language accepts the output.
        let g = arithmetic();
        let mut rng = MutationRng::new(0xC0FFEE);
        let mut produced_nonempty = false;
        for _ in 0..64 {
            if let Some(out) = g.generate(256, &mut rng) {
                produced_nonempty = true;
                assert!(out.len() <= 256);
                assert!(
                    out.iter()
                        .all(|b| matches!(b, b'1' | b'2' | b'+' | b'(' | b')')),
                    "unexpected byte in {out:?}"
                );
            }
        }
        assert!(
            produced_nonempty,
            "grammar generated nothing across 64 draws"
        );
    }

    #[test]
    fn self_recursive_grammar_terminates() {
        // A grammar that can only recurse must not loop forever; it just yields empty.
        let g = Grammar::from_rules(&rules(&[("START", &["{START}"])]), None).unwrap();
        let mut rng = MutationRng::new(1);
        assert_eq!(g.generate(64, &mut rng), None);
        assert_eq!(g.generate_tree(64, &mut rng), None);
    }

    #[test]
    fn a_generated_tree_is_a_whole_sentence_within_max_len() {
        // A sentence is never cut off at `max_len`: the derivation takes
        // smaller productions as it nears it.
        let g = arithmetic();
        let mut rng = MutationRng::new(9);
        for max_len in [1, 3, 8, 64] {
            for _ in 0..200 {
                let tree = g.generate_tree(max_len, &mut rng).expect("a tree");
                let out = g.sentence(&tree);
                assert_eq!(out.len(), tree.len());
                assert!(out.len() <= max_len, "{max_len}: {out:?}");
                assert!(is_arithmetic(&out), "{out:?}");
            }
        }
        // No sentence of the grammar is shorter than one byte.
        assert_eq!(g.generate_tree(0, &mut rng), None);
    }

    #[test]
    fn the_smallest_derivation_is_the_shortest_sentence() {
        let g = Grammar::from_rules(
            &rules(&[
                ("START", &["{LONG}", "<{MID}>"]),
                ("LONG", &["abcdefgh"]),
                ("MID", &["{MID}{MID}", "xy", "z"]),
            ]),
            None,
        )
        .unwrap();
        let start = g.smallest[g.start].unwrap();
        assert_eq!(start.cost.len, 3, "`<z>`");
        assert_eq!(start.alt, 1);
        let mid = g.smallest[g.names.iter().position(|n| n == "MID").unwrap()].unwrap();
        assert_eq!((mid.cost.len, mid.alt), (1, 2));
        let mut rng = MutationRng::new(2);
        let tree = g.generate_tree(3, &mut rng).unwrap();
        assert_eq!(g.sentence(&tree), b"<z>");
    }

    #[test]
    fn a_grammar_nested_too_deep_for_a_derivation_is_rejected() {
        let chain: Vec<(String, Vec<String>)> = (0..=MAX_SMALLEST_HEIGHT)
            .map(|i| {
                let production = if i == MAX_SMALLEST_HEIGHT {
                    "x".to_owned()
                } else {
                    format!("{{R{}}}", i + 1)
                };
                (format!("R{i}"), vec![production])
            })
            .collect();
        let err = Grammar::from_rules(&chain, Some("R0")).unwrap_err();
        assert!(err.contains("nests") && err.contains("R0"), "{err}");
        // One rule fewer is within the bound.
        let shorter: Vec<(String, Vec<String>)> = chain[1..].to_vec();
        assert!(Grammar::from_rules(&shorter, Some("R1")).is_ok());
    }

    #[test]
    fn an_empty_recursion_does_not_blow_up_the_tree() {
        // `A -> AA | ""` derives only the empty sentence, through trees of any
        // size: the node budget keeps them bounded.
        let g = Grammar::from_rules(&rules(&[("A", &["{A}{A}", ""])]), None).unwrap();
        let mut rng = MutationRng::new(4);
        for _ in 0..50 {
            let tree = g.generate_tree(16, &mut rng).unwrap();
            assert!(tree.node_count() <= node_budget(16));
            assert!(tree.is_empty());
        }
    }

    /// Acceptance (#329): 1000 spliced outputs at a fixed seed are all valid
    /// sentences — of the arithmetic grammar, by its own recognizer, and of the
    /// nested grammar, by an Earley parse.
    #[test]
    fn one_thousand_spliced_outputs_are_all_valid_sentences() {
        for (name, g, accepts) in [
            (
                "arithmetic",
                arithmetic(),
                (|_: &Grammar, s: &[u8]| is_arithmetic(s)) as fn(&Grammar, &[u8]) -> bool,
            ),
            (
                "nested",
                nested(),
                earley_accepts as fn(&Grammar, &[u8]) -> bool,
            ),
        ] {
            let max_len = 256;
            let mut rng = MutationRng::new(0x5EED_0329);
            let mut pool: Vec<Derivation> = (0..16)
                .map(|_| g.generate_tree(max_len, &mut rng).unwrap())
                .collect();
            let mut spliced = 0;
            let mut new_sentences = 0;
            while spliced < 1000 {
                let a = rng.choose_index(pool.len()).unwrap();
                let b = rng.choose_index(pool.len()).unwrap();
                let Some(child) = g.splice(&pool[a], &pool[b], max_len, &mut rng) else {
                    continue;
                };
                spliced += 1;
                let out = g.sentence(&child);
                assert_eq!(out.len(), child.len());
                assert!(out.len() <= max_len, "{name}: {} bytes", out.len());
                assert!(
                    accepts(&g, &out),
                    "{name}: splice {spliced} is no sentence: {:?}",
                    String::from_utf8_lossy(&out)
                );
                if out != g.sentence(&pool[a]) {
                    new_sentences += 1;
                }
                // Splice the splices too, so subtrees travel between trees.
                let slot = rng.choose_index(pool.len()).unwrap();
                pool[slot] = child;
            }
            assert!(
                new_sentences > 500,
                "{name}: {new_sentences} of 1000 differ"
            );
        }
    }

    #[test]
    fn replaced_and_pumped_trees_are_valid_sentences() {
        let g = nested();
        let mut rng = MutationRng::new(0x329);
        let mut tree = g.generate_tree(512, &mut rng).unwrap();
        let (mut replaced, mut pumped) = (0, 0);
        for _ in 0..1000 {
            let Some(child) = g.mutate_tree(&tree, 512, &mut rng) else {
                tree = g.generate_tree(512, &mut rng).unwrap();
                continue;
            };
            let out = g.sentence(&child);
            assert!(out.len() <= 512);
            assert!(
                earley_accepts(&g, &out),
                "{:?}",
                String::from_utf8_lossy(&out)
            );
            if child.node_count() > tree.node_count() + 2 {
                pumped += 1;
            }
            replaced += 1;
            tree = child;
        }
        assert!(replaced > 900, "{replaced}");
        assert!(pumped > 0);
    }

    #[test]
    fn pumping_a_recursion_nests_it_deeper() {
        let g = Grammar::from_rules(&rules(&[("A", &["({A})", "x"])]), None).unwrap();
        let depth = |s: &[u8]| s.iter().filter(|&&b| b == b'(').count();
        let mut rng = MutationRng::new(6);
        // `((x))`: A over A over A.
        let tree = loop {
            let tree = g.generate_tree(64, &mut rng).unwrap();
            if depth(&g.sentence(&tree)) == 2 {
                break tree;
            }
        };
        let mut deeper = 0;
        for _ in 0..50 {
            let pumped = g.pump_recursion(&tree, 4096, &mut rng).unwrap();
            let out = g.sentence(&pumped);
            assert_eq!(out.len(), 2 * depth(&out) + 1, "{out:?}");
            assert!(depth(&out) > 2, "{out:?}");
            deeper = deeper.max(depth(&out));
        }
        assert!(deeper >= 4, "{deeper}");
        // No room past the tree as it is: no repeat fits.
        assert_eq!(g.pump_recursion(&tree, 5, &mut rng), None);
        // A tree without a recursion has nothing to pump.
        let flat = Grammar::from_rules(&rules(&[("A", &["x{B}"]), ("B", &["y"])]), None).unwrap();
        let leaf = flat.generate_tree(8, &mut rng).unwrap();
        assert_eq!(flat.pump_recursion(&leaf, 8, &mut rng), None);
    }

    #[test]
    fn a_splice_takes_a_subtree_of_the_same_rule_from_the_donor() {
        let g = Grammar::from_rules(
            &rules(&[
                ("START", &["<{NAME}={NUM}>"]),
                ("NAME", &["alpha", "beta"]),
                ("NUM", &["1", "22", "333"]),
            ]),
            None,
        )
        .unwrap();
        let mut rng = MutationRng::new(12);
        let (mut a, mut b);
        loop {
            a = g.generate_tree(64, &mut rng).unwrap();
            b = g.generate_tree(64, &mut rng).unwrap();
            let (sa, sb) = (g.sentence(&a), g.sentence(&b));
            if sa[1] != sb[1] && sa[sa.len() - 2] != sb[sb.len() - 2] {
                break;
            }
        }
        // `<NAME=NUM>` split into its two parts.
        let parts = |tree: &Derivation| {
            let text = String::from_utf8(g.sentence(tree)).unwrap();
            let (name, num) = text[1..text.len() - 1].split_once('=').unwrap();
            (name.to_owned(), num.to_owned())
        };
        let ((a_name, a_num), (b_name, b_num)) = (parts(&a), parts(&b));
        let allowed = [
            (b_name.clone(), a_num.clone()),
            (a_name.clone(), b_num.clone()),
            (b_name.clone(), b_num.clone()),
        ];
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let child = parts(&g.splice(&a, &b, 64, &mut rng).unwrap());
            // NAME, NUM or the whole START came from `b`; nothing else.
            assert!(
                allowed.contains(&child),
                "{child:?} from {a_name}={a_num}, {b_name}={b_num}"
            );
            seen.insert(child);
        }
        assert_eq!(
            seen.len(),
            3,
            "every same-rule subtree of the donor: {seen:?}"
        );
    }
    /// `LIST := ITEM | ITEM,LIST`, `ITEM := [WORD] | (LIST)`.
    fn list() -> Grammar {
        Grammar::from_rules(
            &rules(&[
                ("START", &["{LIST}"]),
                ("LIST", &["{ITEM}", "{ITEM},{LIST}"]),
                ("ITEM", &["[{WORD}]", "({LIST})"]),
                ("WORD", &["alpha", "beta", "BHFMAGIC", "gamma"]),
            ]),
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_parse_reads_back_a_tree_that_derives_the_input() {
        for g in [arithmetic(), nested(), list()] {
            let mut rng = MutationRng::new(0x369);
            for _ in 0..300 {
                let sentence = g.generate(256, &mut rng).unwrap_or_default();
                let tree = g
                    .parse(&sentence)
                    .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&sentence)));
                assert_eq!(g.sentence(&tree), sentence);
                assert_eq!(tree.len(), sentence.len());
            }
        }
    }

    #[test]
    fn a_parse_handles_empty_productions_and_rule_cycles() {
        // `A` derives itself, and `B` the empty sentence among others.
        let g = Grammar::from_rules(
            &rules(&[("A", &["{A}", "{B}{A}", ""]), ("B", &["b", "", "{B}{B}"])]),
            None,
        )
        .unwrap();
        for input in [&b""[..], b"b", b"bbbb"] {
            let tree = g.parse(input).unwrap();
            assert_eq!(g.sentence(&tree), input);
        }
        assert_eq!(
            g.parse(b"bab"),
            Err(ParseError::NotASentence { at: 1 }),
            "nothing reads the `a`"
        );
    }

    #[test]
    fn a_parse_refuses_what_is_no_sentence() {
        let g = arithmetic();
        for input in [&b"1+"[..], b"(1", b"12", b"", b"1+3"] {
            let error = g.parse(input).unwrap_err();
            assert!(
                matches!(error, ParseError::NotASentence { .. }),
                "{input:?}: {error}"
            );
        }
        assert_eq!(g.parse(b"1+(2+x)"), Err(ParseError::NotASentence { at: 5 }));
        let long = vec![b'1'; MAX_PARSE_LEN + 1];
        assert!(matches!(g.parse(&long), Err(ParseError::TooLong { .. })));
    }

    /// #369: a finding minimized on its tree is a smaller sentence that still
    /// does what it did; byte minimization of it would leave `BHFMAGIC`,
    /// which is no sentence.
    #[test]
    fn minimize_reduces_a_sentence_to_the_smallest_that_still_holds() {
        let g = list();
        let input = b"[alpha],([beta],([gamma],[BHFMAGIC])),[gamma]";
        let tree = g.parse(input).unwrap();
        let holds = |s: &[u8]| -> Result<bool, ()> { Ok(s.windows(8).any(|w| w == b"BHFMAGIC")) };
        let result = g.minimize(&tree, 10_000, holds).unwrap();
        let minimized = g.sentence(&result.tree);
        assert_eq!(minimized, b"[BHFMAGIC]");
        assert!(g.parse(&minimized).is_ok());
        assert!(result.kept > 0 && result.tried >= result.kept);
        assert!(
            g.parse(b"BHFMAGIC").is_err(),
            "the byte-minimal input is no sentence"
        );
    }

    #[test]
    fn minimize_keeps_every_candidate_a_sentence_and_stops_at_its_run_bound() {
        let g = nested();
        let mut rng = MutationRng::new(0x3690);
        for _ in 0..40 {
            let tree = g.generate_tree(256, &mut rng).unwrap();
            let original = g.sentence(&tree);
            // Holds while the sentence keeps the original's count of `[`.
            let brackets = |s: &[u8]| s.iter().filter(|&&b| b == b'[').count();
            let want = brackets(&original);
            let mut runs = 0;
            let result = g
                .minimize(&tree, 50, |candidate| -> Result<bool, ()> {
                    runs += 1;
                    assert!(earley_accepts(&g, candidate), "{candidate:?}");
                    Ok(brackets(candidate) == want)
                })
                .unwrap();
            let minimized = g.sentence(&result.tree);
            assert!(runs <= 50 && result.tried == runs);
            assert!(minimized.len() <= original.len());
            assert_eq!(brackets(&minimized), want);
            assert!(earley_accepts(&g, &minimized));
        }
    }

    #[test]
    fn minimize_returns_the_predicates_error() {
        let g = list();
        let tree = g.parse(b"[alpha],[beta]").unwrap();
        let error = g
            .minimize(&tree, 100, |_| Err::<bool, &str>("harness failed to start"))
            .unwrap_err();
        assert_eq!(error, "harness failed to start");
    }
}
