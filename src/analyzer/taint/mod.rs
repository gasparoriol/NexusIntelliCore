//! Intra-procedural taint engine over the tree-sitter AST (SAST v2, Fase 2).
//!
//! Each language has one query, compiled once from `rules::TAINT_PACKS`. Its
//! capture names drive the engine:
//!
//! | Capture | Meaning |
//! |---|---|
//! | `@function` | analysis scope (function, method, lambda, closure) |
//! | `@assign.lhs` / `@assign.rhs` | binding; a clean value clears taint outside branches |
//! | `@update.lhs` / `@update.rhs` | `+=`-style binding; never clears taint |
//! | `@prop.to` / `@prop.from` | mutation (`sb.append(x)`) taints the receiver |
//! | `@source` / `@source.<key>` | expression producing user input |
//! | `@source.param` | names bound by this pattern start tainted |
//! | `@sink.<key>[.write]` | argument that must not be tainted |
//! | `@sanitizer[.<key>]` | expression whose result is clean |
//! | `@guard.<key>` | value validated by a condition (`if (!p.startsWith(base + sep))`) |
//! | `@_name` | helper capture used only by predicates |
//!
//! Functions are analysed independently in source order. A variable is the
//! text of an `identifier` node inside the function (method/field names are
//! excluded), or the full text of a member access (`this.path`). Any
//! expression containing a source or a tainted variable is tainted unless the
//! path crosses a sanitizer. Flows across functions or files are not tracked.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{LazyLock, OnceLock};
use tree_sitter::{Language, Node, Query, QueryCursor, Tree};

use super::lang::LANGUAGE_REGISTRY;
use super::rules::{self, TaintPack};
use super::types::AuditFinding;

const ALL_KEYS: u32 = u32::MAX;
const ROOT_SCOPE: usize = usize::MAX;

/// Nodes that reference a variable by name.
const IDENT_KINDS: &[&str] = &[
    "identifier",
    "shorthand_property_identifier",
    "simple_identifier",
    "interpolated_identifier",
];
/// Nodes that bind a name inside a (destructuring) pattern.
const PATTERN_IDENT_KINDS: &[&str] = &[
    "identifier",
    "shorthand_property_identifier_pattern",
    "shorthand_field_identifier",
    "simple_identifier",
];
/// Member accesses tracked by their full text.
const MEMBER_KINDS: &[&str] = &[
    "field_access",
    "attribute",
    "member_expression",
    "field_expression",
    "selector_expression",
    "member_access_expression",
    "navigation_expression",
];
/// Subscript targets taint their container (field holding the container, or
/// "" for the first named child) and never clear it.
const SUBSCRIPT_KINDS: &[(&str, &str)] = &[
    ("subscript", "value"),
    ("subscript_expression", "object"),
    ("array_access", "array"),
    ("index_expression", ""),
    ("element_access_expression", "expression"),
    ("indexing_expression", ""),
];
/// Control flow that makes a clean reassignment conditional.
const BRANCH_KINDS: &[&str] = &[
    "if_statement",
    "if_expression",
    "elif_clause",
    "else_clause",
    "while_statement",
    "while_expression",
    "do_statement",
    "for_statement",
    "for_in_statement",
    "enhanced_for_statement",
    "for_expression",
    "loop_expression",
    "switch_statement",
    "switch_expression",
    "switch_block",
    "match_statement",
    "match_expression",
    "match_arm",
    "case_clause",
    "try_statement",
    "catch_clause",
    "except_clause",
    "finally_clause",
    "ternary_expression",
    "conditional_expression",
    "foreach_statement",
    "switch_section",
    "expression_switch_statement",
    "type_switch_statement",
    "select_statement",
    "expression_case",
    "type_case",
    "default_case",
    "communication_case",
    "do_while_statement",
    "when_expression",
    "when_entry",
    "try_expression",
    "catch_block",
];
/// Statements whose `condition` field makes a guard effective.
const CONDITION_KINDS: &[&str] = &[
    "if_statement",
    "elif_clause",
    "if_expression",
    "while_statement",
    "while_expression",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Function,
    AssignLhs,
    AssignRhs,
    UpdateLhs,
    UpdateRhs,
    PropTo,
    PropFrom,
    Source(u32),
    Bind,
    Sink { key: usize, write: bool },
    Sanitizer(u32),
    Guard(u32),
    Helper,
}

fn parse_role(name: &str, keys: &[&str]) -> Result<Role, String> {
    let key_index = |k: &str| {
        keys.iter()
            .position(|x| *x == k)
            .ok_or_else(|| format!("capture @{name} references unknown taint key `{k}`"))
    };
    let role = match name {
        "function" => Role::Function,
        "assign.lhs" => Role::AssignLhs,
        "assign.rhs" => Role::AssignRhs,
        "update.lhs" => Role::UpdateLhs,
        "update.rhs" => Role::UpdateRhs,
        "prop.to" => Role::PropTo,
        "prop.from" => Role::PropFrom,
        "source" => Role::Source(ALL_KEYS),
        "source.param" => Role::Bind,
        "sanitizer" => Role::Sanitizer(ALL_KEYS),
        _ if name.starts_with('_') => Role::Helper,
        _ => {
            if let Some(k) = name.strip_prefix("source.") {
                Role::Source(1 << key_index(k)?)
            } else if let Some(rest) = name.strip_prefix("sink.") {
                let (k, write) = rest
                    .strip_suffix(".write")
                    .map_or((rest, false), |k| (k, true));
                Role::Sink {
                    key: key_index(k)?,
                    write,
                }
            } else if let Some(k) = name.strip_prefix("sanitizer.") {
                Role::Sanitizer(1 << key_index(k)?)
            } else if let Some(k) = name.strip_prefix("guard.") {
                Role::Guard(1 << key_index(k)?)
            } else {
                return Err(format!(
                    "unknown capture @{name}; helper captures must start with `_`"
                ));
            }
        }
    };
    Ok(role)
}

pub(crate) struct CompiledPack {
    pack: &'static TaintPack,
    query: Query,
    roles: Vec<Role>,
}

/// Compile a pack for one grammar and validate its capture names: unknown
/// roles or keys, and rule keys without any sink, are errors.
pub(crate) fn compile(
    pack: &'static TaintPack,
    ts_lang: &Language,
) -> Result<CompiledPack, String> {
    if pack.rules.len() > 32 {
        return Err("a taint pack supports at most 32 rules".to_owned());
    }
    let query = Query::new(ts_lang, &pack.queries.join("\n")).map_err(|e| e.to_string())?;
    let keys: Vec<&str> = pack.rules.iter().map(|r| r.key).collect();
    let roles = query
        .capture_names()
        .iter()
        .map(|n| parse_role(n, &keys))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, key) in keys.iter().enumerate() {
        if !roles
            .iter()
            .any(|r| matches!(r, Role::Sink { key: k, .. } if *k == i))
        {
            return Err(format!("taint key `{key}` has no @sink.{key} capture"));
        }
    }
    Ok(CompiledPack { pack, query, roles })
}

/// One slot per grammar with a taint pack; each pack is compiled on first use
/// so a project only pays for the languages it contains.
static COMPILED: LazyLock<HashMap<&'static str, OnceLock<Option<CompiledPack>>>> =
    LazyLock::new(|| {
        LANGUAGE_REGISTRY
            .iter()
            .filter(|g| rules::taint_pack(g.name()).is_some())
            .map(|g| (g.name(), OnceLock::new()))
            .collect()
    });

fn compiled(lang: &str) -> Option<&'static CompiledPack> {
    COMPILED
        .get(lang)?
        .get_or_init(|| {
            let pack = rules::taint_pack(lang)?;
            let ts_lang = LANGUAGE_REGISTRY
                .iter()
                .find(|g| g.name() == lang)?
                .tree_sitter_language()?;
            compile(pack, &ts_lang)
                .map_err(|e| {
                    tracing::warn!(language = lang, error = %e, "invalid taint pack; skipped");
                })
                .ok()
        })
        .as_ref()
}

/// True when the grammar has a valid taint pack.
#[must_use]
pub fn has_pack(lang: &str) -> bool {
    compiled(lang).is_some()
}

/// Rounds of summary computation: a flow is followed through at most this
/// many nested calls (SAST v2 §2.2, N2b).
pub const SUMMARY_DEPTH: usize = 3;

// ── Function summaries (N2b) ─────────────────────────────────────────────────

/// What calling a function does with taint. Bit `k` refers to rule `k` of the
/// language pack.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// The return value carries user input from a source inside the function.
    returns_source: u32,
    /// Per parameter: keys for which a tainted argument taints the result.
    returns_from: Vec<u32>,
    /// Per parameter: keys whose sink a tainted argument reaches.
    sinks: Vec<u32>,
    /// Per parameter: keys whose reached sink writes or executes.
    write_sinks: Vec<u32>,
    /// First bound name of each parameter (keyword arguments).
    params: Vec<String>,
}

/// Summary of one function definition, produced by [`summarize`].
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    family: usize,
    name: String,
    summary: Summary,
}

/// Summaries of a set of files, resolved by language family and name. A name
/// defined more than once is ambiguous and never used: precision first.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summaries {
    map: HashMap<usize, HashMap<String, Option<Summary>>>,
}

impl Summaries {
    #[must_use]
    pub fn from_entries(entries: impl IntoIterator<Item = FunctionSummary>) -> Self {
        let mut map: HashMap<usize, HashMap<String, Option<Summary>>> = HashMap::new();
        for e in entries {
            map.entry(e.family)
                .or_default()
                .entry(e.name)
                .and_modify(|slot| *slot = None)
                .or_insert(Some(e.summary));
        }
        Self { map }
    }

    /// True when no function has a usable summary (calls need no resolution).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn get(&self, family: usize, name: &str) -> Option<&Summary> {
        self.map.get(&family)?.get(name)?.as_ref()
    }
}

/// Languages that share a rule list (JS/TS) share summaries.
fn family(pack: &TaintPack) -> usize {
    pack.rules.as_ptr() as usize
}

/// Summaries of every named function in `tree`, using `known` for callees.
#[must_use]
pub fn summarize(tree: &Tree, source: &str, lang: &str, known: &Summaries) -> Vec<FunctionSummary> {
    let Some(cp) = compiled(lang) else {
        return Vec::new();
    };
    let env = Env {
        summaries: known,
        family: family(cp.pack),
    };
    Facts::collect(cp, tree, source.as_bytes()).summaries(cp.pack, &env, u32::MAX)
}

/// Analyse one file following calls to its own functions: facts are collected
/// once and summaries are iterated up to [`SUMMARY_DEPTH`] rounds, stopping
/// as soon as they no longer change.
#[must_use]
pub fn analyze_local(tree: &Tree, source: &str, lang: &str) -> Vec<AuditFinding> {
    let Some(cp) = compiled(lang) else {
        return Vec::new();
    };
    let facts = Facts::collect(cp, tree, source.as_bytes());
    let family = family(cp.pack);
    // Only a rule with a sink in this file can produce a finding here.
    let active = facts.sink_mask();
    let mut known = Summaries::default();
    for _ in 0..SUMMARY_DEPTH {
        let next = Summaries::from_entries(facts.summaries(
            cp.pack,
            &Env {
                summaries: &known,
                family,
            },
            active,
        ));
        if next == known {
            break;
        }
        known = next;
        // Another round only matters if some call resolves to a summary.
        if !facts.has_resolvable_call(&known, family) {
            break;
        }
    }
    facts.findings(
        cp.pack,
        &Env {
            summaries: &known,
            family,
        },
    )
}

/// Run every taint rule of `lang` over an already parsed `tree`, following
/// calls through `known` summaries.
#[must_use]
pub fn analyze(tree: &Tree, source: &str, lang: &str, known: &Summaries) -> Vec<AuditFinding> {
    let Some(cp) = compiled(lang) else {
        return Vec::new();
    };
    let env = Env {
        summaries: known,
        family: family(cp.pack),
    };
    Facts::collect(cp, tree, source.as_bytes()).findings(cp.pack, &env)
}

struct Env<'a> {
    summaries: &'a Summaries,
    family: usize,
}

#[derive(Clone, Copy)]
enum Op<'t> {
    Bind(Node<'t>),
    Assign {
        lhs: Node<'t>,
        rhs: Node<'t>,
        update: bool,
    },
    Prop {
        to: Node<'t>,
        from: Node<'t>,
    },
    Guard(Node<'t>, u32),
    Sink {
        arg: Node<'t>,
        key: usize,
        write: bool,
    },
    /// Any call: checked against callee summaries at analysis time.
    Call(Node<'t>),
    /// Value returned by the enclosing function.
    Return(Node<'t>),
}

impl<'t> Op<'t> {
    /// Node that locates the operation in a scope.
    fn anchor(self) -> Node<'t> {
        match self {
            Op::Bind(n) | Op::Guard(n, _) | Op::Call(n) | Op::Return(n) => n,
            Op::Assign { lhs, .. } => lhs,
            Op::Prop { to, .. } => to,
            Op::Sink { arg, .. } => arg,
        }
    }

    /// Program point: bindings take effect after their value is evaluated,
    /// sinks and calls are checked where they start.
    fn position(self) -> (usize, u8) {
        match self {
            Op::Bind(n) => (n.start_byte(), 0),
            Op::Guard(n, _) => (n.end_byte(), 1),
            Op::Assign { rhs, .. } => (rhs.end_byte(), 2),
            Op::Prop { from, .. } => (from.end_byte(), 3),
            Op::Sink { arg, .. } => (arg.start_byte(), 4),
            Op::Call(n) => (n.start_byte(), 5),
            Op::Return(n) => (n.end_byte(), 6),
        }
    }
}

struct Event<'t> {
    scope: usize,
    op: Op<'t>,
}

struct Hit<'t> {
    line: usize,
    key: usize,
    write: bool,
    source_line: usize,
    node: Node<'t>,
    /// Callee whose summary reaches the sink.
    via: Option<String>,
}

/// Result of simulating one scope for one rule.
struct Outcome<'t> {
    hits: Vec<Hit<'t>>,
    returns: Option<usize>,
}

const CALL_KINDS: &[&str] = &[
    "call_expression",
    "call",
    "method_invocation",
    "invocation_expression",
];

/// Per-file facts extracted by one query pass and one tree walk.
struct Facts<'t> {
    src: &'t [u8],
    functions: HashMap<usize, Node<'t>>,
    sources: HashMap<usize, u32>,
    sanitizers: HashMap<usize, u32>,
    events: Vec<Event<'t>>,
    /// Contiguous event range of each scope (events are sorted by scope).
    scopes: Vec<(usize, std::ops::Range<usize>)>,
}

impl<'t> Facts<'t> {
    fn collect(cp: &CompiledPack, tree: &'t Tree, src: &'t [u8]) -> Self {
        let mut facts = Facts {
            src,
            functions: HashMap::new(),
            sources: HashMap::new(),
            sanitizers: HashMap::new(),
            events: Vec::new(),
            scopes: Vec::new(),
        };
        let mut ops: Vec<Op<'t>> = Vec::new();
        let mut cursor = QueryCursor::new();
        for m in cursor.matches(&cp.query, tree.root_node(), src) {
            // assign.lhs, assign.rhs, update.lhs, update.rhs, prop.to, prop.from
            let mut pair: [Option<Node<'t>>; 6] = [None; 6];
            for cap in m.captures {
                let node = cap.node;
                match cp.roles[cap.index as usize] {
                    Role::Function => {
                        facts.functions.insert(node.id(), node);
                    }
                    Role::AssignLhs => pair[0] = Some(node),
                    Role::AssignRhs => pair[1] = Some(node),
                    Role::UpdateLhs => pair[2] = Some(node),
                    Role::UpdateRhs => pair[3] = Some(node),
                    Role::PropTo => pair[4] = Some(node),
                    Role::PropFrom => pair[5] = Some(node),
                    Role::Source(mask) => *facts.sources.entry(node.id()).or_default() |= mask,
                    Role::Sanitizer(mask) => {
                        *facts.sanitizers.entry(node.id()).or_default() |= mask;
                    }
                    Role::Bind => ops.push(Op::Bind(node)),
                    Role::Guard(mask) => ops.push(Op::Guard(node, mask)),
                    Role::Sink { key, write } => ops.push(Op::Sink {
                        arg: node,
                        key,
                        write,
                    }),
                    Role::Helper => {}
                }
            }
            if let [Some(lhs), Some(rhs), ..] = pair {
                ops.push(Op::Assign {
                    lhs,
                    rhs,
                    update: false,
                });
            }
            if let [_, _, Some(lhs), Some(rhs), ..] = pair {
                ops.push(Op::Assign {
                    lhs,
                    rhs,
                    update: true,
                });
            }
            if let [.., Some(to), Some(from)] = pair {
                ops.push(Op::Prop { to, from });
            }
        }

        // Calls and returns come from a structural walk, not from the query.
        let mut stack = vec![tree.root_node()];
        while let Some(n) = stack.pop() {
            let kind = n.kind();
            if CALL_KINDS.contains(&kind) {
                ops.push(Op::Call(n));
            } else if let Some(value) = explicit_return(n, src) {
                ops.push(Op::Return(value));
            }
            for i in 0..n.named_child_count() {
                if let Some(c) = n.named_child(i) {
                    stack.push(c);
                }
            }
        }
        for func in facts.functions.values() {
            if let Some(value) = implicit_return(*func, src) {
                ops.push(Op::Return(value));
            }
        }

        for op in ops {
            if let Op::Guard(n, _) = op {
                if !facts.in_condition(n) {
                    continue;
                }
            }
            let scope = facts.scope_of(op.anchor());
            facts.events.push(Event { scope, op });
        }
        facts.events.sort_by_key(|e| (e.scope, e.op.position()));
        let mut start = 0;
        for i in 1..=facts.events.len() {
            if i == facts.events.len() || facts.events[i].scope != facts.events[start].scope {
                facts.scopes.push((facts.events[start].scope, start..i));
                start = i;
            }
        }
        facts
    }

    /// Bit `k` set when the file has a sink for rule `k`.
    fn sink_mask(&self) -> u32 {
        self.events.iter().fold(0, |mask, e| match e.op {
            Op::Sink { key, .. } => mask | (1 << key),
            _ => mask,
        })
    }

    /// True when a call in the file names a function with a summary.
    fn has_resolvable_call(&self, known: &Summaries, family: usize) -> bool {
        self.events.iter().any(|e| match e.op {
            Op::Call(call) => call_parts(call, self.src)
                .is_some_and(|parts| known.get(family, parts.name).is_some()),
            _ => false,
        })
    }

    fn scope_events(&self, scope: usize) -> &[Event<'t>] {
        self.scopes
            .iter()
            .find(|(s, _)| *s == scope)
            .map_or(&[], |(_, range)| &self.events[range.clone()])
    }

    /// Simulate one scope for rule `k`, starting from `init` tainted names.
    fn simulate(
        &self,
        events: &[Event<'t>],
        scope: usize,
        k: usize,
        init: &[(String, usize)],
        env: &Env<'_>,
    ) -> Outcome<'t> {
        let bit = 1u32 << k;
        let mut state: HashMap<String, usize> = init.iter().cloned().collect();
        let mut out = Outcome {
            hits: Vec::new(),
            returns: None,
        };
        for e in events {
            match e.op {
                Op::Bind(n) => {
                    let line = line_of(n);
                    for name in self.bound_names(n) {
                        state.insert(name, line);
                    }
                }
                Op::Assign { lhs, rhs, update } => {
                    let (target, update) =
                        subscript_base(lhs).map_or((lhs, update), |base| (base, true));
                    let names = self.bound_names(target);
                    match self.taint_of(rhs, bit, &state, env) {
                        Some(line) => {
                            for name in names {
                                state.insert(name, line);
                            }
                        }
                        None if !update && !self.under_branch(lhs, scope) => {
                            for name in &names {
                                state.remove(name);
                            }
                        }
                        None => {}
                    }
                }
                Op::Prop { to, from } => {
                    if let Some(line) = self.taint_of(from, bit, &state, env) {
                        for name in self.bound_names(to) {
                            state.insert(name, line);
                        }
                    }
                }
                Op::Guard(n, mask) if mask & bit != 0 => {
                    for name in self.referenced_names(n) {
                        state.remove(&name);
                    }
                }
                Op::Sink { arg, key, write } if key == k => {
                    if let Some(source_line) = self.taint_of(arg, bit, &state, env) {
                        out.hits.push(Hit {
                            line: line_of(arg),
                            key,
                            write,
                            source_line,
                            node: arg,
                            via: None,
                        });
                    }
                }
                Op::Call(call) => self.check_call(call, k, &state, env, &mut out),
                Op::Return(value) => {
                    if out.returns.is_none() {
                        out.returns = self.taint_of(value, bit, &state, env);
                    }
                }
                Op::Guard(..) | Op::Sink { .. } => {}
            }
        }
        out
    }

    /// A tainted argument reaching a sink inside the callee.
    fn check_call(
        &self,
        call: Node<'t>,
        k: usize,
        state: &HashMap<String, usize>,
        env: &Env<'_>,
        out: &mut Outcome<'t>,
    ) {
        if env.summaries.is_empty() {
            return;
        }
        let bit = 1u32 << k;
        let Some(parts) = call_parts(call, self.src) else {
            return;
        };
        let Some(summary) = env.summaries.get(env.family, parts.name) else {
            return;
        };
        for (i, arg) in parts.args.iter().enumerate() {
            let Some(slot) = param_slot(summary, i, *arg, self.src) else {
                continue;
            };
            if summary.sinks.get(slot).is_some_and(|m| m & bit != 0) {
                if let Some(source_line) = self.taint_of(arg_value(*arg), bit, state, env) {
                    out.hits.push(Hit {
                        line: line_of(call),
                        key: k,
                        write: summary.write_sinks.get(slot).is_some_and(|m| m & bit != 0),
                        source_line,
                        node: call,
                        via: Some(parts.name.to_owned()),
                    });
                }
            }
        }
    }

    /// Summaries of the named functions; only rules in `active` are computed.
    fn summaries(
        &self,
        pack: &'static TaintPack,
        env: &Env<'_>,
        active: u32,
    ) -> Vec<FunctionSummary> {
        let mut functions: Vec<&Node<'t>> = self.functions.values().collect();
        functions.sort_by_key(|f| f.start_byte());
        let mut out = Vec::new();
        for func in functions {
            let Some(name) = super::audit::declared_name(*func, self.src) else {
                continue;
            };
            let events = self.scope_events(func.id());
            // Without sinks, calls or returns a function cannot affect a summary.
            if !events
                .iter()
                .any(|e| matches!(e.op, Op::Sink { .. } | Op::Call(_) | Op::Return(_)))
            {
                continue;
            }
            let params = self.param_names(*func);
            let mut summary = Summary {
                returns_source: 0,
                returns_from: vec![0; params.len()],
                sinks: vec![0; params.len()],
                write_sinks: vec![0; params.len()],
                params: params
                    .iter()
                    .map(|p| p.first().cloned().unwrap_or_default())
                    .collect(),
            };
            let line = line_of(*func);
            for k in 0..pack.rules.len() {
                let bit = 1u32 << k;
                if active & bit == 0 {
                    continue;
                }
                let base = self.simulate(events, func.id(), k, &[], env);
                if base.returns.is_some() {
                    summary.returns_source |= bit;
                }
                let base_hits: HashSet<usize> = base.hits.iter().map(|h| h.line).collect();
                for (i, names) in params.iter().enumerate() {
                    let init: Vec<(String, usize)> =
                        names.iter().map(|n| (n.clone(), line)).collect();
                    let run = self.simulate(events, func.id(), k, &init, env);
                    if run.returns.is_some() {
                        summary.returns_from[i] |= bit;
                    }
                    for hit in run.hits.iter().filter(|h| !base_hits.contains(&h.line)) {
                        summary.sinks[i] |= bit;
                        if hit.write {
                            summary.write_sinks[i] |= bit;
                        }
                    }
                }
            }
            out.push(FunctionSummary {
                family: family(pack),
                name,
                summary,
            });
        }
        out
    }

    fn findings(&self, pack: &'static TaintPack, env: &Env<'_>) -> Vec<AuditFinding> {
        let mut hits: BTreeMap<(usize, usize), Hit<'t>> = BTreeMap::new();
        for (scope, range) in &self.scopes {
            let events = &self.events[range.clone()];
            for k in 0..pack.rules.len() {
                // A scope without a sink for this rule (or any call that may
                // reach one through a summary) cannot produce a finding.
                let relevant = events.iter().any(|e| match e.op {
                    Op::Sink { key, .. } => key == k,
                    Op::Call(_) => !env.summaries.is_empty(),
                    _ => false,
                });
                if !relevant {
                    continue;
                }
                for hit in self.simulate(events, *scope, k, &[], env).hits {
                    match hits.entry((hit.line, hit.key)) {
                        std::collections::btree_map::Entry::Occupied(mut e) => {
                            e.get_mut().write |= hit.write;
                        }
                        std::collections::btree_map::Entry::Vacant(e) => {
                            e.insert(hit);
                        }
                    }
                }
            }
        }
        hits.into_values()
            .map(|hit| {
                let meta = &pack.rules[hit.key].meta;
                let description = hit.via.as_ref().map_or_else(
                    || meta.description.to_owned(),
                    |callee| format!("{} (via {callee}())", meta.description),
                );
                AuditFinding {
                    rule: meta,
                    line: hit.line,
                    is_write_sink: hit.write,
                    description,
                    flow: Some((hit.source_line, hit.line)),
                    function: super::audit::enclosing_function_name(hit.node, self.src),
                }
            })
            .collect()
    }

    /// Bound names of each parameter of `func`, in declaration order.
    fn param_names(&self, func: Node<'_>) -> Vec<Vec<String>> {
        let Some(params) = parameter_list(func) else {
            return Vec::new();
        };
        if PATTERN_IDENT_KINDS.contains(&params.kind()) {
            return vec![vec![self.text(params).to_owned()]];
        }
        let mut out = Vec::new();
        for i in 0..params.named_child_count() {
            let Some(p) = params.named_child(i) else {
                continue;
            };
            match p.kind() {
                "comment"
                | "line_comment"
                | "block_comment"
                | "self_parameter"
                | "parameter_modifiers" => continue,
                "parameter_declaration" | "variadic_parameter_declaration" => {
                    // Go: `a, b string` declares two parameters.
                    let mut cursor = p.walk();
                    let names: Vec<Node<'_>> =
                        p.children_by_field_name("name", &mut cursor).collect();
                    if names.len() > 1 {
                        out.extend(names.iter().map(|n| vec![self.text(*n).to_owned()]));
                        continue;
                    }
                }
                _ => {}
            }
            let target = p
                .child_by_field_name("pattern")
                .or_else(|| p.child_by_field_name("name"))
                .or_else(|| p.child_by_field_name("left"))
                .or_else(|| {
                    matches!(p.kind(), "typed_parameter" | "parameter")
                        .then(|| p.named_child(0))
                        .flatten()
                })
                .or_else(|| {
                    // C: parameter_declaration → declarator chain → identifier.
                    let mut d = p.child_by_field_name("declarator")?;
                    while let Some(inner) = d.child_by_field_name("declarator") {
                        d = inner;
                    }
                    Some(d)
                })
                .unwrap_or(p);
            let names = self.bound_names(target);
            if names.len() == 1 && matches!(names[0].as_str(), "self" | "cls") {
                continue;
            }
            out.push(names);
        }
        out
    }

    fn text(&self, n: Node<'_>) -> &'t str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// Line of the source that taints `node` for rule bit `bit`, if any.
    ///
    /// Calls to functions with a known summary follow the summary instead of
    /// the default "any tainted argument taints the result" propagation.
    fn taint_of(
        &self,
        node: Node<'_>,
        bit: u32,
        state: &HashMap<String, usize>,
        env: &Env<'_>,
    ) -> Option<usize> {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let id = n.id();
            if self.sanitizers.get(&id).is_some_and(|m| m & bit != 0) {
                continue;
            }
            if self.sources.get(&id).is_some_and(|m| m & bit != 0) {
                return Some(line_of(n));
            }
            // Nested functions are separate scopes.
            if id != node.id() && self.functions.contains_key(&id) {
                continue;
            }
            let kind = n.kind();
            if !env.summaries.is_empty() && CALL_KINDS.contains(&kind) {
                if let Some(parts) = call_parts(n, self.src) {
                    if let Some(summary) = env.summaries.get(env.family, parts.name) {
                        if summary.returns_source & bit != 0 {
                            return Some(line_of(n));
                        }
                        for (i, arg) in parts.args.iter().enumerate() {
                            let propagates = param_slot(summary, i, *arg, self.src)
                                .and_then(|slot| summary.returns_from.get(slot))
                                .is_some_and(|m| m & bit != 0);
                            if propagates {
                                stack.push(arg_value(*arg));
                            }
                        }
                        stack.extend(parts.receiver);
                        continue;
                    }
                }
            }
            if IDENT_KINDS.contains(&kind) {
                if !is_member_name(n) {
                    if let Some(line) = state.get(self.text(n)) {
                        return Some(*line);
                    }
                }
                continue;
            }
            if MEMBER_KINDS.contains(&kind) {
                if let Some(line) = state.get(self.text(n)) {
                    return Some(*line);
                }
            } else if kind == "string_literal" && in_macro(n) {
                // Rust inline format arguments: `format!("… {id}")`.
                if let Some(line) = format_args_in(self.text(n))
                    .into_iter()
                    .find_map(|name| state.get(name))
                {
                    return Some(*line);
                }
                continue;
            }
            for i in (0..n.child_count()).rev() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
        None
    }

    /// Names bound by an assignment target or pattern.
    fn bound_names(&self, node: Node<'_>) -> Vec<String> {
        if MEMBER_KINDS.contains(&node.kind()) || PATTERN_IDENT_KINDS.contains(&node.kind()) {
            return vec![self.text(node).to_owned()];
        }
        let mut names = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            if PATTERN_IDENT_KINDS.contains(&n.kind()) {
                if !is_member_name(n) {
                    names.push(self.text(n).to_owned());
                }
                continue;
            }
            // Type names (`Some(x)`, `Query(q)`) and object keys (`{ key: x }`) bind nothing.
            let skip_type = n.child_by_field_name("type");
            let skip_key = if n.kind() == "pair_pattern" {
                n.child_by_field_name("key")
            } else {
                None
            };
            for i in 0..n.child_count() {
                if let Some(c) = n.child(i) {
                    if Some(c) != skip_type && Some(c) != skip_key {
                        stack.push(c);
                    }
                }
            }
        }
        names
    }

    /// Variables and member accesses referenced inside `node`.
    fn referenced_names(&self, node: Node<'_>) -> Vec<String> {
        let mut names = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let kind = n.kind();
            if MEMBER_KINDS.contains(&kind) {
                names.push(self.text(n).to_owned());
            } else if IDENT_KINDS.contains(&kind) && !is_member_name(n) {
                names.push(self.text(n).to_owned());
                continue;
            }
            for i in 0..n.child_count() {
                if let Some(c) = n.child(i) {
                    stack.push(c);
                }
            }
        }
        names
    }

    fn scope_of(&self, node: Node<'_>) -> usize {
        let mut cur = node.parent();
        while let Some(n) = cur {
            if self.functions.contains_key(&n.id()) {
                return n.id();
            }
            cur = n.parent();
        }
        ROOT_SCOPE
    }

    fn under_branch(&self, node: Node<'_>, scope: usize) -> bool {
        let mut cur = node.parent();
        while let Some(n) = cur {
            if n.id() == scope {
                return false;
            }
            if BRANCH_KINDS.contains(&n.kind()) {
                return true;
            }
            cur = n.parent();
        }
        false
    }

    /// True when `node` lies in the `condition` of the nearest conditional.
    fn in_condition(&self, node: Node<'_>) -> bool {
        let mut child = node;
        let mut cur = node.parent();
        while let Some(p) = cur {
            if CONDITION_KINDS.contains(&p.kind()) {
                return p.child_by_field_name("condition") == Some(child);
            }
            if self.functions.contains_key(&p.id()) {
                return false;
            }
            child = p;
            cur = p.parent();
        }
        false
    }
}

struct CallParts<'t> {
    name: &'t str,
    args: Vec<Node<'t>>,
    receiver: Option<Node<'t>>,
}

/// Callee name, arguments and receiver of a call node, across grammars.
fn call_parts<'t>(call: Node<'t>, src: &'t [u8]) -> Option<CallParts<'t>> {
    let (callee, args) = if call.kind() == "method_invocation" {
        (
            call.child_by_field_name("name")?,
            call.child_by_field_name("arguments")?,
        )
    } else {
        let callee = call
            .child_by_field_name("function")
            .or_else(|| call.named_child(0))?;
        let args = call.child_by_field_name("arguments").or_else(|| {
            // Kotlin: call_suffix → value_arguments.
            let mut cursor = call.walk();
            let suffix = call
                .named_children(&mut cursor)
                .find(|c| c.kind() == "call_suffix")?;
            let mut cursor = suffix.walk();
            let found = suffix
                .named_children(&mut cursor)
                .find(|c| c.kind() == "value_arguments");
            found
        })?;
        (callee, args)
    };
    let receiver = if call.kind() == "method_invocation" {
        call.child_by_field_name("object")
    } else {
        ["object", "value", "operand", "expression"]
            .iter()
            .find_map(|f| callee.child_by_field_name(f))
            .or_else(|| {
                (callee.kind() == "navigation_expression")
                    .then(|| callee.named_child(0))
                    .flatten()
            })
    };
    let mut cursor = args.walk();
    let args: Vec<Node<'t>> = args
        .named_children(&mut cursor)
        .filter(|a| !a.kind().contains("comment"))
        .collect();
    Some(CallParts {
        name: callee_name(callee, src)?,
        args,
        receiver,
    })
}

fn callee_name<'t>(callee: Node<'t>, src: &'t [u8]) -> Option<&'t str> {
    let name_node = match callee.kind() {
        "identifier" | "simple_identifier" | "field_identifier" | "property_identifier" => callee,
        "member_expression" => callee.child_by_field_name("property")?,
        "attribute" => callee.child_by_field_name("attribute")?,
        "field_expression" | "selector_expression" => callee.child_by_field_name("field")?,
        "scoped_identifier" | "member_access_expression" => callee.child_by_field_name("name")?,
        "generic_function" => return callee_name(callee.child_by_field_name("function")?, src),
        "navigation_expression" => {
            let suffix = callee.named_child(callee.named_child_count().checked_sub(1)?)?;
            suffix.named_child(0)?
        }
        _ => return None,
    };
    name_node.utf8_text(src).ok()
}

/// Parameter index receiving argument `i` (keyword arguments by name).
fn param_slot(summary: &Summary, i: usize, arg: Node<'_>, src: &[u8]) -> Option<usize> {
    let named = matches!(arg.kind(), "keyword_argument" | "argument")
        .then(|| arg.child_by_field_name("name"))
        .flatten();
    match named {
        Some(name) => {
            let name = name.utf8_text(src).ok()?;
            summary.params.iter().position(|p| p == name)
        }
        None => (i < summary.params.len()).then_some(i),
    }
}

fn arg_value(arg: Node<'_>) -> Node<'_> {
    if arg.kind() == "keyword_argument" {
        arg.child_by_field_name("value").unwrap_or(arg)
    } else {
        arg
    }
}

/// Value of a `return` statement/expression.
fn explicit_return<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    match n.kind() {
        "return_statement" | "return_expression" => n.named_child(0),
        // Kotlin: `return x` is a jump_expression.
        "jump_expression" if n.utf8_text(src).is_ok_and(|t| t.starts_with("return")) => {
            n.named_child(0)
        }
        _ => None,
    }
}

/// Expression-bodied functions and Rust tail expressions.
fn implicit_return<'t>(func: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = func.child_by_field_name("body").or_else(|| {
        // Kotlin `fun f(x: String) = …` keeps the expression in function_body.
        let mut cursor = func.walk();
        let found = func
            .named_children(&mut cursor)
            .find(|c| c.kind() == "function_body");
        found
    })?;
    match body.kind() {
        "block" => {
            // Rust: a trailing expression without `;` is the value.
            let last = body.named_child(body.named_child_count().checked_sub(1)?)?;
            let is_tail = !last.kind().ends_with("statement")
                && !last.kind().ends_with("declaration")
                && !last.kind().contains("comment")
                && !last.kind().ends_with("_item")
                && func.kind() != "function_definition";
            let ends_with_semicolon = body
                .utf8_text(src)
                .is_ok_and(|t| t.trim_end().trim_end_matches('}').trim_end().ends_with(';'));
            (is_tail && !ends_with_semicolon).then_some(last)
        }
        "function_body" => body
            .utf8_text(src)
            .is_ok_and(|t| t.trim_start().starts_with('='))
            .then(|| body.named_child(0))
            .flatten(),
        "statement_block" | "compound_statement" => None,
        _ => Some(body),
    }
}

/// Parameter list node of a function, across grammars.
fn parameter_list(func: Node<'_>) -> Option<Node<'_>> {
    if let Some(params) = func
        .child_by_field_name("parameters")
        .or_else(|| func.child_by_field_name("parameter"))
    {
        return Some(params);
    }
    if let Some(mut d) = func.child_by_field_name("declarator") {
        // C: walk pointer declarators down to the function_declarator.
        while d.kind() != "function_declarator" {
            d = d.child_by_field_name("declarator")?;
        }
        return d.child_by_field_name("parameters");
    }
    let mut cursor = func.walk();
    let found = func
        .named_children(&mut cursor)
        .find(|c| matches!(c.kind(), "function_value_parameters" | "lambda_parameters"));
    found
}

fn line_of(n: Node<'_>) -> usize {
    n.start_position().row + 1
}

/// Method, field, attribute and keyword names are not variable references.
fn is_member_name(n: Node<'_>) -> bool {
    let Some(p) = n.parent() else {
        return false;
    };
    let field = match p.kind() {
        "scoped_identifier" | "navigation_suffix" => return true,
        "method_invocation" | "keyword_argument" | "member_access_expression" | "argument" => {
            "name"
        }
        "field_access" => "field",
        "attribute" => "attribute",
        _ => return false,
    };
    p.child_by_field_name(field) == Some(n)
}

fn subscript_base(node: Node<'_>) -> Option<Node<'_>> {
    SUBSCRIPT_KINDS
        .iter()
        .find(|(kind, _)| *kind == node.kind())
        .and_then(|(_, field)| {
            if field.is_empty() {
                node.named_child(0)
            } else {
                node.child_by_field_name(field)
            }
        })
}

fn in_macro(n: Node<'_>) -> bool {
    let mut cur = n.parent();
    while let Some(p) = cur {
        match p.kind() {
            "token_tree" => return true,
            "function_item" => return false,
            _ => cur = p.parent(),
        }
    }
    false
}

/// Named arguments of a Rust format string: `{id}`, `{id:?}`; `{{` is escaped.
fn format_args_in(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut names = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'{') {
            i += 2;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if end > start
            && !bytes[start].is_ascii_digit()
            && matches!(bytes.get(end), Some(b'}' | b':'))
        {
            names.push(&text[start..end]);
        }
        i = end;
    }
    names
}

#[cfg(test)]
mod tests;
