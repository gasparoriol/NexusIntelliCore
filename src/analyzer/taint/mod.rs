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
const IDENT_KINDS: &[&str] = &["identifier", "shorthand_property_identifier"];
/// Nodes that bind a name inside a (destructuring) pattern.
const PATTERN_IDENT_KINDS: &[&str] = &[
    "identifier",
    "shorthand_property_identifier_pattern",
    "shorthand_field_identifier",
];
/// Member accesses tracked by their full text.
const MEMBER_KINDS: &[&str] = &[
    "field_access",
    "attribute",
    "member_expression",
    "field_expression",
];
/// Subscript targets taint their container (field holding the container, or
/// "" for the first named child) and never clear it.
const SUBSCRIPT_KINDS: &[(&str, &str)] = &[
    ("subscript", "value"),
    ("subscript_expression", "object"),
    ("array_access", "array"),
    ("index_expression", ""),
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

/// Run every taint rule of `lang` over an already parsed `tree`.
#[must_use]
pub fn analyze(tree: &Tree, source: &str, lang: &str) -> Vec<AuditFinding> {
    compiled(lang)
        .map(|cp| Facts::collect(cp, tree, source.as_bytes()).findings(cp.pack))
        .unwrap_or_default()
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
}

impl<'t> Op<'t> {
    /// Node that locates the operation in a scope.
    fn anchor(self) -> Node<'t> {
        match self {
            Op::Bind(n) | Op::Guard(n, _) => n,
            Op::Assign { lhs, .. } => lhs,
            Op::Prop { to, .. } => to,
            Op::Sink { arg, .. } => arg,
        }
    }

    /// Program point: bindings take effect after their value is evaluated,
    /// sinks are checked where their argument starts.
    fn position(self) -> (usize, u8) {
        match self {
            Op::Bind(n) => (n.start_byte(), 0),
            Op::Guard(n, _) => (n.end_byte(), 1),
            Op::Assign { rhs, .. } => (rhs.end_byte(), 2),
            Op::Prop { from, .. } => (from.end_byte(), 3),
            Op::Sink { arg, .. } => (arg.start_byte(), 4),
        }
    }
}

struct Event<'t> {
    scope: usize,
    op: Op<'t>,
}

struct Hit {
    write: bool,
    source_line: usize,
}

/// Per-file facts extracted by one query pass.
struct Facts<'t> {
    src: &'t [u8],
    functions: HashSet<usize>,
    sources: HashMap<usize, u32>,
    sanitizers: HashMap<usize, u32>,
    events: Vec<Event<'t>>,
}

impl<'t> Facts<'t> {
    fn collect(cp: &CompiledPack, tree: &'t Tree, src: &'t [u8]) -> Self {
        let mut facts = Facts {
            src,
            functions: HashSet::new(),
            sources: HashMap::new(),
            sanitizers: HashMap::new(),
            events: Vec::new(),
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
                        facts.functions.insert(node.id());
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
        facts
    }

    fn findings(&self, pack: &'static TaintPack) -> Vec<AuditFinding> {
        let mut hits: BTreeMap<(usize, usize), Hit> = BTreeMap::new();
        for k in 0..pack.rules.len() {
            if !self
                .events
                .iter()
                .any(|e| matches!(e.op, Op::Sink { key, .. } if key == k))
            {
                continue;
            }
            let bit = 1u32 << k;
            let mut state: HashMap<String, usize> = HashMap::new();
            let mut current_scope = None;
            for e in &self.events {
                if current_scope != Some(e.scope) {
                    state.clear();
                    current_scope = Some(e.scope);
                }
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
                        match self.taint_of(rhs, bit, &state) {
                            Some(line) => {
                                for name in names {
                                    state.insert(name, line);
                                }
                            }
                            None if !update && !self.under_branch(lhs, e.scope) => {
                                for name in &names {
                                    state.remove(name);
                                }
                            }
                            None => {}
                        }
                    }
                    Op::Prop { to, from } => {
                        if let Some(line) = self.taint_of(from, bit, &state) {
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
                        if let Some(source_line) = self.taint_of(arg, bit, &state) {
                            let hit = hits
                                .entry((line_of(arg), k))
                                .or_insert(Hit { write, source_line });
                            hit.write |= write;
                        }
                    }
                    Op::Guard(..) | Op::Sink { .. } => {}
                }
            }
        }
        hits.into_iter()
            .map(|((line, k), hit)| {
                let meta = &pack.rules[k].meta;
                AuditFinding {
                    rule: meta,
                    line,
                    is_write_sink: hit.write,
                    description: meta.description.to_owned(),
                    flow: Some((hit.source_line, line)),
                }
            })
            .collect()
    }

    fn text(&self, n: Node<'_>) -> &'t str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// Line of the source that taints `node` for rule bit `bit`, if any.
    fn taint_of(&self, node: Node<'_>, bit: u32, state: &HashMap<String, usize>) -> Option<usize> {
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
            if id != node.id() && self.functions.contains(&id) {
                continue;
            }
            let kind = n.kind();
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
            if self.functions.contains(&n.id()) {
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
            if self.functions.contains(&p.id()) {
                return false;
            }
            child = p;
            cur = p.parent();
        }
        false
    }
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
        "scoped_identifier" => return true,
        "method_invocation" | "keyword_argument" => "name",
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
