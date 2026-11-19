// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parse one REPL input line into a typed [`Command`], separated from the
//! dispatch that runs it. The loop in `session` handles everything before this
//! (skipping blank and comment lines, expanding aliases, canonicalizing a bare
//! command to its `::`-qualified form, splitting pasted multi-line input, and
//! the `use`-one-shot queue sentinels), so by the time a line reaches
//! `parse_command` it starts with `::` or one of the sigils `? ! + - ~`.
//!
//! Parsing is pure: no file or cluster I/O, no `Core` calls, no engine types.
//! That keeps the grammar unit-testable without a running engine, and leaves a
//! client (the REPL today, a planned gRPC client later) free to run the result
//! however it likes. Argument strings a command hands to the engine (a query
//! body, a fact atom, a rule) are carried through verbatim and parsed by the
//! handler, which owns those engine types.
//!
//! A `::`-path the built-ins don't recognize becomes [`Command::Unknown`]
//! rather than a hard error. The dispatcher turns that into today's "unknown
//! command" or usage message; it is also the seam where a future extension
//! registry (user-defined or wasm commands registered under their own
//! namespace) gets a chance to claim the path before the REPL gives up.

use super::OutputFormat;

/// A parsed REPL command. Variants carry already-validated arguments; strings
/// bound for the engine (query bodies, fact atoms, rules, source specs) are
/// passed through untouched for the handler to parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `?- <body>` or `query <body>`: evaluate a query over the active state.
    Query(String),
    /// `why <fact>`: show how a fact was derived (provenance).
    Why(String),
    /// `use [<snapshot> [<command>]]`: point read-only commands at a snapshot.
    /// No snapshot means return to live state; a trailing command runs once
    /// with the snapshot in use.
    Use {
        snapshot: Option<String>,
        one_shot: Option<String>,
    },
    /// `snapshot <name>`: freeze the current state under a name.
    Snapshot(String),
    /// `diff <a> [<b>]` or `diff-relation <a> [<b>] <relation>`. A single name
    /// diffs against whatever is in use. `relation` is set only for the
    /// `diff-relation` form, which scopes the diff to one relation.
    Diff {
        first: String,
        second: Option<String>,
        relation: Option<String>,
    },
    /// `show [--all] [<relation>...]`: list relations, or detail named ones.
    Show { names: Vec<String>, all: bool },
    /// `define <rule>.`: add a rule and re-evaluate.
    Define(String),
    /// `+<fact>.`: assert a ground fact.
    AssertFact(String),
    /// `-<fact>.`: retract a ground fact.
    RetractFact(String),
    /// `~<old>. <new>.`: replace one ground fact. The two atoms are left
    /// unsplit; the handler parses them.
    ReplaceFact(String),
    /// `source <src>`: read a Mangle source (facts and rules) and evaluate.
    Source(String),
    /// `load <relation> <source>`: bulk-load tuples into one relation.
    Load { relation: String, source: String },
    /// `k8s::load <src>`: load Kubernetes objects as facts. The spec (a dir, a
    /// `.json` file, or `! <kubectl args>`) is resolved by the client.
    K8sLoad(String),
    /// `k8s::apply-delta <base> <head>`: diff two renders of the same manifests.
    K8sApplyDelta(String),
    /// `k8s::match <Kind> <namespace> <selector>` (one kind) or
    /// `k8s::match-all <namespace> <selector>` (any kind).
    K8sMatch {
        kind: Option<String>,
        namespace: String,
        selector: String,
    },
    /// `rbac::diff <snap> [<snap2>] [--hide-escalation-lost]`.
    RbacDiff {
        first: String,
        second: Option<String>,
        hide_escalation_lost: bool,
    },
    /// `rbac::<check> ...`: an RBAC subsystem check; the tail is parsed by
    /// `rbac_command`.
    Rbac(String),
    /// `sched::<check> ...`: a scheduling subsystem check; the tail is parsed
    /// by `sched_command`.
    Sched(String),
    /// `explain <body>`: plan a query without running it.
    Explain(String),
    /// `smtlib <relation> [<relation>...]`: dump relations as SMT-LIB.
    Smtlib(Vec<String>),
    /// `rollback <name>`: reset live state to a snapshot (not on the `Core`
    /// trait; `LocalCore` only).
    Rollback(String),
    /// `!<cmd>`: run a shell command.
    Shell(String),
    /// `quit` / `exit` / `q`: leave the REPL.
    Quit,
    /// `help [<topic>]`.
    Help(Option<String>),
    /// `alias` and its forms.
    Alias(AliasCommand),
    /// `unalias <name>`.
    Unalias(String),
    /// `pretty`: toggle between default and pretty output.
    PrettyToggle,
    /// `format [<name>]`: set the output format, or report it when no name is
    /// given (`None`).
    Format(Option<OutputFormat>),
    /// A bare subsystem namespace (`rbac`, `sched`, `k8s`): list its commands.
    SubsystemHelp(Subsystem),
    /// A `::`-path no built-in claimed, carrying the text after the leading
    /// `::`. The dispatcher reports it (usage hint or unknown command) and is
    /// where an extension registry would get to claim it first.
    Unknown(String),
}

/// The three subsystem namespaces whose bare form lists their subcommands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subsystem {
    Rbac,
    Sched,
    K8s,
}

impl Subsystem {
    /// The namespace name as it appears in commands and help.
    pub fn as_str(self) -> &'static str {
        match self {
            Subsystem::Rbac => "rbac",
            Subsystem::Sched => "sched",
            Subsystem::K8s => "k8s",
        }
    }
}

/// The `alias` command's forms: list all, show one, or define one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliasCommand {
    List,
    Show(String),
    Set { name: String, body: String },
}

/// A command that could not be parsed. The message is ready to print; it is the
/// same usage text the REPL has always shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err(message: &str) -> Result<Command, ParseError> {
    Err(ParseError(message.to_string()))
}

/// Parse one preprocessed input line into a [`Command`]. The line is expected
/// to start with `::` or a sigil (`? ! + - ~`); see the module docs for what
/// the loop strips first. The match order mirrors the dispatcher so that a
/// prefix like `rbac::diff` is recognized before the `rbac::` catch-all.
pub fn parse_command(line: &str) -> Result<Command, ParseError> {
    // Queries keep both spellings; `?-` is the shorthand.
    if let Some(body) = line
        .strip_prefix("::query ")
        .or_else(|| line.strip_prefix("?- "))
    {
        return Ok(Command::Query(body.to_string()));
    }

    if let Some(fact) = line.strip_prefix("::why ") {
        return Ok(Command::Why(fact.to_string()));
    }

    if line == "::use" || line.starts_with("::use ") {
        let rest = line.strip_prefix("::use").unwrap_or("").trim();
        if rest.is_empty() {
            return Ok(Command::Use {
                snapshot: None,
                one_shot: None,
            });
        }
        let (name, one_shot) = match rest.split_once(char::is_whitespace) {
            Some((name, command)) => (name.to_string(), Some(command.trim().to_string())),
            None => (rest.to_string(), None),
        };
        return Ok(Command::Use {
            snapshot: Some(name),
            one_shot,
        });
    }

    if let Some(name) = line.strip_prefix("::snapshot ") {
        return Ok(Command::Snapshot(name.trim().to_string()));
    }

    // `diff` and `diff-relation` share argument shapes; the relation (last
    // token) is present only for the latter.
    let diff_args = line
        .strip_prefix("::diff ")
        .map(|rest| (rest, false))
        .or_else(|| {
            line.strip_prefix("::diff-relation ")
                .map(|rest| (rest, true))
        });
    if let Some((rest, one_relation)) = diff_args {
        let mut parts: Vec<&str> = rest.split_whitespace().collect();
        let relation = if one_relation {
            parts.pop().map(str::to_string)
        } else {
            None
        };
        return match parts.as_slice() {
            [name] => Ok(Command::Diff {
                first: name.to_string(),
                second: None,
                relation,
            }),
            [first, second] => Ok(Command::Diff {
                first: first.to_string(),
                second: Some(second.to_string()),
                relation,
            }),
            _ if one_relation => err(
                "Usage: diff-relation <name> <relation>  or  diff-relation <name1> <name2> <relation>",
            ),
            _ => err("Usage: diff <name>  or  diff <name1> <name2>"),
        };
    }

    if line == "::show" || line.starts_with("::show ") {
        let tokens = line.strip_prefix("::show").unwrap_or("").split_whitespace();
        // `--all`/`*` reveals undocumented intermediate relations; the rest are
        // explicit relation names.
        let mut all = false;
        let mut names = Vec::new();
        for token in tokens {
            if token == "--all" || token == "*" {
                all = true;
            } else {
                names.push(token.to_string());
            }
        }
        return Ok(Command::Show { names, all });
    }

    if let Some(rule) = line.strip_prefix("::define ") {
        return Ok(Command::Define(rule.to_string()));
    }

    // Fact mutators. The handler parses the atom; `+`/`-` drop a trailing `.`
    // as the loop did, `~` keeps both atoms together.
    if let Some(rest) = line.strip_prefix('~') {
        return Ok(Command::ReplaceFact(rest.trim().to_string()));
    }
    if let Some(inner) = line.strip_prefix('+') {
        return Ok(Command::AssertFact(
            inner.trim_end_matches('.').trim().to_string(),
        ));
    }
    if let Some(inner) = line.strip_prefix('-') {
        return Ok(Command::RetractFact(
            inner.trim_end_matches('.').trim().to_string(),
        ));
    }

    if let Some(src) = line.strip_prefix("::source ") {
        return Ok(Command::Source(src.trim().to_string()));
    }

    if let Some(rest) = line.strip_prefix("::k8s::load ") {
        return Ok(Command::K8sLoad(rest.trim().to_string()));
    }
    if let Some(rest) = line.strip_prefix("::k8s::apply-delta ") {
        return Ok(Command::K8sApplyDelta(rest.trim().to_string()));
    }

    if let Some(rest) = line.strip_prefix("::load ") {
        let rest = rest.trim();
        return match rest.split_once(char::is_whitespace) {
            Some((relation, source)) => Ok(Command::Load {
                relation: relation.to_string(),
                source: source.trim().to_string(),
            }),
            None => err("Usage: load <relation> <source>  (source is a file path or ! <cmd>)"),
        };
    }

    // `k8s::match <Kind> <namespace> <selector>` scopes to one Kind;
    // `k8s::match-all <namespace> <selector>` matches any Kind.
    let match_args = line
        .strip_prefix("::k8s::match ")
        .map(|rest| (rest, true))
        .or_else(|| {
            line.strip_prefix("::k8s::match-all ")
                .map(|rest| (rest, false))
        });
    if let Some((rest, one_kind)) = match_args {
        let fields = if one_kind { 3 } else { 2 };
        let parts: Vec<&str> = rest.trim().splitn(fields, char::is_whitespace).collect();
        let (kind, namespace, selector) = match (one_kind, parts.as_slice()) {
            (true, [kind, namespace, selector]) => (Some(kind.to_string()), *namespace, *selector),
            (false, [namespace, selector]) => (None, *namespace, *selector),
            (true, _) => {
                return err(
                    "Usage: k8s::match <Kind> <namespace> <selector>  (namespace \"\" for cluster-scoped)",
                );
            }
            (false, _) => return err("Usage: k8s::match-all <namespace> <selector>"),
        };
        // The cluster-scoped namespace is typed as ""; the REPL does not
        // otherwise strip quotes from arguments.
        return Ok(Command::K8sMatch {
            kind,
            namespace: namespace.trim_matches('"').to_string(),
            selector: selector.to_string(),
        });
    }

    // `rbac::diff` must be recognized before the `rbac::` catch-all below.
    if line == "::rbac::diff" {
        return err("Usage: rbac::diff <snap> [snap2] [--hide-escalation-lost]");
    }
    if let Some(rest) = line.strip_prefix("::rbac::diff ") {
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        let hide_escalation_lost = tokens.contains(&"--hide-escalation-lost");
        let parts: Vec<&str> = tokens
            .iter()
            .filter(|t| **t != "--hide-escalation-lost")
            .copied()
            .collect();
        return match parts.as_slice() {
            [name] => Ok(Command::RbacDiff {
                first: name.to_string(),
                second: None,
                hide_escalation_lost,
            }),
            [first, second] => Ok(Command::RbacDiff {
                first: first.to_string(),
                second: Some(second.to_string()),
                hide_escalation_lost,
            }),
            _ => err("Usage: rbac::diff <snap> [snap2] [--hide-escalation-lost]"),
        };
    }
    if let Some(rest) = line.strip_prefix("::rbac::") {
        return Ok(Command::Rbac(rest.trim().to_string()));
    }
    if let Some(rest) = line.strip_prefix("::sched::") {
        return Ok(Command::Sched(rest.trim().to_string()));
    }

    if let Some(query) = line.strip_prefix("::explain ") {
        return Ok(Command::Explain(query.to_string()));
    }

    if let Some(rest) = line.strip_prefix("::smtlib ") {
        let relations: Vec<String> = rest.split_whitespace().map(str::to_string).collect();
        if relations.is_empty() {
            return err("Usage: smtlib <relation> [relation ...]");
        }
        return Ok(Command::Smtlib(relations));
    }

    if line == "::rollback" || line.starts_with("::rollback ") {
        let name = line.strip_prefix("::rollback").unwrap_or("").trim();
        if name.is_empty() {
            return err("Usage: rollback <name>");
        }
        return Ok(Command::Rollback(name.to_string()));
    }

    if let Some(cmd) = line.strip_prefix('!') {
        return Ok(Command::Shell(cmd.trim().to_string()));
    }

    if line == "::quit" || line == "::exit" || line == "::q" {
        return Ok(Command::Quit);
    }

    if line == "::help" || line.starts_with("::help ") {
        let topic = line.strip_prefix("::help").unwrap_or("").trim();
        return Ok(Command::Help(
            (!topic.is_empty()).then(|| topic.to_string()),
        ));
    }

    if line == "::alias" || line.starts_with("::alias ") {
        let rest = line.strip_prefix("::alias").unwrap_or("").trim();
        let alias = if rest.is_empty() {
            AliasCommand::List
        } else if let Some((name, body)) = rest.split_once(char::is_whitespace) {
            let body = body.trim();
            if body.is_empty() {
                return err("Usage: alias <name> <command...>");
            }
            AliasCommand::Set {
                name: name.to_string(),
                body: body.to_string(),
            }
        } else {
            AliasCommand::Show(rest.to_string())
        };
        return Ok(Command::Alias(alias));
    }

    if line == "::unalias" || line.starts_with("::unalias ") {
        let name = line.strip_prefix("::unalias").unwrap_or("").trim();
        if name.is_empty() {
            return err("Usage: unalias <name>");
        }
        return Ok(Command::Unalias(name.to_string()));
    }

    if line == "::pretty" {
        return Ok(Command::PrettyToggle);
    }

    if line == "::format" || line.starts_with("::format ") {
        let arg = line.strip_prefix("::format").unwrap_or("").trim();
        let format = match arg {
            "default" => Some(OutputFormat::Plain),
            "compact" => Some(OutputFormat::Compact),
            "pretty" => Some(OutputFormat::Pretty),
            "table" => Some(OutputFormat::Table),
            "ndjson" => Some(OutputFormat::Ndjson),
            "" => None, // no arg: just report the current format
            other => {
                return err(&format!(
                    "Unknown format '{other}'. Use: default | compact | pretty | table | ndjson."
                ));
            }
        };
        return Ok(Command::Format(format));
    }

    // Bare subsystem namespaces list their subcommands.
    if line == "::rbac" {
        return Ok(Command::SubsystemHelp(Subsystem::Rbac));
    }
    if line == "::sched" {
        return Ok(Command::SubsystemHelp(Subsystem::Sched));
    }
    if line == "::k8s" {
        return Ok(Command::SubsystemHelp(Subsystem::K8s));
    }

    // No built-in matched. Hand back the path after `::` for the dispatcher to
    // report (and, later, for an extension registry to claim).
    Ok(Command::Unknown(
        line.strip_prefix("::").unwrap_or(line).to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Command {
        parse_command(line).expect("should parse")
    }

    fn usage(line: &str) -> String {
        parse_command(line).expect_err("should fail").0
    }

    #[test]
    fn queries_keep_both_spellings() {
        assert_eq!(parse("?- pod(X)"), Command::Query("pod(X)".into()));
        assert_eq!(parse("::query pod(X)"), Command::Query("pod(X)".into()));
    }

    #[test]
    fn why_passes_fact_through_verbatim() {
        assert_eq!(parse("::why pod(X, Y)"), Command::Why("pod(X, Y)".into()));
    }

    #[test]
    fn use_has_three_forms() {
        assert_eq!(
            parse("::use"),
            Command::Use {
                snapshot: None,
                one_shot: None
            }
        );
        assert_eq!(
            parse("::use before"),
            Command::Use {
                snapshot: Some("before".into()),
                one_shot: None
            }
        );
        assert_eq!(
            parse("::use before rbac::reaches admin"),
            Command::Use {
                snapshot: Some("before".into()),
                one_shot: Some("rbac::reaches admin".into())
            }
        );
    }

    #[test]
    fn diff_against_in_use_or_two_snapshots() {
        assert_eq!(
            parse("::diff before"),
            Command::Diff {
                first: "before".into(),
                second: None,
                relation: None
            }
        );
        assert_eq!(
            parse("::diff before after"),
            Command::Diff {
                first: "before".into(),
                second: Some("after".into()),
                relation: None
            }
        );
    }

    #[test]
    fn diff_relation_takes_the_trailing_relation() {
        assert_eq!(
            parse("::diff-relation before rbac_allowed"),
            Command::Diff {
                first: "before".into(),
                second: None,
                relation: Some("rbac_allowed".into())
            }
        );
        assert_eq!(
            parse("::diff-relation before after rbac_allowed"),
            Command::Diff {
                first: "before".into(),
                second: Some("after".into()),
                relation: Some("rbac_allowed".into())
            }
        );
    }

    #[test]
    fn diff_arity_errors_name_their_form() {
        assert!(usage("::diff a b c").contains("Usage: diff <name>"));
        // Only the relation token: nothing left to diff.
        assert!(usage("::diff-relation rel").contains("Usage: diff-relation"));
    }

    #[test]
    fn show_collects_flags_and_names() {
        assert_eq!(
            parse("::show"),
            Command::Show {
                names: vec![],
                all: false
            }
        );
        assert_eq!(
            parse("::show --all pod node"),
            Command::Show {
                names: vec!["pod".into(), "node".into()],
                all: true
            }
        );
        assert_eq!(
            parse("::show *"),
            Command::Show {
                names: vec![],
                all: true
            }
        );
    }

    #[test]
    fn fact_mutators_trim_as_the_loop_did() {
        assert_eq!(parse("+pod(x)."), Command::AssertFact("pod(x)".into()));
        assert_eq!(parse("-pod(x)."), Command::RetractFact("pod(x)".into()));
        assert_eq!(
            parse("~pod(x). pod(y)."),
            Command::ReplaceFact("pod(x). pod(y).".into())
        );
    }

    #[test]
    fn load_needs_a_relation_and_source() {
        assert_eq!(
            parse("::load rel data.tsv"),
            Command::Load {
                relation: "rel".into(),
                source: "data.tsv".into()
            }
        );
        assert!(usage("::load rel").contains("Usage: load"));
    }

    #[test]
    fn k8s_match_scopes_and_strips_namespace_quotes() {
        assert_eq!(
            parse("::k8s::match Pod default app=web"),
            Command::K8sMatch {
                kind: Some("Pod".into()),
                namespace: "default".into(),
                selector: "app=web".into()
            }
        );
        assert_eq!(
            parse("::k8s::match-all \"\" app=web"),
            Command::K8sMatch {
                kind: None,
                namespace: "".into(),
                selector: "app=web".into()
            }
        );
        assert!(usage("::k8s::match Pod").contains("Usage: k8s::match <Kind>"));
        assert!(usage("::k8s::match-all one").contains("Usage: k8s::match-all"));
    }

    #[test]
    fn rbac_diff_parses_flag_and_arity() {
        assert_eq!(
            parse("::rbac::diff before --hide-escalation-lost"),
            Command::RbacDiff {
                first: "before".into(),
                second: None,
                hide_escalation_lost: true
            }
        );
        assert_eq!(
            parse("::rbac::diff before after"),
            Command::RbacDiff {
                first: "before".into(),
                second: Some("after".into()),
                hide_escalation_lost: false
            }
        );
        assert!(usage("::rbac::diff").contains("Usage: rbac::diff"));
    }

    #[test]
    fn rbac_diff_wins_over_the_rbac_catch_all() {
        // `rbac::diff ...` must not be routed to the generic `rbac::` check.
        assert!(matches!(
            parse("::rbac::diff before"),
            Command::RbacDiff { .. }
        ));
        assert_eq!(
            parse("::rbac::reaches admin"),
            Command::Rbac("reaches admin".into())
        );
        assert_eq!(
            parse("::sched::karpenter"),
            Command::Sched("karpenter".into())
        );
    }

    #[test]
    fn smtlib_needs_at_least_one_relation() {
        assert_eq!(
            parse("::smtlib a b"),
            Command::Smtlib(vec!["a".into(), "b".into()])
        );
        assert!(usage("::smtlib ").contains("Usage: smtlib"));
    }

    #[test]
    fn rollback_requires_a_name() {
        assert_eq!(
            parse("::rollback before"),
            Command::Rollback("before".into())
        );
        assert!(usage("::rollback").contains("Usage: rollback"));
    }

    #[test]
    fn simple_and_terminal_commands() {
        assert_eq!(parse("!ls -la"), Command::Shell("ls -la".into()));
        assert_eq!(parse("::quit"), Command::Quit);
        assert_eq!(parse("::exit"), Command::Quit);
        assert_eq!(parse("::q"), Command::Quit);
        assert_eq!(parse("::pretty"), Command::PrettyToggle);
        assert_eq!(parse("::help"), Command::Help(None));
        assert_eq!(
            parse("::help rbac::reaches"),
            Command::Help(Some("rbac::reaches".into()))
        );
    }

    #[test]
    fn alias_forms() {
        assert_eq!(parse("::alias"), Command::Alias(AliasCommand::List));
        assert_eq!(
            parse("::alias r"),
            Command::Alias(AliasCommand::Show("r".into()))
        );
        assert_eq!(
            parse("::alias r rbac::reaches"),
            Command::Alias(AliasCommand::Set {
                name: "r".into(),
                body: "rbac::reaches".into()
            })
        );
        assert_eq!(parse("::unalias r"), Command::Unalias("r".into()));
        assert!(usage("::unalias").contains("Usage: unalias"));
    }

    #[test]
    fn format_validates_its_argument() {
        assert_eq!(parse("::format"), Command::Format(None));
        assert_eq!(
            parse("::format table"),
            Command::Format(Some(OutputFormat::Table))
        );
        assert_eq!(
            parse("::format default"),
            Command::Format(Some(OutputFormat::Plain))
        );
        assert!(usage("::format bogus").contains("Unknown format 'bogus'"));
    }

    #[test]
    fn bare_subsystem_lists_its_commands() {
        assert_eq!(parse("::rbac"), Command::SubsystemHelp(Subsystem::Rbac));
        assert_eq!(parse("::sched"), Command::SubsystemHelp(Subsystem::Sched));
        assert_eq!(parse("::k8s"), Command::SubsystemHelp(Subsystem::K8s));
    }

    #[test]
    fn unknown_paths_fall_through_for_the_dispatcher() {
        // A no-space bare verb is not a built-in match; it falls through so the
        // dispatcher can show its usage hint.
        assert_eq!(parse("::diff"), Command::Unknown("diff".into()));
        assert_eq!(parse("::snapshot"), Command::Unknown("snapshot".into()));
        assert_eq!(
            parse("::k8s::nope arg"),
            Command::Unknown("k8s::nope arg".into())
        );
        assert_eq!(
            parse("::madeup::thing"),
            Command::Unknown("madeup::thing".into())
        );
    }
}
