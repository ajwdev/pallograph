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
/// the loop strips first.
///
/// The shape is: handle the sigil forms, which glue their argument to the
/// sigil; then the `rbac::`/`sched::` subsystems, which take any subcommand
/// (so they match on the namespace prefix); then split what remains into a
/// head word and an argument and match on the head. `argument` is `None` when
/// the head stands alone, which lets a command whose argument is required
/// (e.g. `query`) fall through to a usage hint.
pub fn parse_command(line: &str) -> Result<Command, ParseError> {
    // Sigil forms carry their argument glued to the sigil, except the `?- `
    // query shorthand. The handler parses the fact atoms; `+`/`-` drop a
    // trailing `.` and `~` keeps both atoms together.
    if let Some(body) = line.strip_prefix("?- ") {
        return Ok(Command::Query(body.to_string()));
    }
    if let Some(atoms) = line.strip_prefix('~') {
        return Ok(Command::ReplaceFact(atoms.trim().to_string()));
    }
    if let Some(atom) = line.strip_prefix('+') {
        return Ok(Command::AssertFact(
            atom.trim_end_matches('.').trim().to_string(),
        ));
    }
    if let Some(atom) = line.strip_prefix('-') {
        return Ok(Command::RetractFact(
            atom.trim_end_matches('.').trim().to_string(),
        ));
    }
    if let Some(cmd) = line.strip_prefix('!') {
        return Ok(Command::Shell(cmd.trim().to_string()));
    }

    // Everything else is a `::`-qualified command; the loop canonicalizes a
    // bare command to this form before calling us.
    let path = line.strip_prefix("::").unwrap_or(line);

    // The `rbac::` and `sched::` subsystems hand any subcommand to their own
    // parser, so they match on the namespace prefix. `rbac::diff` has
    // structured arguments of its own, so it is recognized first.
    if path == "rbac::diff" {
        return err("Usage: rbac::diff <snap> [snap2] [--hide-escalation-lost]");
    }
    if let Some(args) = path.strip_prefix("rbac::diff ") {
        return parse_rbac_diff(args);
    }
    if let Some(rest) = path.strip_prefix("rbac::") {
        return Ok(Command::Rbac(rest.trim().to_string()));
    }
    if let Some(rest) = path.strip_prefix("sched::") {
        return Ok(Command::Sched(rest.trim().to_string()));
    }

    let (head, argument) = match path.split_once(' ') {
        Some((head, argument)) => (head, Some(argument)),
        None => (path, None),
    };

    Ok(match (head, argument) {
        // Arguments the engine parses, passed through verbatim.
        ("query", Some(body)) => Command::Query(body.to_string()),
        ("why", Some(fact)) => Command::Why(fact.to_string()),
        ("explain", Some(body)) => Command::Explain(body.to_string()),
        ("define", Some(rule)) => Command::Define(rule.to_string()),
        ("source", Some(src)) => Command::Source(src.trim().to_string()),
        ("snapshot", Some(name)) => Command::Snapshot(name.trim().to_string()),

        // Arguments parsed into structured fields.
        ("use", _) => parse_use(argument),
        ("show", _) => parse_show(argument),
        ("diff", Some(args)) => parse_diff(args, false)?,
        ("diff-relation", Some(args)) => parse_diff(args, true)?,
        ("load", Some(args)) => parse_load(args)?,
        ("smtlib", Some(args)) => parse_smtlib(args)?,
        ("k8s::load", Some(spec)) => Command::K8sLoad(spec.trim().to_string()),
        ("k8s::apply-delta", Some(spec)) => Command::K8sApplyDelta(spec.trim().to_string()),
        ("k8s::match", Some(args)) => parse_k8s_match(args, true)?,
        ("k8s::match-all", Some(args)) => parse_k8s_match(args, false)?,

        // Commands with a single required name.
        ("rollback", _) => match argument.map(str::trim).filter(|a| !a.is_empty()) {
            Some(name) => Command::Rollback(name.to_string()),
            None => return err("Usage: rollback <name>"),
        },
        ("unalias", _) => match argument.map(str::trim).filter(|a| !a.is_empty()) {
            Some(name) => Command::Unalias(name.to_string()),
            None => return err("Usage: unalias <name>"),
        },

        // Session commands.
        ("alias", _) => parse_alias(argument)?,
        ("format", _) => parse_format(argument)?,
        ("help", _) => Command::Help(
            argument
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(String::from),
        ),

        // Commands that take no argument.
        ("quit" | "exit" | "q", None) => Command::Quit,
        ("pretty", None) => Command::PrettyToggle,
        ("rbac", None) => Command::SubsystemHelp(Subsystem::Rbac),
        ("sched", None) => Command::SubsystemHelp(Subsystem::Sched),
        ("k8s", None) => Command::SubsystemHelp(Subsystem::K8s),

        // No built-in matched (or a known command used with no argument, e.g.
        // a bare `diff`). Hand back the path for the dispatcher to report, and
        // for a future extension registry to claim.
        _ => Command::Unknown(path.to_string()),
    })
}

/// `use [<snapshot> [<command>]]`: no snapshot returns to live state; a
/// trailing command runs once with the snapshot in use.
fn parse_use(argument: Option<&str>) -> Command {
    let rest = argument.unwrap_or("").trim();
    if rest.is_empty() {
        return Command::Use {
            snapshot: None,
            one_shot: None,
        };
    }
    let (name, one_shot) = match rest.split_once(char::is_whitespace) {
        Some((name, command)) => (name.to_string(), Some(command.trim().to_string())),
        None => (rest.to_string(), None),
    };
    Command::Use {
        snapshot: Some(name),
        one_shot,
    }
}

/// `show [--all | *] [<relation>...]`.
fn parse_show(argument: Option<&str>) -> Command {
    // `--all`/`*` reveals undocumented intermediate relations; the rest are
    // explicit relation names.
    let mut all = false;
    let mut names = Vec::new();
    for token in argument.unwrap_or("").split_whitespace() {
        if token == "--all" || token == "*" {
            all = true;
        } else {
            names.push(token.to_string());
        }
    }
    Command::Show { names, all }
}

/// `diff <a> [<b>]`, or `diff-relation <a> [<b>] <relation>` when
/// `one_relation`. A single name diffs against whatever is in use; the
/// relation, present only for `diff-relation`, is the last token.
fn parse_diff(args: &str, one_relation: bool) -> Result<Command, ParseError> {
    let mut parts: Vec<&str> = args.split_whitespace().collect();
    let relation = if one_relation {
        parts.pop().map(str::to_string)
    } else {
        None
    };
    match parts.as_slice() {
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
    }
}

/// `load <relation> <source>`.
fn parse_load(args: &str) -> Result<Command, ParseError> {
    match args.trim().split_once(char::is_whitespace) {
        Some((relation, source)) => Ok(Command::Load {
            relation: relation.to_string(),
            source: source.trim().to_string(),
        }),
        None => err("Usage: load <relation> <source>  (source is a file path or ! <cmd>)"),
    }
}

/// `smtlib <relation> [<relation>...]`.
fn parse_smtlib(args: &str) -> Result<Command, ParseError> {
    let relations: Vec<String> = args.split_whitespace().map(str::to_string).collect();
    if relations.is_empty() {
        return err("Usage: smtlib <relation> [relation ...]");
    }
    Ok(Command::Smtlib(relations))
}

/// `k8s::match <Kind> <namespace> <selector>` (one kind) or
/// `k8s::match-all <namespace> <selector>` (any kind).
fn parse_k8s_match(args: &str, one_kind: bool) -> Result<Command, ParseError> {
    let fields = if one_kind { 3 } else { 2 };
    let parts: Vec<&str> = args.trim().splitn(fields, char::is_whitespace).collect();
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
    // The cluster-scoped namespace is typed as ""; the REPL does not otherwise
    // strip quotes from arguments.
    Ok(Command::K8sMatch {
        kind,
        namespace: namespace.trim_matches('"').to_string(),
        selector: selector.to_string(),
    })
}

/// `rbac::diff <snap> [<snap2>] [--hide-escalation-lost]`.
fn parse_rbac_diff(args: &str) -> Result<Command, ParseError> {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    let hide_escalation_lost = tokens.contains(&"--hide-escalation-lost");
    let parts: Vec<&str> = tokens
        .iter()
        .filter(|t| **t != "--hide-escalation-lost")
        .copied()
        .collect();
    match parts.as_slice() {
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
    }
}

/// `alias`, `alias <name>`, or `alias <name> <command...>`.
fn parse_alias(argument: Option<&str>) -> Result<Command, ParseError> {
    let rest = argument.unwrap_or("").trim();
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
    Ok(Command::Alias(alias))
}

/// `format [default|compact|pretty|table|ndjson]`; no argument reports the
/// current format (`None`).
fn parse_format(argument: Option<&str>) -> Result<Command, ParseError> {
    let format = match argument.unwrap_or("").trim() {
        "default" => Some(OutputFormat::Plain),
        "compact" => Some(OutputFormat::Compact),
        "pretty" => Some(OutputFormat::Pretty),
        "table" => Some(OutputFormat::Table),
        "ndjson" => Some(OutputFormat::Ndjson),
        "" => None,
        other => {
            return err(&format!(
                "Unknown format '{other}'. Use: default | compact | pretty | table | ndjson."
            ));
        }
    };
    Ok(Command::Format(format))
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
