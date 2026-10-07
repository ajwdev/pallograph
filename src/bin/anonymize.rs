// Copyright (c) 2026 Netflix, Inc.
// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Anonymize a `kubectl get -o json` dump so it can be shared or benchmarked
//! without leaking real names.
//!
//! Fail-closed by default: every string is split into alphanumeric runs
//! ("tokens") and each token is replaced by a same-length, same-character-
//! class fake (separators are copied verbatim). The token map is global and
//! injective, so joins between objects (names, namespaces, labels,
//! selectors, UUIDs, `system:serviceaccount:<ns>:<sa>`) survive.
//!
//! A path table (`act_for`) carves out fields whose values are public or
//! structural and must stay readable: enums (`operator`, `effect`, ...),
//! `apiVersion`/`kind`, RBAC verbs/resources/apiGroups (when public),
//! well-known scheduling labels (arch, zone, instance-type, ...), and
//! resource quantities. Built-in principals from `src/builtins.txt` and a
//! few reserved names (`default`, `cluster-admin`, `kube-system`) are kept
//! whole so the engine's literals still match. Secret/ConfigMap base64
//! payloads are replaced with random base64 of the same length.
//!
//!   cargo run --release --bin anonymize -- real/dump.json \
//!       -o anon/dump.json --check --report

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const VOCAB: &str = include_str!("../../hack/anonymize/public-vocab.txt");
const API_RESOURCES: &str = include_str!("../../fixtures/testdata/small/api-resources.txt");
const BUILTINS: &str = include_str!("../builtins.txt");

/// Names the rules and SMT code compare against literally.
const KEEP_NAMES: &[&str] = &[
    "default",
    "cluster-admin",
    "kube-system",
    "kube-public",
    "kube-node-lease",
];
/// String fields that are schema enums; kept verbatim.
const ENUM_KEYS: &[&str] = &[
    "operator",
    "effect",
    "protocol",
    "imagePullPolicy",
    "restartPolicy",
    "dnsPolicy",
    "preemptionPolicy",
    "whenUnsatisfiable",
    "phase",
    "status",
    "qosClass",
    "scheme",
    "medium",
    "mountPropagation",
    "terminationMessagePolicy",
    "consolidationPolicy",
];
/// (parent, key) enum fields that are too generic to match on key alone.
const ENUM_PAIRS: &[(&str, &str)] = &[
    ("seccompProfile", "type"),
    ("appArmorProfile", "type"),
    ("hostPath", "type"),
    ("capabilities", "add"),
    ("capabilities", "drop"),
];
/// Domains whose label/annotation/resource keys are public.
const PUBLIC_DOMAINS: &[&str] = &[
    "kubernetes.io",
    "k8s.io",
    "karpenter.sh",
    "karpenter.k8s.aws",
    "amazonaws.com",
    "argoproj.io",
    "helm.sh",
    "nvidia.com",
    "cert-manager.io",
    "cilium.io",
];
/// Unprefixed public keys (resource names, matchFields paths).
const PUBLIC_KEYS: &[&str] = &[
    "cpu",
    "memory",
    "pods",
    "ephemeral-storage",
    "storage",
    "nodes",
    "metadata.name",
    "metadata.namespace",
    "spec.nodeName",
];
/// Maps whose *keys* are free-form user strings. `true` if values are
/// label-like (eligible for public-value keeping).
const FREEFORM: &[(&str, bool)] = &[
    ("labels", true),
    ("nodeSelector", true),
    ("matchLabels", true),
    ("selector", true),
    ("annotations", false),
    ("data", false),
    ("binaryData", false),
    ("stringData", false),
];
/// Resource-quantity maps: keys are rewritten unless public, values
/// (`250m`, `16Gi`) are kept so scheduling math stays realistic.
const QTY_MAPS: &[&str] = &[
    "capacity",
    "allocatable",
    "allocatedResources",
    "limits",
    "requests",
];
/// String-valued fields copied verbatim.
const SKIP_STR: &[&str] = &["resourceVersion"];

#[derive(Parser)]
#[command(about = "Anonymize a k8s JSON dump, preserving relations and string lengths")]
struct Cli {
    /// Input JSON file (a List, a single object, or concatenated objects)
    input: PathBuf,
    /// Output JSON file
    #[arg(short, long)]
    output: PathBuf,
    /// PRNG seed (default: random). Same seed + input => same output.
    #[arg(long)]
    seed: Option<u64>,
    /// Local denylist (case-insensitive substrings, one per line). Matches
    /// are always rewritten and fail `--check` if they survive. Keep this
    /// file out of git (`*.local.txt` is ignored).
    #[arg(long)]
    deny: Option<PathBuf>,
    /// Write the real->fake token map here (never written unless asked)
    #[arg(long)]
    mapping: Option<PathBuf>,
    /// Print every field path + value kept verbatim, with counts, to stderr
    #[arg(long)]
    report: bool,
    /// Scan the output for leaks; exit non-zero on a hit
    #[arg(long)]
    check: bool,
}

fn word_list(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(str::to_string)
}

/// Split `s` into alternating (is_token, run) pieces; a token is a maximal
/// run of ASCII alphanumerics.
fn runs(s: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_tok = false;
    for (i, c) in s.char_indices() {
        let t = c.is_ascii_alphanumeric();
        if i == 0 {
            in_tok = t;
        } else if t != in_tok {
            out.push((in_tok, &s[start..i]));
            start = i;
            in_tok = t;
        }
    }
    if !s.is_empty() {
        out.push((in_tok, &s[start..]));
    }
    out
}

/// Quantity/duration-like tokens (`500m`, `100Mi`, `720h`, `8080`) are kept.
fn is_quantity(tok: &str) -> bool {
    let digits = tok.bytes().take_while(u8::is_ascii_digit).count();
    let rest = &tok[digits..];
    digits > 0 && digits <= 4 && rest.len() <= 2 && rest.bytes().all(|b| b.is_ascii_alphabetic())
}

/// `2026-09-16T21:50:12Z`-style timestamps are copied verbatim.
fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 20
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
}

fn public_domain(d: &str) -> bool {
    PUBLIC_DOMAINS
        .iter()
        .any(|p| d == *p || d.strip_suffix(p).is_some_and(|h| h.ends_with('.')))
}

/// Is this label/annotation/resource *key* public (so safe to keep)?
fn public_key(k: &str) -> bool {
    PUBLIC_KEYS.contains(&k)
        || k.starts_with("hugepages-")
        || k.split_once('/').is_some_and(|(d, _)| public_domain(d))
}

/// Label keys whose *values* are public (arch, zone, instance type, ...),
/// so nodeSelectors, node labels and NodePool requirements stay realistic.
fn public_value_key(k: &str) -> bool {
    matches!(
        k,
        "kubernetes.io/arch"
            | "kubernetes.io/os"
            | "beta.kubernetes.io/arch"
            | "beta.kubernetes.io/os"
            | "node.kubernetes.io/instance-type"
            | "beta.kubernetes.io/instance-type"
            | "topology.kubernetes.io/zone"
            | "topology.kubernetes.io/region"
            | "failure-domain.beta.kubernetes.io/zone"
            | "failure-domain.beta.kubernetes.io/region"
            | "topology.k8s.aws/zone-id"
            | "karpenter.sh/capacity-type"
            | "eks.amazonaws.com/capacityType"
    ) || k.starts_with("karpenter.k8s.aws/instance-")
        || k.starts_with("nvidia.com/")
}

/// How a string at some field path is treated.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Act {
    /// Tokenize and rewrite (the default).
    Text,
    /// Keep verbatim (schema enum / public value).
    Keep,
    /// Keep verbatim if every word is public k8s vocabulary, else rewrite.
    Vocab,
    /// Keep verbatim if it is a public label/resource key, else rewrite.
    Key,
}

fn act_for(path: &[&str], keep_vals: bool) -> Act {
    if keep_vals {
        return Act::Keep;
    }
    let last = path.last().copied().unwrap_or("");
    let parent = if path.len() >= 2 {
        path[path.len() - 2]
    } else {
        ""
    };
    if ENUM_KEYS.contains(&last) || ENUM_PAIRS.contains(&(parent, last)) {
        return Act::Keep;
    }
    match last {
        "verbs" | "apiVersion" | "kind" | "apiGroup" => Act::Vocab,
        "resources" | "apiGroups" if path.contains(&"rules") => Act::Vocab,
        "key" | "topologyKey" => Act::Key,
        _ => Act::Text,
    }
}

struct Mapper {
    deny: Vec<String>,
    vocab: HashSet<String>,
    keep_exact: HashSet<String>,
    keep_prefix: Vec<String>,
    /// Every token in the input; fakes never collide with these.
    seen: HashSet<String>,
    map: HashMap<String, String>,
    issued: HashSet<String>,
    /// Tokens intentionally kept verbatim somewhere (excluded from --check's
    /// "rewritten token survived" test).
    kept_tokens: HashSet<String>,
    /// "path = value" -> count, for --report.
    kept_paths: HashMap<String, usize>,
    /// real base64 value -> fake base64 value
    b64: HashMap<String, String>,
    rng: u64,
}

impl Mapper {
    fn new(seed: u64, deny: Vec<String>) -> Self {
        let vocab = word_list(VOCAB)
            .chain(API_RESOURCES.lines().map(str::to_string))
            .flat_map(|l| {
                runs(&l)
                    .into_iter()
                    .filter(|r| r.0)
                    .map(|r| r.1.to_string())
                    .collect::<Vec<_>>()
            })
            .collect();

        let mut keep_exact: HashSet<String> = KEEP_NAMES.iter().map(|s| s.to_string()).collect();
        let mut keep_prefix = Vec::new();
        for line in word_list(BUILTINS) {
            if let Some(p) = line.strip_suffix('*') {
                keep_prefix.push(p.to_string());
            } else {
                // `system:serviceaccount:kube-system:<sa>` is built from
                // namespace + name at eval time, so keep the bare SA name too.
                if let Some(sa) = line.strip_prefix("system:serviceaccount:kube-system:") {
                    keep_exact.insert(sa.to_string());
                }
                keep_exact.insert(line);
            }
        }

        Mapper {
            deny,
            vocab,
            keep_exact,
            keep_prefix,
            seen: HashSet::new(),
            map: HashMap::new(),
            issued: HashSet::new(),
            kept_tokens: HashSet::new(),
            kept_paths: HashMap::new(),
            b64: HashMap::new(),
            // xorshift must not start at zero
            rng: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
        }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    fn denied(&self, s: &str) -> bool {
        if self.deny.is_empty() {
            return false;
        }
        let lower = s.to_ascii_lowercase();
        self.deny.iter().any(|d| lower.contains(d.as_str()))
    }

    fn is_builtin(&self, s: &str) -> bool {
        self.keep_exact.contains(s) || self.keep_prefix.iter().any(|p| s.starts_with(p.as_str()))
    }

    /// Pass 1: record every token so fakes can avoid them.
    fn note(&mut self, s: &str) {
        for (is_tok, r) in runs(s) {
            if is_tok {
                self.seen.insert(r.to_string());
            }
        }
    }

    fn fresh(&mut self, tok: &str) -> String {
        let hex = tok.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        for _ in 0..100_000 {
            let fake: String = tok
                .bytes()
                .map(|b| match b {
                    b'0'..=b'9' => (b'0' + (self.next() % 10) as u8) as char,
                    b'a'..=b'z' if hex => (b'a' + (self.next() % 6) as u8) as char,
                    b'a'..=b'z' => (b'a' + (self.next() % 26) as u8) as char,
                    _ => (b'A' + (self.next() % 26) as u8) as char,
                })
                .collect();
            if fake != tok
                && !self.seen.contains(&fake)
                && !self.issued.contains(&fake)
                && !self.denied(&fake)
            {
                self.issued.insert(fake.clone());
                return fake;
            }
        }
        panic!("token space exhausted for {tok:?}");
    }

    /// Random base64 with the same encoded length (and padding) as `s`,
    /// memoized so equal secrets stay equal. `s` must satisfy `is_b64`.
    fn fake_b64(&mut self, s: &str) -> String {
        if let Some(f) = self.b64.get(s) {
            return f.clone();
        }
        let pad = s.len() - s.trim_end_matches('=').len();
        let n = s.len() / 4 * 3 - pad;
        let fake = loop {
            let bytes: Vec<u8> = (0..n).map(|_| self.next() as u8).collect();
            let f = b64_encode(&bytes);
            if f != s && !self.denied(&f) {
                break f;
            }
        };
        self.b64.insert(s.to_string(), fake.clone());
        fake
    }

    /// Pass 2: rewrite one string according to its field's `Act`.
    fn apply(&mut self, path: &[&str], s: &str, act: Act) -> String {
        if s.is_empty() {
            return String::new();
        }
        let keep = !self.denied(s)
            && (self.is_builtin(s)
                || match act {
                    Act::Text => false,
                    Act::Keep => true,
                    Act::Vocab => runs(s)
                        .iter()
                        .filter(|r| r.0)
                        .all(|r| self.vocab.contains(r.1)),
                    Act::Key => public_key(s),
                });
        if keep {
            let shown: String = s.chars().take(100).collect();
            *self
                .kept_paths
                .entry(format!("{} = {shown}", path.join(".")))
                .or_default() += 1;
            for (is_tok, r) in runs(s) {
                if is_tok {
                    self.kept_tokens.insert(r.to_string());
                }
            }
            return s.to_string();
        }
        self.rewrite(s)
    }

    /// Token-wise rewrite. The `system:` / `system:serviceaccount:` prefixes
    /// are kept because the engine parses them.
    fn rewrite(&mut self, s: &str) -> String {
        let mut keep_lead = if s.starts_with("system:serviceaccount:") {
            2
        } else if s.starts_with("system:") {
            1
        } else {
            0
        };
        let mut out = String::with_capacity(s.len());
        for (is_tok, r) in runs(s) {
            if !is_tok {
                out.push_str(r);
                continue;
            }
            if keep_lead > 0 {
                keep_lead -= 1;
                out.push_str(r);
            } else if !self.denied(r) && (r.len() <= 2 || is_quantity(r)) {
                self.kept_tokens.insert(r.to_string());
                out.push_str(r);
            } else if let Some(f) = self.map.get(r) {
                out.push_str(f);
            } else {
                let f = self.fresh(r);
                self.map.insert(r.to_string(), f.clone());
                out.push_str(&f);
            }
        }
        out
    }
}

/// Field of `v` that holds base64 values: `Secret.data`, `ConfigMap.binaryData`.
fn b64_field(v: &Value) -> Option<&'static str> {
    match v.get("kind").and_then(Value::as_str) {
        Some("Secret") => Some("data"),
        Some("ConfigMap") => Some("binaryData"),
        _ => None,
    }
}

fn is_b64(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !s.is_empty()
        && s.len().is_multiple_of(4)
        && s.len() - body.len() <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn b64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Visit every top-level object, unwrapping `List.items`.
fn for_each_object(v: &mut Value, f: &mut dyn FnMut(&mut Value)) {
    if let Some(items) = v.get_mut("items").and_then(Value::as_array_mut) {
        items.iter_mut().for_each(|i| for_each_object(i, f));
    } else {
        f(v);
    }
}

fn blank_b64(v: &mut Value) {
    for_each_object(v, &mut |o| {
        let Some(field) = b64_field(o) else { return };
        if let Some(m) = o.get_mut(field).and_then(Value::as_object_mut) {
            for x in m.values_mut().filter(|x| x.as_str().is_some_and(is_b64)) {
                *x = Value::String(String::new());
            }
        }
    });
}

/// Replace blanked base64 values in `anon` with random base64 of the same
/// length, consistent per distinct input value. `orig` and `anon` must have
/// the same shape.
fn fill_b64(orig: &Value, anon: &mut Value, m: &mut Mapper) {
    if let (Some(oi), Some(ai)) = (
        orig.get("items").and_then(Value::as_array),
        anon.get_mut("items").and_then(Value::as_array_mut),
    ) {
        oi.iter().zip(ai).for_each(|(o, a)| fill_b64(o, a, m));
        return;
    }
    let Some(field) = b64_field(orig) else { return };
    let (Some(om), Some(am)) = (
        orig.get(field).and_then(Value::as_object),
        anon.get_mut(field).and_then(Value::as_object_mut),
    ) else {
        return;
    };
    for (k, v) in om {
        if let Some(s) = v.as_str().filter(|s| is_b64(s)) {
            let nk = m.apply(&[field], k, Act::Key);
            am.insert(nk, Value::String(m.fake_b64(s)));
        }
    }
}

type Visit<'f> = dyn FnMut(&[&str], &str, Act) -> String + 'f;

/// Rebuild `v`, passing every string (values and free-form map keys) through
/// `f` with its field path and the `Act` for that field. `keep_vals` is set
/// by the parent when this is a `values`/`value` field of a
/// `{key, operator, values}` object whose key has public values.
fn walk<'a>(v: &'a Value, path: &mut Vec<&'a str>, keep_vals: bool, f: &mut Visit) -> Value {
    match v {
        Value::String(s) => {
            let last = path.last().copied().unwrap_or("");
            if SKIP_STR.contains(&last) || is_timestamp(s) {
                v.clone()
            } else {
                Value::String(f(path, s, act_for(path, keep_vals)))
            }
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| walk(x, path, keep_vals, f)).collect()),
        Value::Object(m) => {
            let last = path.last().copied().unwrap_or("");
            // `resources` is a quantity map on e.g. NodePool status but a
            // container-level wrapper (requests/limits) elsewhere.
            if QTY_MAPS.contains(&last)
                || (last == "resources" && m.values().all(|x| !x.is_object()))
            {
                return Value::Object(
                    m.iter()
                        .map(|(k, x)| (f(path, k, Act::Key), x.clone()))
                        .collect(),
                );
            }
            if let Some(&(_, label_like)) = FREEFORM.iter().find(|(n, _)| *n == last) {
                let mut out = Map::new();
                for (k, x) in m {
                    let nk = f(path, k, Act::Key);
                    let nv = match x {
                        Value::String(s)
                            if label_like && public_value_key(k) && !is_timestamp(s) =>
                        {
                            // real key in the path so --report shows which label
                            path.push(k);
                            let r = Value::String(f(path, s, Act::Keep));
                            path.pop();
                            r
                        }
                        _ => {
                            path.push("*");
                            let r = walk(x, path, false, f);
                            path.pop();
                            r
                        }
                    };
                    out.insert(nk, nv);
                }
                return Value::Object(out);
            }
            let pub_vals = m
                .get("key")
                .and_then(Value::as_str)
                .is_some_and(public_value_key);
            let mut out = Map::new();
            for (k, x) in m {
                path.push(k);
                let kv = pub_vals && (k == "values" || k == "value");
                out.insert(k.clone(), walk(x, path, kv, f));
                path.pop();
            }
            Value::Object(out)
        }
        _ => v.clone(),
    }
}

/// Run both passes over `docs` and return the anonymized copies.
fn anonymize(m: &mut Mapper, docs: &[Value]) -> Vec<Value> {
    // Base64 payloads are replaced wholesale, never tokenized: blank them
    // for the token passes, then fill in random same-length base64.
    let blanked: Vec<Value> = docs
        .iter()
        .map(|d| {
            let mut b = d.clone();
            blank_b64(&mut b);
            b
        })
        .collect();
    for d in &blanked {
        walk(d, &mut Vec::new(), false, &mut |_, s, _| {
            m.note(s);
            s.to_string()
        });
    }
    let mut anon: Vec<Value> = blanked
        .iter()
        .map(|d| walk(d, &mut Vec::new(), false, &mut |p, s, a| m.apply(p, s, a)))
        .collect();
    for (o, a) in docs.iter().zip(anon.iter_mut()) {
        fill_b64(o, a, m);
    }
    anon
}

fn parse_input(bytes: &[u8]) -> Result<Vec<Value>> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<Result<_, _>>()
        .context("parsing JSON")
}

fn serialize(docs: &[Value]) -> Result<String> {
    // kubectl emits 4-space indent; match it so byte sizes stay comparable.
    let mut out = Vec::new();
    for d in docs {
        let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
        serde::Serialize::serialize(d, &mut ser)?;
        out.push(b'\n');
    }
    Ok(String::from_utf8(out)?)
}

/// Leak scan over the serialized output. Returns human-readable problems.
fn check(anon: &[Value], m: &Mapper) -> Vec<String> {
    let mut problems = Vec::new();
    // Only strings the tool could have rewritten; schema field names (e.g.
    // `kernelVersion`) are expected to survive and would be false positives.
    let mut out_tokens: HashSet<String> = HashSet::new();
    let mut hits: HashSet<(String, String)> = HashSet::new();
    for d in anon {
        walk(d, &mut Vec::new(), false, &mut |p, s, _| {
            out_tokens.extend(runs(s).into_iter().filter(|r| r.0).map(|r| r.1.to_string()));
            let lower = s.to_ascii_lowercase();
            for d in m.deny.iter().filter(|d| lower.contains(d.as_str())) {
                hits.insert((d.clone(), p.join(".")));
            }
            s.to_string()
        });
    }
    let mut hits: Vec<_> = hits.into_iter().collect();
    hits.sort();
    for (d, path) in hits {
        problems.push(format!(
            "denylist substring {d:?} present in output at {path}"
        ));
    }
    for real in m.map.keys() {
        if out_tokens.contains(real) && !m.kept_tokens.contains(real) {
            problems.push(format!("rewritten token {real:?} still present in output"));
        }
    }
    problems
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut deny: Vec<String> = Vec::new();
    if let Some(p) = &cli.deny {
        deny.extend(word_list(&std::fs::read_to_string(p)?).map(|d| d.to_ascii_lowercase()));
    }

    let seed = cli.seed.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1)
    });

    let bytes = std::fs::read(&cli.input).with_context(|| format!("read {:?}", cli.input))?;
    let docs = parse_input(&bytes)?;
    let mut m = Mapper::new(seed, deny);
    let anon = anonymize(&mut m, &docs);
    let text = serialize(&anon)?;

    if let Some(dir) = cli.output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&cli.output, &text)?;

    eprintln!(
        "anonymize: {} -> {} ({} -> {} bytes), {} tokens rewritten, {} field values kept",
        cli.input.display(),
        cli.output.display(),
        bytes.len(),
        text.len(),
        m.map.len(),
        m.kept_paths.len()
    );

    if let Some(p) = &cli.mapping {
        let obj: Map<String, Value> = m
            .map
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        std::fs::write(p, serde_json::to_string_pretty(&obj)?)?;
        eprintln!(
            "anonymize: wrote mapping to {} (do not commit)",
            p.display()
        );
    }

    if cli.report {
        let mut kept: Vec<_> = m.kept_paths.iter().collect();
        kept.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (t, n) in kept {
            eprintln!("kept {n:>7} {t}");
        }
    }

    if cli.check {
        let problems = check(&anon, &m);
        if !problems.is_empty() {
            for p in &problems {
                eprintln!("CHECK FAILED: {p}");
            }
            bail!("{} leak check problem(s)", problems.len());
        }
        eprintln!("anonymize: leak check passed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapper(seed: u64) -> Mapper {
        Mapper::new(seed, vec!["acmecorp".into()])
    }

    fn run(m: &mut Mapper, s: &str) -> String {
        m.note(s);
        m.rewrite(s)
    }

    fn anon(v: &Value) -> (Value, Mapper) {
        let mut m = mapper(1);
        let out = anonymize(&mut m, std::slice::from_ref(v)).remove(0);
        (out, m)
    }

    fn j(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn preserves_length_and_separators() {
        let mut m = mapper(1);
        let s = "tenancy.acme.net/claim-name: Foo_Bar@x.io";
        let o = run(&mut m, s);
        assert_eq!(o.len(), s.len());
        for (a, b) in s.chars().zip(o.chars()) {
            if !a.is_ascii_alphanumeric() {
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn consistent_and_injective() {
        let mut m = mapper(2);
        let a = run(&mut m, "system:serviceaccount:payments:billing");
        let b = run(&mut m, "payments");
        assert!(a.starts_with("system:serviceaccount:"));
        assert_eq!(a.split(':').nth(2).unwrap(), b);
        let mut seen = HashSet::new();
        for i in 0..20_000 {
            let t = format!("tok{i}x");
            assert!(seen.insert(run(&mut m, &t)), "collision for {t}");
        }
    }

    #[test]
    fn deterministic_per_seed() {
        let s = "alpha-beta.gamma/delta";
        assert_eq!(run(&mut mapper(7), s), run(&mut mapper(7), s));
        assert_ne!(run(&mut mapper(7), s), run(&mut mapper(8), s));
    }

    #[test]
    fn denylist_overrides_keeps() {
        let mut m = mapper(3);
        assert_eq!(m.apply(&["operator"], "In", Act::Keep), "In");
        assert_ne!(m.apply(&["operator"], "AcmeCorp", Act::Keep), "AcmeCorp");
        assert!(
            !m.rewrite("myacmecorpthing")
                .to_lowercase()
                .contains("acmecorp")
        );
    }

    #[test]
    fn check_scans_values_not_schema_field_names() {
        let v = j(
            r#"{"kind":"Node","metadata":{"name":"n1","labels":{"team":"acmecorp-core"}},
            "status":{"nodeInfo":{"acmecorpVersion":"1.2.3"}}}"#,
        );
        let (out, m) = anon(&v);
        // the label value was rewritten, the schema key survives: no problems
        assert!(check(std::slice::from_ref(&out), &m).is_empty());
        // a surviving denied word in a value is reported with its path
        let mut bad = out.clone();
        bad["metadata"]["name"] = Value::String("x-acmecorp-y".into());
        let problems = check(std::slice::from_ref(&bad), &m);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("denylist") && p.contains("metadata.name")),
            "{problems:?}"
        );
    }

    #[test]
    fn reserved_and_builtin_names_kept_whole() {
        let mut m = mapper(4);
        for s in [
            "cluster-admin",
            "default",
            "kube-system",
            "eks:addon-manager",
            "system:kube-scheduler",
        ] {
            assert_eq!(m.apply(&["metadata", "name"], s, Act::Text), s);
        }
        assert_ne!(
            m.apply(&["metadata", "name"], "billing-api", Act::Text),
            "billing-api"
        );
        // quantity-ish and tiny tokens survive rewriting
        assert_eq!(run(&mut m, "500m 8080 ab"), "500m 8080 ab");
    }

    #[test]
    fn uuids_stay_hex_and_shaped() {
        let mut m = mapper(5);
        let u = "0a1b2c3d-1234-5678-9abc-def012345678";
        let o = run(&mut m, u);
        assert_eq!(o.len(), u.len());
        assert!(o.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()));
        assert_eq!(o, run(&mut m, u));
    }

    #[test]
    fn identity_fields_rewritten_structure_kept() {
        let v = j(r#"{"apiVersion":"v1","kind":"Pod",
            "metadata":{"name":"billing-api-0","namespace":"payments",
              "creationTimestamp":"2026-09-16T21:50:12Z","resourceVersion":"123456789",
              "labels":{"app.kubernetes.io/name":"billing","team":"payments"}},
            "spec":{"nodeName":"ip-10-1-2-3","serviceAccountName":"billing",
              "containers":[{"name":"main","image":"registry.acme.io/billing:v1.2"}]}}"#);
        let (o, _) = anon(&v);
        assert_eq!(o["apiVersion"], "v1");
        assert_eq!(o["kind"], "Pod");
        assert_eq!(
            o["metadata"]["creationTimestamp"],
            v["metadata"]["creationTimestamp"]
        );
        assert_eq!(o["metadata"]["resourceVersion"], "123456789");
        for p in [
            &o["metadata"]["name"],
            &o["metadata"]["namespace"],
            &o["spec"]["serviceAccountName"],
            &o["spec"]["containers"][0]["image"],
        ] {
            let s = p.as_str().unwrap();
            assert!(
                !["billing", "payments", "registry.acme.io"]
                    .iter()
                    .any(|w| s.contains(w)),
                "{s}"
            );
        }
        // public label key kept, its value and non-public keys rewritten
        let labels = o["metadata"]["labels"].as_object().unwrap();
        assert!(labels.contains_key("app.kubernetes.io/name"));
        assert_ne!(labels["app.kubernetes.io/name"], "billing");
        assert!(!labels.contains_key("team"));
        // joins: the SA name and the `billing` label value share a fake
        let sa = o["spec"]["serviceAccountName"].as_str().unwrap();
        assert_eq!(labels["app.kubernetes.io/name"], sa);
    }

    #[test]
    fn rbac_public_vocab_kept_custom_rewritten() {
        let v = j(r#"{"kind":"ClusterRole","metadata":{"name":"x"},
            "rules":[{"apiGroups":["","apps","compute.acme.io"],
                      "resources":["pods","pods/exec","widgets"],
                      "verbs":["get","impersonate","*"],
                      "resourceNames":["secret-thing"]}]}"#);
        let (o, _) = anon(&v);
        let r = &o["rules"][0];
        assert_eq!(r["apiGroups"][0], "");
        assert_eq!(r["apiGroups"][1], "apps");
        assert_ne!(r["apiGroups"][2], "compute.acme.io");
        assert_eq!(r["resources"][0], "pods");
        assert_eq!(r["resources"][1], "pods/exec");
        assert_ne!(r["resources"][2], "widgets");
        assert_eq!(r["verbs"], v["rules"][0]["verbs"]);
        assert_ne!(r["resourceNames"][0], "secret-thing");
    }

    #[test]
    fn scheduling_inputs_keep_public_values() {
        let v = j(r#"{"kind":"NodePool","metadata":{"name":"gpu-pool"},
            "spec":{"template":{"spec":{"requirements":[
              {"key":"node.kubernetes.io/instance-type","operator":"In","values":["p5.48xlarge"]},
              {"key":"acme.io/tier","operator":"In","values":["premium"]},
              {"key":"karpenter.sh/nodepool","operator":"In","values":["gpu-pool"]}]}}},
            "status":{"resources":{"cpu":"192","memory":"2097152Ki","acme.io/widget":"4","nvidia.com/gpu":"8"}}}"#);
        let (o, _) = anon(&v);
        let req = &o["spec"]["template"]["spec"]["requirements"];
        assert_eq!(req[0]["key"], "node.kubernetes.io/instance-type");
        assert_eq!(req[0]["operator"], "In");
        assert_eq!(req[0]["values"][0], "p5.48xlarge");
        assert_ne!(req[1]["key"], "acme.io/tier");
        assert_ne!(req[1]["values"][0], "premium");
        assert_eq!(req[2]["key"], "karpenter.sh/nodepool");
        assert_ne!(req[2]["values"][0], "gpu-pool");
        let res = o["status"]["resources"].as_object().unwrap();
        assert_eq!(res["cpu"], "192");
        assert_eq!(res["memory"], "2097152Ki");
        assert_eq!(res["nvidia.com/gpu"], "8");
        assert!(!res.contains_key("acme.io/widget"));
        assert_eq!(res.len(), 4);
    }

    #[test]
    fn node_selector_matches_node_label() {
        let node = j(r#"{"kind":"Node","metadata":{"name":"n1","labels":{
            "kubernetes.io/arch":"amd64","kubernetes.io/hostname":"n1","acme.io/pool":"blue"}},
            "status":{"allocatable":{"cpu":"32","memory":"131072Mi"}}}"#);
        let pod = j(r#"{"kind":"Pod","metadata":{"name":"p"},
            "spec":{"nodeSelector":{"kubernetes.io/arch":"amd64","acme.io/pool":"blue"}}}"#);
        let mut m = mapper(1);
        let out = anonymize(&mut m, &[node, pod]);
        let nl = out[0]["metadata"]["labels"].as_object().unwrap();
        let ns = out[1]["spec"]["nodeSelector"].as_object().unwrap();
        assert_eq!(nl["kubernetes.io/arch"], "amd64");
        let pool_key = nl.keys().find(|k| !k.starts_with("kubernetes.io")).unwrap();
        assert!(
            ns.contains_key(pool_key),
            "selector key must join node label key"
        );
        assert_eq!(
            ns[pool_key], nl[pool_key],
            "selector value must join node label value"
        );
        assert_eq!(out[0]["status"]["allocatable"]["cpu"], "32");
    }

    #[test]
    fn secret_data_becomes_same_length_random_base64() {
        // "hunter2-secret!" and a padded/unpadded pair
        let v = j(r#"{"kind":"List","items":[
              {"kind":"Secret","metadata":{"name":"creds"},
               "data":{"tls.crt":"aHVudGVyMi1zZWNyZXQh","pw":"c2VjcmV0cw==","dup":"aHVudGVyMi1zZWNyZXQh"}},
              {"kind":"ConfigMap","metadata":{"name":"cm"},
               "data":{"conf":"abcdefgh"},"binaryData":{"blob":"AAECAwQFBgc="}}]}"#);
        let (a, _) = anon(&v);

        let sec = &a["items"][0]["data"];
        let real = &v["items"][0]["data"];
        let (ok, ov) = (real.as_object().unwrap(), sec.as_object().unwrap());
        assert_eq!(ov.len(), 3);
        for ((rk, rv), (nk, nv)) in ok.iter().zip(ov) {
            assert_eq!(rk.len(), nk.len());
            if rk.len() > 2 {
                assert_ne!(rk, nk, "key {rk} not rewritten");
            }
            let (rv, nv) = (rv.as_str().unwrap(), nv.as_str().unwrap());
            assert_ne!(rv, nv);
            assert_eq!(rv.len(), nv.len());
            assert!(is_b64(nv));
            assert_eq!(rv.matches('=').count(), nv.matches('=').count());
        }
        let vals: Vec<_> = ov.values().collect();
        assert_eq!(vals[0], vals[2], "equal secrets must stay equal");
        assert_ne!(vals[0], vals[1]);

        // ConfigMap.data is plaintext (tokenized, not base64); binaryData is base64.
        let conf = a["items"][1]["data"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        assert_ne!(conf, "abcdefgh");
        assert_eq!(conf.as_str().unwrap().len(), 8);
        let bin = a["items"][1]["binaryData"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        assert_eq!(bin.as_str().unwrap().len(), 12);
        assert_ne!(bin, "AAECAwQFBgc=");
    }

    #[test]
    fn b64_encode_matches_known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }
}
