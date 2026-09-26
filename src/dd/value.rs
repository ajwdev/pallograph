// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serde-capable mirror types for `mangle_common::{Value, CompoundKind}`.
//!
//! # Why this exists
//!
//! Differential-dataflow's keyed operators (`join_map`, `antijoin`, `distinct`) require
//! their data types to implement `ExchangeData`, which bottoms out at
//! `serde::Serialize + for<'a> Deserialize<'a>`. `mangle_common::Value` is a foreign
//! type with no serde derives, so we mirror it here.
//!
//! # Parity contract
//!
//! `Val`'s `Eq`/`Hash`/`Ord` exactly replicate `Value`'s hand-written impls
//! (mangle-common/src/lib.rs:62-144). Any divergence would cause set-deduplication
//! mismatches between the interpreter and DD backends. The unit tests below verify
//! this directly.

use mangle_common::{CompoundKind, Value};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CompoundKindMirror
// ---------------------------------------------------------------------------

/// Mirror of `mangle_common::CompoundKind`. The original lacks serde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompoundKindMirror {
    List,
    Pair,
    Map,
    Struct,
}

impl From<CompoundKind> for CompoundKindMirror {
    fn from(k: CompoundKind) -> Self {
        match k {
            CompoundKind::List => CompoundKindMirror::List,
            CompoundKind::Pair => CompoundKindMirror::Pair,
            CompoundKind::Map => CompoundKindMirror::Map,
            CompoundKind::Struct => CompoundKindMirror::Struct,
        }
    }
}

impl From<CompoundKindMirror> for CompoundKind {
    fn from(k: CompoundKindMirror) -> Self {
        match k {
            CompoundKindMirror::List => CompoundKind::List,
            CompoundKindMirror::Pair => CompoundKind::Pair,
            CompoundKindMirror::Map => CompoundKind::Map,
            CompoundKindMirror::Struct => CompoundKind::Struct,
        }
    }
}

// ---------------------------------------------------------------------------
// OrdF64 — f64 with total-order semantics matching Value
// ---------------------------------------------------------------------------

/// `f64` wrapper with total-order `Eq`/`Hash`/`Ord` matching `Value`'s semantics:
/// - `Eq` / `Hash`: bit-identical (`to_bits()`). NaN == NaN; +0.0 != -0.0.
/// - `Ord`: `f64::total_cmp`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OrdF64(pub f64);

impl PartialEq for OrdF64 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}
impl Eq for OrdF64 {}

impl std::hash::Hash for OrdF64 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl PartialOrd for OrdF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

// ---------------------------------------------------------------------------
// Val — the per-element type flowing through DD collections
// ---------------------------------------------------------------------------

/// Serde-capable mirror of `mangle_common::Value`.
///
/// `Eq`/`Hash`/`Ord` are manually implemented to replicate `Value`'s exact semantics
/// including cross-numeric comparisons:
/// - `Number` ↔ `Float`: promote integer to float for comparison.
/// - `Duration` ↔ `Number`: compare as raw i64 nanoseconds.
/// - `Time` ↔ `Number`: compare as raw i64 nanoseconds.
/// - Cross-variant order: Number/Float < String < Name < Time < Duration < Compound < Null.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Val {
    Number(i64),
    Float(OrdF64),
    String(String),
    Name(String),
    Time(i64),
    Duration(i64),
    Compound(CompoundKindMirror, Vec<Val>),
    Null,
}

impl PartialEq for Val {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Val::Number(a), Val::Number(b)) => a == b,
            (Val::Float(a), Val::Float(b)) => a == b,
            (Val::String(a), Val::String(b)) => a == b,
            (Val::Name(a), Val::Name(b)) => a == b,
            (Val::Time(a), Val::Time(b)) => a == b,
            (Val::Duration(a), Val::Duration(b)) => a == b,
            (Val::Compound(ka, a), Val::Compound(kb, b)) => ka == kb && a == b,
            (Val::Null, Val::Null) => true,
            _ => false,
        }
    }
}

impl Eq for Val {}

impl std::hash::Hash for Val {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Val::Number(n) => n.hash(state),
            Val::Float(f) => f.hash(state),
            Val::String(s) => s.hash(state),
            Val::Name(s) => s.hash(state),
            Val::Time(t) => t.hash(state),
            Val::Duration(d) => d.hash(state),
            Val::Compound(k, v) => {
                k.hash(state);
                v.hash(state);
            }
            Val::Null => {}
        }
    }
}

impl PartialOrd for Val {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Val {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Val::Number(a), Val::Number(b)) => a.cmp(b),
            (Val::Float(a), Val::Float(b)) => a.cmp(b),
            // Cross-numeric: promote integer to float for comparison.
            (Val::Number(a), Val::Float(b)) => (*a as f64).total_cmp(&b.0),
            (Val::Float(a), Val::Number(b)) => a.0.total_cmp(&(*b as f64)),
            (Val::String(a), Val::String(b)) => a.cmp(b),
            (Val::Name(a), Val::Name(b)) => a.cmp(b),
            (Val::Time(a), Val::Time(b)) => a.cmp(b),
            (Val::Duration(a), Val::Duration(b)) => a.cmp(b),
            // Cross-type: Duration vs Number compare as raw i64 nanoseconds.
            (Val::Duration(a), Val::Number(b)) => a.cmp(b),
            (Val::Number(a), Val::Duration(b)) => a.cmp(b),
            // Cross-type: Time vs Number compare as raw i64 nanoseconds.
            (Val::Time(a), Val::Number(b)) => a.cmp(b),
            (Val::Number(a), Val::Time(b)) => a.cmp(b),
            (Val::Compound(ka, a), Val::Compound(kb, b)) => {
                ka.cmp(kb).then_with(|| a.cmp(b))
            }
            (Val::Null, Val::Null) => std::cmp::Ordering::Equal,
            // Cross-variant ordering: Number/Float < String < Name < Time < Duration < Compound < Null
            (Val::Number(_) | Val::Float(_), _) => std::cmp::Ordering::Less,
            (_, Val::Number(_) | Val::Float(_)) => std::cmp::Ordering::Greater,
            (Val::String(_), _) => std::cmp::Ordering::Less,
            (_, Val::String(_)) => std::cmp::Ordering::Greater,
            (Val::Name(_), _) => std::cmp::Ordering::Less,
            (_, Val::Name(_)) => std::cmp::Ordering::Greater,
            (Val::Time(_), _) => std::cmp::Ordering::Less,
            (_, Val::Time(_)) => std::cmp::Ordering::Greater,
            (Val::Duration(_), _) => std::cmp::Ordering::Less,
            (_, Val::Duration(_)) => std::cmp::Ordering::Greater,
            (Val::Compound(..), _) => std::cmp::Ordering::Less,
            (_, Val::Compound(..)) => std::cmp::Ordering::Greater,
        }
    }
}

impl From<&Value> for Val {
    fn from(v: &Value) -> Self {
        match v {
            Value::Number(n) => Val::Number(*n),
            Value::Float(f) => Val::Float(OrdF64(*f)),
            Value::String(s) => Val::String(s.clone()),
            Value::Name(s) => Val::Name(s.clone()),
            Value::Time(t) => Val::Time(*t),
            Value::Duration(d) => Val::Duration(*d),
            Value::Compound(k, elems) => Val::Compound(
                CompoundKindMirror::from(*k),
                elems.iter().map(Val::from).collect(),
            ),
            Value::Null => Val::Null,
        }
    }
}

impl From<Val> for Value {
    fn from(v: Val) -> Self {
        match v {
            Val::Number(n) => Value::Number(n),
            Val::Float(OrdF64(f)) => Value::Float(f),
            Val::String(s) => Value::String(s),
            Val::Name(s) => Value::Name(s),
            Val::Time(t) => Value::Time(t),
            Val::Duration(d) => Value::Duration(d),
            Val::Compound(k, elems) => {
                Value::Compound(CompoundKind::from(k), elems.into_iter().map(Value::from).collect())
            }
            Val::Null => Value::Null,
        }
    }
}

// ---------------------------------------------------------------------------
// Row — a whole tuple, the DD collection element type D
// ---------------------------------------------------------------------------

/// A tuple of `Val`s — the data type `D` flowing through DD collections.
///
/// Derives all the traits DD needs, including `Serialize`/`Deserialize` for
/// `ExchangeData`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Row(pub Vec<Val>);

impl Row {
    pub fn into_values(self) -> Vec<Value> {
        self.0.into_iter().map(Value::from).collect()
    }
}

impl From<&[Value]> for Row {
    fn from(tuple: &[Value]) -> Self {
        Row(tuple.iter().map(Val::from).collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: Value) -> Value {
        Value::from(Val::from(&v))
    }

    #[test]
    fn round_trip_scalars() {
        assert_eq!(round_trip(Value::Number(42)), Value::Number(42));
        assert_eq!(round_trip(Value::Float(3.14)), Value::Float(3.14));
        assert_eq!(round_trip(Value::String("hello".into())), Value::String("hello".into()));
        assert_eq!(round_trip(Value::Name("/foo/bar".into())), Value::Name("/foo/bar".into()));
        assert_eq!(round_trip(Value::Time(1_000_000)), Value::Time(1_000_000));
        assert_eq!(round_trip(Value::Duration(500)), Value::Duration(500));
        assert_eq!(round_trip(Value::Null), Value::Null);
    }

    #[test]
    fn round_trip_compound() {
        let v = Value::Compound(
            CompoundKind::List,
            vec![Value::Number(1), Value::String("x".into())],
        );
        assert_eq!(round_trip(v.clone()), v);
    }

    /// Float Eq parity: NaN == NaN (via to_bits); +0.0 != -0.0.
    #[test]
    fn float_eq_parity() {
        let nan_v = Val::Float(OrdF64(f64::NAN));
        assert_eq!(nan_v, nan_v.clone());

        let pos_zero = Val::Float(OrdF64(0.0_f64));
        let neg_zero = Val::Float(OrdF64(-0.0_f64));
        assert_ne!(pos_zero, neg_zero);

        // Verify parity with Value's own behavior.
        assert_eq!(
            Value::Float(f64::NAN) == Value::Float(f64::NAN),
            nan_v == nan_v.clone()
        );
        assert_eq!(
            Value::Float(0.0) == Value::Float(-0.0),
            pos_zero == neg_zero
        );
    }

    /// Ord parity: Val::cmp must match Value::cmp for all cross-type cases.
    #[test]
    fn ord_parity() {
        let cases: &[(Value, Value)] = &[
            (Value::Number(1), Value::Number(2)),
            (Value::Float(1.5), Value::Float(2.5)),
            (Value::Number(1), Value::Float(1.5)),
            (Value::Number(2), Value::Float(1.5)),
            (Value::String("a".into()), Value::String("b".into())),
            // Cross-variant ordering
            (Value::Number(0), Value::String("x".into())),
            (Value::String("x".into()), Value::Name("/a".into())),
            (Value::Name("/a".into()), Value::Time(100)),
            (Value::Time(100), Value::Duration(100)),
            (Value::Duration(100), Value::Compound(CompoundKind::List, vec![])),
            (Value::Compound(CompoundKind::List, vec![]), Value::Null),
            // Duration/Time vs Number
            (Value::Duration(5), Value::Number(10)),
            (Value::Number(5), Value::Time(10)),
        ];
        for (a, b) in cases {
            let va = Val::from(a);
            let vb = Val::from(b);
            assert_eq!(
                a.cmp(b),
                va.cmp(&vb),
                "Ord mismatch: {:?} vs {:?}",
                a,
                b
            );
        }
    }

    /// Hash parity: bit-based float hashing.
    #[test]
    fn float_hash_parity() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn h(v: &Val) -> u64 {
            let mut s = DefaultHasher::new();
            v.hash(&mut s);
            s.finish()
        }

        let nan1 = Val::Float(OrdF64(f64::NAN));
        let nan2 = Val::Float(OrdF64(f64::NAN));
        assert_eq!(h(&nan1), h(&nan2));

        let pz = Val::Float(OrdF64(0.0));
        let nz = Val::Float(OrdF64(-0.0));
        assert_ne!(h(&pz), h(&nz));
    }
}
