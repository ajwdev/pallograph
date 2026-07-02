//! Integration test exercising cel-z3 the way a consumer (e.g. pallograph) will:
//! through the public re-exports only. Demonstrates the motivating shape -
//! "does a VAP's validations guarantee an invariant?" - reduced to the
//! generic `implies` primitive, with a counterexample when it does not.

use cel_z3::{Analyzer, CelType, Env, ModelValue};
use z3::{Config, Context};

/// A VAP that caps replicas at 10 does NOT guarantee the stronger invariant
/// "replicas <= 5"; cel-z3 should find a counterexample.
#[test]
fn vap_does_not_imply_stronger_invariant() {
    let ctx = Context::new(&Config::new());
    let mut env = Env::new();
    env.declare("object.spec.replicas", CelType::Int);
    let analyzer = Analyzer::new(&ctx, &env);

    let vap = analyzer.translate("object.spec.replicas <= 10").unwrap();
    let invariant = analyzer.translate("object.spec.replicas <= 5").unwrap();

    // The VAP does not imply the stronger invariant.
    assert!(!analyzer.implies(&vap, &invariant));

    // A counterexample admitted by the VAP but violating the invariant:
    // some replicas value with 5 < replicas <= 10.
    let gap = analyzer
        .translate("object.spec.replicas <= 10 && object.spec.replicas > 5")
        .unwrap();
    let model = analyzer.model_for(&gap).expect("counterexample exists");
    match model.get("object.spec.replicas") {
        Some(ModelValue::Int(v)) => assert!(*v > 5 && *v <= 10, "got replicas={v}"),
        other => panic!("expected Int replicas, got {other:?}"),
    }
}

/// A VAP that caps replicas at 5 DOES guarantee the invariant "replicas <= 10".
#[test]
fn stricter_vap_implies_invariant() {
    let ctx = Context::new(&Config::new());
    let mut env = Env::new();
    env.declare("object.spec.replicas", CelType::Int);
    let analyzer = Analyzer::new(&ctx, &env);

    let vap = analyzer.translate("object.spec.replicas <= 5").unwrap();
    let invariant = analyzer.translate("object.spec.replicas <= 10").unwrap();

    assert!(analyzer.implies(&vap, &invariant));
}
