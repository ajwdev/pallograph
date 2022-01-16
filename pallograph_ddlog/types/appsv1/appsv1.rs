#![allow(
    path_statements,
    unused_imports,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    unused_parens,
    non_shorthand_field_patterns,
    dead_code,
    overflowing_literals,
    unreachable_patterns,
    unused_variables,
    clippy::missing_safety_doc,
    clippy::match_single_binding,
    clippy::ptr_arg,
    clippy::redundant_closure,
    clippy::needless_lifetimes,
    clippy::borrowed_box,
    clippy::map_clone,
    clippy::toplevel_ref_arg,
    clippy::double_parens,
    clippy::collapsible_if,
    clippy::clone_on_copy,
    clippy::unused_unit,
    clippy::deref_addrof,
    clippy::clone_on_copy,
    clippy::needless_return,
    clippy::op_ref,
    clippy::match_like_matches_macro,
    clippy::comparison_chain,
    clippy::len_zero,
    clippy::extra_unused_lifetimes
)]

use ::num::One;
use ::std::ops::Deref;

use ::differential_dataflow::collection;
use ::timely::communication;
use ::timely::dataflow::scopes;
use ::timely::worker;

use ::ddlog_derive::{FromRecord, IntoRecord, Mutator};
use ::differential_datalog::ddval::DDValConvert;
use ::differential_datalog::program;
use ::differential_datalog::program::TupleTS;
use ::differential_datalog::program::XFormArrangement;
use ::differential_datalog::program::XFormCollection;
use ::differential_datalog::program::Weight;
use ::differential_datalog::record::FromRecord;
use ::differential_datalog::record::FromRecordInner;
use ::differential_datalog::record::IntoRecord;
use ::differential_datalog::record::Mutator;
use ::differential_datalog::record::MutatorInner;
use ::serde::Deserialize;
use ::serde::Serialize;


// `usize` and `isize` are builtin Rust types; we therefore declare an alias to DDlog's `usize` and
// `isize`.
pub type std_usize = u64;
pub type std_isize = i64;


#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "appsv1::ReplicaSet")]
pub struct ReplicaSet {
    pub meta: types__metav1::ObjectMeta,
    pub spec: ReplicaSetSpec,
    pub status: ReplicaSetStatus
}
impl abomonation::Abomonation for ReplicaSet{}
impl ::std::fmt::Display for ReplicaSet {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReplicaSet{meta,spec,status} => {
                __formatter.write_str("appsv1::ReplicaSet{")?;
                ::std::fmt::Debug::fmt(meta, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(spec, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(status, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ReplicaSet {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "appsv1::ReplicaSetByName")]
pub struct ReplicaSetByName {
    pub rs: ddlog_std::Ref<ReplicaSet>,
    pub ns: String,
    pub name: String
}
impl abomonation::Abomonation for ReplicaSetByName{}
impl ::std::fmt::Display for ReplicaSetByName {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReplicaSetByName{rs,ns,name} => {
                __formatter.write_str("appsv1::ReplicaSetByName{")?;
                ::std::fmt::Debug::fmt(rs, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(ns, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ReplicaSetByName {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "appsv1::ReplicaSetMatchesPod")]
pub struct ReplicaSetMatchesPod {
    pub rs: ddlog_std::Ref<ReplicaSet>,
    pub pod: ddlog_std::Ref<types__corev1::Pod>
}
impl abomonation::Abomonation for ReplicaSetMatchesPod{}
impl ::std::fmt::Display for ReplicaSetMatchesPod {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReplicaSetMatchesPod{rs,pod} => {
                __formatter.write_str("appsv1::ReplicaSetMatchesPod{")?;
                ::std::fmt::Debug::fmt(rs, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(pod, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ReplicaSetMatchesPod {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "appsv1::ReplicaSetSpec")]
pub struct ReplicaSetSpec {
    pub selector: types__selectors::LabelSelector
}
impl abomonation::Abomonation for ReplicaSetSpec{}
impl ::std::fmt::Display for ReplicaSetSpec {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReplicaSetSpec{selector} => {
                __formatter.write_str("appsv1::ReplicaSetSpec{")?;
                ::std::fmt::Debug::fmt(selector, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ReplicaSetSpec {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "appsv1::ReplicaSetStatus")]
pub struct ReplicaSetStatus {
}
impl abomonation::Abomonation for ReplicaSetStatus{}
impl ::std::fmt::Display for ReplicaSetStatus {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReplicaSetStatus{} => {
                __formatter.write_str("appsv1::ReplicaSetStatus{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ReplicaSetStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
pub fn __Key_appsv1_ReplicaSet(__key: &::differential_datalog::ddval::DDValue) -> ::differential_datalog::ddval::DDValue {
    let ref x = *unsafe {<ddlog_std::Ref<ReplicaSet>>::from_ddvalue_ref_unchecked(__key) };
    (ddlog_std::tuple2(x.meta.namespace.clone(), x.meta.name.clone())).into_ddvalue()
}
pub static __Arng_appsv1_ReplicaSetByName_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <ReplicaSetByName>::from_ddvalue_unchecked(__v) } {
                ReplicaSetByName{rs: _, ns: ref _0, name: _} => Some(((*_0).clone()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Rule_appsv1_ReplicaSetByName_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* appsv1::ReplicaSetByName[(appsv1::ReplicaSetByName{.rs=rs, .ns=ns, .name=name}: appsv1::ReplicaSetByName)] :- appsv1::ReplicaSet[(rs@ ((&(appsv1::ReplicaSet{.meta=(_: metav1::ObjectMeta), .spec=(_: appsv1::ReplicaSetSpec), .status=(_: appsv1::ReplicaSetStatus)}: appsv1::ReplicaSet)): ddlog_std::Ref<appsv1::ReplicaSet>))], ((var ns: string) = ((rs.meta).namespace)), ((var name: string) = ((rs.meta).name)). */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("appsv1.dl", 15, 1, 20, 1)),
        rel: 3,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("appsv1.dl", 15, 1, 15, 32)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let ref rs = match *unsafe { <ddlog_std::Ref<ReplicaSet>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref rs => match rs {
                                                                      ref _0_ => match ((*_0_)).deref() {
                                                                                     ReplicaSet{meta: _, spec: _, status: _} => (*rs).clone(),
                                                                                     _ => return ::core::option::Option::None
                                                                                 },
                                                                      _ => return ::core::option::Option::None
                                                                  },
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    let ref ns: String = match rs.meta.namespace.clone() {
                                                        ns => ns,
                                                        _ => return None
                                                    };
                                                    let ref name: String = match rs.meta.name.clone() {
                                                        name => name,
                                                        _ => return None
                                                    };
                                                    Some(((ReplicaSetByName{rs: (*rs).clone(), ns: (*ns).clone(), name: (*name).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});
pub static __Rule_appsv1_ReplicaSetMatchesPod_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* appsv1::ReplicaSetMatchesPod[(appsv1::ReplicaSetMatchesPod{.rs=rs, .pod=pod}: appsv1::ReplicaSetMatchesPod)] :- appsv1::ReplicaSetByName[(appsv1::ReplicaSetByName{.rs=(rs: ddlog_std::Ref<appsv1::ReplicaSet>), .ns=(ns: string), .name=(_: string)}: appsv1::ReplicaSetByName)], corev1::PodByName[(corev1::PodByName{.pod=(pod: ddlog_std::Ref<corev1::Pod>), .ns=(ns: string), .name=(_: string)}: corev1::PodByName)], (selectors::labelSelectorMatches((ddlog_std::Some{.x=((ddlog_std::ref_new: function(selectors::LabelSelector):ddlog_std::Ref<selectors::LabelSelector>)(((rs.spec).selector)))}: ddlog_std::Option<ddlog_std::Ref<selectors::LabelSelector>>), ((pod.meta).labels))). */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("appsv1.dl", 21, 1, 25, 1)),
        arr: (4, 0),
        xform: XFormArrangement::Join {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("corev1::PodByName"), ::std::borrow::Cow::Borrowed("(corev1::PodByName{.pod=(_: ddlog_std::Ref<corev1::Pod>), .ns=(_0: string), .name=(_: string)}: corev1::PodByName)"), ::ddlog_profiler::SourcePosition::new_range("appsv1.dl", 23, 3, 23, 24)),
                   ffun: None,
                   arrangement: (8,0),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let (ref rs, ref ns) = match *unsafe { <ReplicaSetByName>::from_ddvalue_ref_unchecked(__v1) } {
                           ReplicaSetByName{rs: ref rs, ns: ref ns, name: _} => ((*rs).clone(), (*ns).clone()),
                           _ => return ::std::option::Option::None
                       };
                       let ref pod = match *unsafe { <types__corev1::PodByName>::from_ddvalue_ref_unchecked(__v2) } {
                           types__corev1::PodByName{pod: ref pod, ns: _, name: _} => (*pod).clone(),
                           _ => return ::std::option::Option::None
                       };
                       if !types__selectors::labelSelectorMatches((&(ddlog_std::Option::Some{x: ddlog_std::ref_new(rs.spec.selector.clone())})), (&pod.meta.labels)) {return None;};
                       ::std::option::Option::Some(((ReplicaSetMatchesPod{rs: (*rs).clone(), pod: (*pod).clone()})).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::std::option::Option::None)
               },
    }
});