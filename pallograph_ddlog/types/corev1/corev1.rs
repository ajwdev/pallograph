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


pub static __STATIC_1: ::once_cell::sync::Lazy<ddlog_std::Map<String, String>> = ::once_cell::sync::Lazy::new(|| ddlog_std::map_empty());
pub static __STATIC_6: ::once_cell::sync::Lazy<ddlog_std::Ref<Pods2>> = ::once_cell::sync::Lazy::new(|| ddlog_std::ref_new((Pods2{meta: (types__metav1::ObjectMeta{namespace: (*(&*crate::__STATIC_0)).clone(), name: (*(&*crate::__STATIC_0)).clone(), labels: {
                                                                                                                                                                                                                                                                    let ref mut __map: ddlog_std::Map<String, String> = (*(&*crate::__STATIC_1)).clone();
                                                                                                                                                                                                                                                                    ddlog_std::insert_ddlog_std_Map__K_V_K_V___Tuple0__::<String, String>(__map, (*(&*crate::__STATIC_2)).clone(), (*(&*crate::__STATIC_3)).clone());
                                                                                                                                                                                                                                                                    ddlog_std::insert_ddlog_std_Map__K_V_K_V___Tuple0__::<String, String>(__map, (*(&*crate::__STATIC_4)).clone(), (*(&*crate::__STATIC_0)).clone());
                                                                                                                                                                                                                                                                    (*__map).clone()
                                                                                                                                                                                                                                                                }, annotations: (*(&*crate::__STATIC_1)).clone()}), spec: (PodSpec{nodeName: (*(&*crate::__STATIC_5)).clone()}), status: (PodStatus{phase: (Phase::Running{})})})));
pub static __STATIC_7: ::once_cell::sync::Lazy<ddlog_std::Vec<ddlog_std::Ref<types__selectors::LabelSelectorRequirement>>> = ::once_cell::sync::Lazy::new(|| ddlog_std::vec_empty());
pub static __STATIC_4: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"app"###));
pub static __STATIC_3: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"bar"###));
pub static __STATIC_2: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"foo"###));
pub static __STATIC_0: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"test"###));
pub static __STATIC_5: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"test-1"###));
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::Phase")]
pub enum Phase {
    #[ddlog(rename = "corev1::Running")]
    Running,
    #[ddlog(rename = "corev1::Pending")]
    Pending,
    #[ddlog(rename = "corev1::Failed")]
    Failed,
    #[ddlog(rename = "corev1::Succeeded")]
    Succeeded,
    #[ddlog(rename = "corev1::Unknown")]
    Unknown
}
impl abomonation::Abomonation for Phase{}
impl ::std::fmt::Display for Phase {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Phase::Running{} => {
                __formatter.write_str("corev1::Running{")?;
                __formatter.write_str("}")
            },
            Phase::Pending{} => {
                __formatter.write_str("corev1::Pending{")?;
                __formatter.write_str("}")
            },
            Phase::Failed{} => {
                __formatter.write_str("corev1::Failed{")?;
                __formatter.write_str("}")
            },
            Phase::Succeeded{} => {
                __formatter.write_str("corev1::Succeeded{")?;
                __formatter.write_str("}")
            },
            Phase::Unknown{} => {
                __formatter.write_str("corev1::Unknown{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Phase {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
impl ::std::default::Default for Phase {
    fn default() -> Self {
        Phase::Running{}
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::PodSpec")]
pub struct PodSpec {
    pub nodeName: String
}
impl abomonation::Abomonation for PodSpec{}
impl ::std::fmt::Display for PodSpec {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PodSpec{nodeName} => {
                __formatter.write_str("corev1::PodSpec{")?;
                differential_datalog::record::format_ddlog_str(nodeName, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for PodSpec {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::PodStatus")]
pub struct PodStatus {
    pub phase: Phase
}
impl abomonation::Abomonation for PodStatus{}
impl ::std::fmt::Display for PodStatus {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PodStatus{phase} => {
                __formatter.write_str("corev1::PodStatus{")?;
                ::std::fmt::Debug::fmt(phase, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for PodStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::Pods2")]
pub struct Pods2 {
    pub meta: types__metav1::ObjectMeta,
    pub spec: PodSpec,
    pub status: PodStatus
}
impl abomonation::Abomonation for Pods2{}
impl ::std::fmt::Display for Pods2 {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Pods2{meta,spec,status} => {
                __formatter.write_str("corev1::Pods2{")?;
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
impl ::std::fmt::Debug for Pods2 {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::Pods2Dump")]
pub struct Pods2Dump {
    pub pod: ddlog_std::Ref<Pods2>
}
impl abomonation::Abomonation for Pods2Dump{}
impl ::std::fmt::Display for Pods2Dump {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Pods2Dump{pod} => {
                __formatter.write_str("corev1::Pods2Dump{")?;
                ::std::fmt::Debug::fmt(pod, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Pods2Dump {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::Pods2Label")]
pub struct Pods2Label {
    pub selector: types__selectors::LabelSelector,
    pub pod: ddlog_std::Ref<Pods2>
}
impl abomonation::Abomonation for Pods2Label{}
impl ::std::fmt::Display for Pods2Label {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Pods2Label{selector,pod} => {
                __formatter.write_str("corev1::Pods2Label{")?;
                ::std::fmt::Debug::fmt(selector, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(pod, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Pods2Label {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::TemplateSelectors")]
pub struct TemplateSelectors {
    pub s: types__selectors::LabelSelector
}
impl abomonation::Abomonation for TemplateSelectors{}
impl ::std::fmt::Display for TemplateSelectors {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            TemplateSelectors{s} => {
                __formatter.write_str("corev1::TemplateSelectors{")?;
                ::std::fmt::Debug::fmt(s, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for TemplateSelectors {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
pub fn __Key_corev1_Pods2(__key: &::differential_datalog::ddval::DDValue) -> ::differential_datalog::ddval::DDValue {
    let ref x = *unsafe {<ddlog_std::Ref<Pods2>>::from_ddvalue_ref_unchecked(__key) };
    (ddlog_std::tuple2(x.meta.namespace.clone(), x.meta.name.clone())).into_ddvalue()
}
pub static __Arng_corev1_Pods2_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <ddlog_std::Ref<Pods2>>::from_ddvalue_unchecked(__v) } {
                _ => Some((()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_corev1_TemplateSelectors_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <TemplateSelectors>::from_ddvalue_unchecked(__v) } {
                TemplateSelectors{s: _} => Some((()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Rule_corev1_Pods2Dump_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* corev1::Pods2Dump[(corev1::Pods2Dump{.pod=pod}: corev1::Pods2Dump)] :- corev1::Pods2[(pod: ddlog_std::Ref<corev1::Pods2>)]. */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 37, 1, 38, 1)),
        rel: 11,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 37, 1, 37, 16)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let ref pod = match *unsafe { <ddlog_std::Ref<Pods2>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref pod => (*pod).clone(),
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    Some(((Pods2Dump{pod: (*pod).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});
pub static __Rule_corev1_Pods2Label_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* corev1::Pods2Label[(corev1::Pods2Label{.selector=selector, .pod=pod}: corev1::Pods2Label)] :- corev1::TemplateSelectors[(corev1::TemplateSelectors{.s=(selector: selectors::LabelSelector)}: corev1::TemplateSelectors)], corev1::Pods2[(pod: ddlog_std::Ref<corev1::Pods2>)], (selectors::labelSelectorMatches((ddlog_std::Some{.x=((ddlog_std::ref_new: function(selectors::LabelSelector):ddlog_std::Ref<selectors::LabelSelector>)(selector))}: ddlog_std::Option<ddlog_std::Ref<selectors::LabelSelector>>), ((pod.meta).labels))). */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 31, 1, 36, 1)),
        arr: (14, 0),
        xform: XFormArrangement::Join {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("corev1::Pods2"), ::std::borrow::Cow::Borrowed("(_: ddlog_std::Ref<corev1::Pods2>)"), ::ddlog_profiler::SourcePosition::new_range("corev1.dl", 33, 3, 33, 13)),
                   ffun: None,
                   arrangement: (11,0),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let ref selector = match *unsafe { <TemplateSelectors>::from_ddvalue_ref_unchecked(__v1) } {
                           TemplateSelectors{s: ref selector} => (*selector).clone(),
                           _ => return ::std::option::Option::None
                       };
                       let ref pod = match *unsafe { <ddlog_std::Ref<Pods2>>::from_ddvalue_ref_unchecked(__v2) } {
                           ref pod => (*pod).clone(),
                           _ => return ::std::option::Option::None
                       };
                       if !types__selectors::labelSelectorMatches((&(ddlog_std::Option::Some{x: ddlog_std::ref_new((*selector).clone())})), (&pod.meta.labels)) {return None;};
                       ::std::option::Option::Some(((Pods2Label{selector: (*selector).clone(), pod: (*pod).clone()})).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::std::option::Option::None)
               },
    }
});
pub static __Fact_corev1_Pods2_0 : ::once_cell::sync::Lazy<(program::RelId, ::differential_datalog::ddval::DDValue)> = ::once_cell::sync::Lazy::new(|| {
    (11, ((*(&*crate::__STATIC_6)).clone()).into_ddvalue()) /*corev1::Pods2[((ddlog_std::ref_new: function(corev1::Pods2):ddlog_std::Ref<corev1::Pods2>)((corev1::Pods2{.meta=(metav1::ObjectMeta{.namespace="test", .name="test", .labels={((var __map: ddlog_std::Map<string,string>) = ((ddlog_std::map_empty: function():ddlog_std::Map<string,string>)()));
                                                                                                                                                                                                                                            {((ddlog_std::insert: function(mut ddlog_std::Map<string,string>, string, string):())(__map, "foo", "bar"));
                                                                                                                                                                                                                                             {((ddlog_std::insert: function(mut ddlog_std::Map<string,string>, string, string):())(__map, "app", "test"));
                                                                                                                                                                                                                                              __map}}}, .annotations=((ddlog_std::map_empty: function():ddlog_std::Map<string,string>)())}: metav1::ObjectMeta), .spec=(corev1::PodSpec{.nodeName="test-1"}: corev1::PodSpec), .status=(corev1::PodStatus{.phase=(corev1::Running{}: corev1::Phase)}: corev1::PodStatus)}: corev1::Pods2)))].*/
});
pub static __Fact_corev1_TemplateSelectors_0 : ::once_cell::sync::Lazy<(program::RelId, ::differential_datalog::ddval::DDValue)> = ::once_cell::sync::Lazy::new(|| {
    (14, ((TemplateSelectors{s: (types__selectors::LabelSelector{matchLabels: {
                                                                                  let ref mut __map: ddlog_std::Map<String, String> = (*(&*crate::__STATIC_1)).clone();
                                                                                  ddlog_std::insert_ddlog_std_Map__K_V_K_V___Tuple0__::<String, String>(__map, (*(&*crate::__STATIC_4)).clone(), (*(&*crate::__STATIC_0)).clone());
                                                                                  ddlog_std::insert_ddlog_std_Map__K_V_K_V___Tuple0__::<String, String>(__map, (*(&*crate::__STATIC_2)).clone(), (*(&*crate::__STATIC_3)).clone());
                                                                                  (*__map).clone()
                                                                              }, matchExpressions: (*(&*crate::__STATIC_7)).clone()})})).into_ddvalue()) /*corev1::TemplateSelectors[(corev1::TemplateSelectors{.s=(selectors::LabelSelector{.matchLabels={((var __map: ddlog_std::Map<string,string>) = ((ddlog_std::map_empty: function():ddlog_std::Map<string,string>)()));
                                                                                                                                                                                                                                                           {((ddlog_std::insert: function(mut ddlog_std::Map<string,string>, string, string):())(__map, "app", "test"));
                                                                                                                                                                                                                                                            {((ddlog_std::insert: function(mut ddlog_std::Map<string,string>, string, string):())(__map, "foo", "bar"));
                                                                                                                                                                                                                                                             __map}}}, .matchExpressions=((ddlog_std::vec_empty: function():ddlog_std::Vec<ddlog_std::Ref<selectors::LabelSelectorRequirement>>)())}: selectors::LabelSelector)}: corev1::TemplateSelectors)].*/
});