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


pub static __STATIC_0: ::once_cell::sync::Lazy<ddlog_std::Map<String, String>> = ::once_cell::sync::Lazy::new(|| ddlog_std::map_empty());
pub static __STATIC_1: ::once_cell::sync::Lazy<ddlog_std::Vec<ddlog_std::Ref<types__selectors::LabelSelectorRequirement>>> = ::once_cell::sync::Lazy::new(|| ddlog_std::vec_empty());
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::MatchesPod")]
pub struct MatchesPod {
    pub selector: types__selectors::LabelSelector,
    pub namespace: String,
    pub pod: ddlog_std::Ref<Pod>
}
impl abomonation::Abomonation for MatchesPod{}
impl ::std::fmt::Display for MatchesPod {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            MatchesPod{selector,namespace,pod} => {
                __formatter.write_str("corev1::MatchesPod{")?;
                ::std::fmt::Debug::fmt(selector, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(pod, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for MatchesPod {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::Pod")]
pub struct Pod {
    pub meta: types__metav1::ObjectMeta,
    pub spec: PodSpec,
    pub status: PodStatus
}
impl abomonation::Abomonation for Pod{}
impl ::std::fmt::Display for Pod {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Pod{meta,spec,status} => {
                __formatter.write_str("corev1::Pod{")?;
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
impl ::std::fmt::Debug for Pod {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::PodByName")]
pub struct PodByName {
    pub pod: ddlog_std::Ref<Pod>,
    pub ns: String,
    pub name: String
}
impl abomonation::Abomonation for PodByName{}
impl ::std::fmt::Display for PodByName {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PodByName{pod,ns,name} => {
                __formatter.write_str("corev1::PodByName{")?;
                ::std::fmt::Debug::fmt(pod, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(ns, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for PodByName {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::PodPhase")]
pub enum PodPhase {
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
impl abomonation::Abomonation for PodPhase{}
impl ::std::fmt::Display for PodPhase {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PodPhase::Running{} => {
                __formatter.write_str("corev1::Running{")?;
                __formatter.write_str("}")
            },
            PodPhase::Pending{} => {
                __formatter.write_str("corev1::Pending{")?;
                __formatter.write_str("}")
            },
            PodPhase::Failed{} => {
                __formatter.write_str("corev1::Failed{")?;
                __formatter.write_str("}")
            },
            PodPhase::Succeeded{} => {
                __formatter.write_str("corev1::Succeeded{")?;
                __formatter.write_str("}")
            },
            PodPhase::Unknown{} => {
                __formatter.write_str("corev1::Unknown{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for PodPhase {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
impl ::std::default::Default for PodPhase {
    fn default() -> Self {
        PodPhase::Running{}
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
    pub phase: PodPhase
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
#[ddlog(rename = "corev1::Selectors")]
pub struct Selectors {
    pub s: types__selectors::LabelSelector
}
impl abomonation::Abomonation for Selectors{}
impl ::std::fmt::Display for Selectors {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Selectors{s} => {
                __formatter.write_str("corev1::Selectors{")?;
                ::std::fmt::Debug::fmt(s, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Selectors {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::Service")]
pub struct Service {
    pub meta: types__metav1::ObjectMeta,
    pub spec: ServiceSpec,
    pub status: ServiceStatus
}
impl abomonation::Abomonation for Service{}
impl ::std::fmt::Display for Service {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Service{meta,spec,status} => {
                __formatter.write_str("corev1::Service{")?;
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
impl ::std::fmt::Debug for Service {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::ServiceByName")]
pub struct ServiceByName {
    pub svc: ddlog_std::Ref<Service>,
    pub ns: String,
    pub name: String
}
impl abomonation::Abomonation for ServiceByName{}
impl ::std::fmt::Display for ServiceByName {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ServiceByName{svc,ns,name} => {
                __formatter.write_str("corev1::ServiceByName{")?;
                ::std::fmt::Debug::fmt(svc, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(ns, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ServiceByName {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::ServiceMatchesPod")]
pub struct ServiceMatchesPod {
    pub rs: ddlog_std::Ref<Service>,
    pub pod: ddlog_std::Ref<Pod>
}
impl abomonation::Abomonation for ServiceMatchesPod{}
impl ::std::fmt::Display for ServiceMatchesPod {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ServiceMatchesPod{rs,pod} => {
                __formatter.write_str("corev1::ServiceMatchesPod{")?;
                ::std::fmt::Debug::fmt(rs, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(pod, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ServiceMatchesPod {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::ServiceSpec")]
pub struct ServiceSpec {
    pub typ: ServiceType,
    pub selector: types__selectors::LabelSelector
}
impl abomonation::Abomonation for ServiceSpec{}
impl ::std::fmt::Display for ServiceSpec {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ServiceSpec{typ,selector} => {
                __formatter.write_str("corev1::ServiceSpec{")?;
                ::std::fmt::Debug::fmt(typ, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(selector, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ServiceSpec {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::ServiceStatus")]
pub struct ServiceStatus {
}
impl abomonation::Abomonation for ServiceStatus{}
impl ::std::fmt::Display for ServiceStatus {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ServiceStatus{} => {
                __formatter.write_str("corev1::ServiceStatus{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ServiceStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "corev1::ServiceType")]
pub enum ServiceType {
    #[ddlog(rename = "corev1::ClusterIP")]
    ClusterIP,
    #[ddlog(rename = "corev1::NodePort")]
    NodePort,
    #[ddlog(rename = "corev1::LoadBalancer")]
    LoadBalancer,
    #[ddlog(rename = "corev1::ExternalName")]
    ExternalName
}
impl abomonation::Abomonation for ServiceType{}
impl ::std::fmt::Display for ServiceType {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ServiceType::ClusterIP{} => {
                __formatter.write_str("corev1::ClusterIP{")?;
                __formatter.write_str("}")
            },
            ServiceType::NodePort{} => {
                __formatter.write_str("corev1::NodePort{")?;
                __formatter.write_str("}")
            },
            ServiceType::LoadBalancer{} => {
                __formatter.write_str("corev1::LoadBalancer{")?;
                __formatter.write_str("}")
            },
            ServiceType::ExternalName{} => {
                __formatter.write_str("corev1::ExternalName{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ServiceType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
impl ::std::default::Default for ServiceType {
    fn default() -> Self {
        ServiceType::ClusterIP{}
    }
}
pub fn __Key_corev1_Pod(__key: &::differential_datalog::ddval::DDValue) -> ::differential_datalog::ddval::DDValue {
    let ref x = *unsafe {<ddlog_std::Ref<Pod>>::from_ddvalue_ref_unchecked(__key) };
    (ddlog_std::tuple2(x.meta.namespace.clone(), x.meta.name.clone())).into_ddvalue()
}
pub fn __Key_corev1_Selectors(__key: &::differential_datalog::ddval::DDValue) -> ::differential_datalog::ddval::DDValue {
    let ref x = *unsafe {<Selectors>::from_ddvalue_ref_unchecked(__key) };
    ((*x).clone()).into_ddvalue()
}
pub fn __Key_corev1_Service(__key: &::differential_datalog::ddval::DDValue) -> ::differential_datalog::ddval::DDValue {
    let ref x = *unsafe {<ddlog_std::Ref<Service>>::from_ddvalue_ref_unchecked(__key) };
    (ddlog_std::tuple2(x.meta.namespace.clone(), x.meta.name.clone())).into_ddvalue()
}
pub static __Arng_corev1_PodByName_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <PodByName>::from_ddvalue_unchecked(__v) } {
                PodByName{pod: _, ns: ref _0, name: _} => Some(((*_0).clone()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_corev1_PodByName_1 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <PodByName>::from_ddvalue_unchecked(__v) } {
                PodByName{pod: _, ns: _, name: _} => Some((()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_corev1_Selectors_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <Selectors>::from_ddvalue_unchecked(__v) } {
                Selectors{s: _} => Some((()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_corev1_MatchesPod_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <MatchesPod>::from_ddvalue_unchecked(__v) } {
                MatchesPod{selector: ref _0, namespace: ref _1, pod: _} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: true
    }
});
pub static __Arng_corev1_MatchesPod_1 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <MatchesPod>::from_ddvalue_unchecked(__v) } {
                MatchesPod{selector: ref _0, namespace: _, pod: _} => Some(((*_0).clone()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: true
    }
});
pub static __Arng_corev1_ServiceByName_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <ServiceByName>::from_ddvalue_unchecked(__v) } {
                ServiceByName{svc: _, ns: ref _0, name: _} => Some(((*_0).clone()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_corev1_ServiceByName_1 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <ServiceByName>::from_ddvalue_unchecked(__v) } {
                ServiceByName{svc: _, ns: ref _0, name: ref _1} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Rule_corev1_PodByName_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* corev1::PodByName[(corev1::PodByName{.pod=pod, .ns=ns, .name=name}: corev1::PodByName)] :- corev1::Pod[(pod@ ((&(corev1::Pod{.meta=(_: metav1::ObjectMeta), .spec=(_: corev1::PodSpec), .status=(_: corev1::PodStatus)}: corev1::Pod)): ddlog_std::Ref<corev1::Pod>))], ((var ns: string) = ((pod.meta).namespace)), ((var name: string) = ((pod.meta).name)). */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 22, 1, 28, 1)),
        rel: 7,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 22, 1, 22, 26)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let ref pod = match *unsafe { <ddlog_std::Ref<Pod>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref pod => match pod {
                                                                       ref _0_ => match ((*_0_)).deref() {
                                                                                      Pod{meta: _, spec: _, status: _} => (*pod).clone(),
                                                                                      _ => return ::core::option::Option::None
                                                                                  },
                                                                       _ => return ::core::option::Option::None
                                                                   },
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    let ref ns: String = match pod.meta.namespace.clone() {
                                                        ns => ns,
                                                        _ => return None
                                                    };
                                                    let ref name: String = match pod.meta.name.clone() {
                                                        name => name,
                                                        _ => return None
                                                    };
                                                    Some(((PodByName{pod: (*pod).clone(), ns: (*ns).clone(), name: (*name).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});
pub static __Rule_corev1_MatchesPod_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* corev1::MatchesPod[(corev1::MatchesPod{.selector=selector, .namespace=ns, .pod=pod}: corev1::MatchesPod)] :- corev1::Selectors[(corev1::Selectors{.s=(selector: selectors::LabelSelector)}: corev1::Selectors)], corev1::PodByName[(corev1::PodByName{.pod=(pod: ddlog_std::Ref<corev1::Pod>), .ns=(ns: string), .name=(_: string)}: corev1::PodByName)], (selectors::labelSelectorMatches((ddlog_std::Some{.x=((ddlog_std::ref_new: function(selectors::LabelSelector):ddlog_std::Ref<selectors::LabelSelector>)(selector))}: ddlog_std::Option<ddlog_std::Ref<selectors::LabelSelector>>), ((pod.meta).labels))). */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 36, 1, 44, 1)),
        arr: (9, 0),
        xform: XFormArrangement::Join {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("corev1::PodByName"), ::std::borrow::Cow::Borrowed("(corev1::PodByName{.pod=(_: ddlog_std::Ref<corev1::Pod>), .ns=(_: string), .name=(_: string)}: corev1::PodByName)"), ::ddlog_profiler::SourcePosition::new_range("corev1.dl", 38, 3, 38, 24)),
                   ffun: None,
                   arrangement: (8,1),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let ref selector = match *unsafe { <Selectors>::from_ddvalue_ref_unchecked(__v1) } {
                           Selectors{s: ref selector} => (*selector).clone(),
                           _ => return ::std::option::Option::None
                       };
                       let (ref pod, ref ns) = match *unsafe { <PodByName>::from_ddvalue_ref_unchecked(__v2) } {
                           PodByName{pod: ref pod, ns: ref ns, name: _} => ((*pod).clone(), (*ns).clone()),
                           _ => return ::std::option::Option::None
                       };
                       if !types__selectors::labelSelectorMatches((&(ddlog_std::Option::Some{x: ddlog_std::ref_new((*selector).clone())})), (&pod.meta.labels)) {return None;};
                       ::std::option::Option::Some(((MatchesPod{selector: (*selector).clone(), namespace: (*ns).clone(), pod: (*pod).clone()})).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::std::option::Option::None)
               },
    }
});
pub static __Rule_corev1_ServiceByName_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* corev1::ServiceByName[(corev1::ServiceByName{.svc=svc, .ns=ns, .name=name}: corev1::ServiceByName)] :- corev1::Service[(svc@ ((&(corev1::Service{.meta=(_: metav1::ObjectMeta), .spec=(_: corev1::ServiceSpec), .status=(_: corev1::ServiceStatus)}: corev1::Service)): ddlog_std::Ref<corev1::Service>))], ((var ns: string) = ((svc.meta).namespace)), ((var name: string) = ((svc.meta).name)). */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 61, 1, 66, 1)),
        rel: 10,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 61, 1, 61, 30)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let ref svc = match *unsafe { <ddlog_std::Ref<Service>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref svc => match svc {
                                                                       ref _0_ => match ((*_0_)).deref() {
                                                                                      Service{meta: _, spec: _, status: _} => (*svc).clone(),
                                                                                      _ => return ::core::option::Option::None
                                                                                  },
                                                                       _ => return ::core::option::Option::None
                                                                   },
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    let ref ns: String = match svc.meta.namespace.clone() {
                                                        ns => ns,
                                                        _ => return None
                                                    };
                                                    let ref name: String = match svc.meta.name.clone() {
                                                        name => name,
                                                        _ => return None
                                                    };
                                                    Some(((ServiceByName{svc: (*svc).clone(), ns: (*ns).clone(), name: (*name).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});
pub static __Rule_corev1_ServiceMatchesPod_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* corev1::ServiceMatchesPod[(corev1::ServiceMatchesPod{.rs=svc, .pod=pod}: corev1::ServiceMatchesPod)] :- corev1::ServiceByName[(corev1::ServiceByName{.svc=(svc: ddlog_std::Ref<corev1::Service>), .ns=(ns: string), .name=(_: string)}: corev1::ServiceByName)], corev1::PodByName[(corev1::PodByName{.pod=(pod: ddlog_std::Ref<corev1::Pod>), .ns=(ns: string), .name=(_: string)}: corev1::PodByName)], (selectors::labelSelectorMatches((ddlog_std::Some{.x=((ddlog_std::ref_new: function(selectors::LabelSelector):ddlog_std::Ref<selectors::LabelSelector>)(((svc.spec).selector)))}: ddlog_std::Option<ddlog_std::Ref<selectors::LabelSelector>>), ((pod.meta).labels))). */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("corev1.dl", 67, 1, 71, 1)),
        arr: (11, 0),
        xform: XFormArrangement::Join {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("corev1::PodByName"), ::std::borrow::Cow::Borrowed("(corev1::PodByName{.pod=(_: ddlog_std::Ref<corev1::Pod>), .ns=(_0: string), .name=(_: string)}: corev1::PodByName)"), ::ddlog_profiler::SourcePosition::new_range("corev1.dl", 69, 3, 69, 24)),
                   ffun: None,
                   arrangement: (8,0),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let (ref svc, ref ns) = match *unsafe { <ServiceByName>::from_ddvalue_ref_unchecked(__v1) } {
                           ServiceByName{svc: ref svc, ns: ref ns, name: _} => ((*svc).clone(), (*ns).clone()),
                           _ => return ::std::option::Option::None
                       };
                       let ref pod = match *unsafe { <PodByName>::from_ddvalue_ref_unchecked(__v2) } {
                           PodByName{pod: ref pod, ns: _, name: _} => (*pod).clone(),
                           _ => return ::std::option::Option::None
                       };
                       if !types__selectors::labelSelectorMatches((&(ddlog_std::Option::Some{x: ddlog_std::ref_new(svc.spec.selector.clone())})), (&pod.meta.labels)) {return None;};
                       ::std::option::Option::Some(((ServiceMatchesPod{rs: (*svc).clone(), pod: (*pod).clone()})).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::std::option::Option::None)
               },
    }
});
pub static __Fact_corev1_Selectors_0 : ::once_cell::sync::Lazy<(program::RelId, ::differential_datalog::ddval::DDValue)> = ::once_cell::sync::Lazy::new(|| {
    (9, ((Selectors{s: (types__selectors::LabelSelector{matchLabels: (*(&*crate::__STATIC_0)).clone(), matchExpressions: (*(&*crate::__STATIC_1)).clone()})})).into_ddvalue()) /*corev1::Selectors[(corev1::Selectors{.s=(selectors::LabelSelector{.matchLabels=((ddlog_std::map_empty: function():ddlog_std::Map<string,string>)()), .matchExpressions=((ddlog_std::vec_empty: function():ddlog_std::Vec<ddlog_std::Ref<selectors::LabelSelectorRequirement>>)())}: selectors::LabelSelector)}: corev1::Selectors)].*/
});