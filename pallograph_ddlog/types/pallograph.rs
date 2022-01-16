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
#[ddlog(rename = "IngressController")]
pub struct IngressController {
    pub ns: String,
    pub name: String,
    pub className: String
}
impl abomonation::Abomonation for IngressController{}
impl ::std::fmt::Display for IngressController {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IngressController{ns,name,className} => {
                __formatter.write_str("IngressController{")?;
                differential_datalog::record::format_ddlog_str(ns, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(className, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for IngressController {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "IsPublic")]
pub struct IsPublic {
    pub svc: ddlog_std::Ref<types__corev1::Service>
}
impl abomonation::Abomonation for IsPublic{}
impl ::std::fmt::Display for IsPublic {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IsPublic{svc} => {
                __formatter.write_str("IsPublic{")?;
                ::std::fmt::Debug::fmt(svc, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for IsPublic {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "NodesInUse")]
pub struct NodesInUse {
    pub name: String
}
impl abomonation::Abomonation for NodesInUse{}
impl ::std::fmt::Display for NodesInUse {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            NodesInUse{name} => {
                __formatter.write_str("NodesInUse{")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for NodesInUse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
pub static __Arng_IngressController_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <IngressController>::from_ddvalue_unchecked(__v) } {
                IngressController{ns: ref _0, name: ref _1, className: _} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Rule_NodesInUse_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* NodesInUse[(NodesInUse{.name=n}: NodesInUse)] :- corev1::Pod[(pod@ ((&(corev1::Pod{.meta=(_: metav1::ObjectMeta), .spec=(_: corev1::PodSpec), .status=(_: corev1::PodStatus)}: corev1::Pod)): ddlog_std::Ref<corev1::Pod>))], ((var n: string) = ((pod.spec).nodeName)). */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 10, 1, 14, 1)),
        rel: 7,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 10, 1, 10, 15)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let ref pod = match *unsafe { <ddlog_std::Ref<types__corev1::Pod>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref pod => match pod {
                                                                       ref _0_ => match ((*_0_)).deref() {
                                                                                      types__corev1::Pod{meta: _, spec: _, status: _} => (*pod).clone(),
                                                                                      _ => return ::core::option::Option::None
                                                                                  },
                                                                       _ => return ::core::option::Option::None
                                                                   },
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    let ref n: String = match pod.spec.nodeName.clone() {
                                                        n => n,
                                                        _ => return None
                                                    };
                                                    Some(((NodesInUse{name: (*n).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});
pub static __Rule_IsPublic_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* IsPublic[(IsPublic{.svc=svc}: IsPublic)] :- corev1::Service[(svc@ ((&(corev1::Service{.meta=(_: metav1::ObjectMeta), .spec=(spec: corev1::ServiceSpec), .status=(_: corev1::ServiceStatus)}: corev1::Service)): ddlog_std::Ref<corev1::Service>))], ((spec.typ) == (corev1::LoadBalancer{}: corev1::ServiceType)). */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 15, 1, 19, 1)),
        rel: 10,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 15, 1, 15, 15)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let (ref svc, ref spec) = match *unsafe { <ddlog_std::Ref<types__corev1::Service>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref svc => match svc {
                                                                       ref _0_ => match ((*_0_)).deref() {
                                                                                      types__corev1::Service{meta: _, spec: spec, status: _} => ((*svc).clone(), (*spec).clone()),
                                                                                      _ => return ::core::option::Option::None
                                                                                  },
                                                                       _ => return ::core::option::Option::None
                                                                   },
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    if !((&*(&spec.typ)) == (&*(&(types__corev1::ServiceType::LoadBalancer{})))) {return None;};
                                                    Some(((IsPublic{svc: (*svc).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});
pub static __Rule_IsPublic_1 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* IsPublic[(IsPublic{.svc=svc}: IsPublic)] :- IsPublic[(IsPublic{.svc=(ingSvc: ddlog_std::Ref<corev1::Service>)}: IsPublic)], IngressController[(IngressController{.ns=((ingSvc.meta).namespace), .name=((ingSvc.meta).name), .className=(className: string)}: IngressController)], networkingv1::IngressByName[(networkingv1::IngressByName{.ing=(ing: ddlog_std::Ref<networkingv1::Ingress>), .ns=((ingSvc.meta).namespace), .name=((ingSvc.meta).name)}: networkingv1::IngressByName)], networkingv1::IngressToService[(networkingv1::IngressToService{.ing=(ing: ddlog_std::Ref<networkingv1::Ingress>), .svc=(svc: ddlog_std::Ref<corev1::Service>)}: networkingv1::IngressToService)], (((ing.spec).ingressClassName) == className). */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 19, 1, 25, 1)),
        rel: 1,
        xform: ::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(((ingSvc.meta).namespace), ((ingSvc.meta).name))"),::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 20, 3, 20, 19)),
                                                afun: {
                                                    fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                        ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                    {
                                                        let ref ingSvc = match *unsafe { <IsPublic>::from_ddvalue_ref_unchecked(&__v) } {
                                                            IsPublic{svc: ref ingSvc} => (*ingSvc).clone(),
                                                            _ => return ::core::option::Option::None
                                                        };
                                                        ::core::option::Option::Some(((ddlog_std::tuple2(ingSvc.meta.namespace.clone(), ingSvc.meta.name.clone())).into_ddvalue(), ((*ingSvc).clone()).into_ddvalue()))
                                                    }
                                                    __ddlog_generated_arrangement_function
                                                },
                                                next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                 debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("IngressController"), ::std::borrow::Cow::Borrowed("(IngressController{.ns=_0, .name=_1, .className=(_: string)}: IngressController)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 21, 3, 21, 72)),
                                                                                 ffun: None,
                                                                                 arrangement: (0,0),
                                                                                 jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                 {
                                                                                     let ref ingSvc = *unsafe { <ddlog_std::Ref<types__corev1::Service>>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                     let ref className = match *unsafe { <IngressController>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                         IngressController{ns: _, name: _, className: ref className} => (*className).clone(),
                                                                                         _ => return ::std::option::Option::None
                                                                                     };
                                                                                     ::std::option::Option::Some((ddlog_std::tuple2((*className).clone(), (*ingSvc).clone())).into_ddvalue())
                                                                                 }
                                                                                 __f},
                                                                                 next: Box::new(::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                                                                                                 debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(((ingSvc.meta).namespace), ((ingSvc.meta).name))"),::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 20, 3, 21, 72)),
                                                                                                                                 afun: {
                                                                                                                                     fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                                                                                                         ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                                                                                                     {
                                                                                                                                         let ddlog_std::tuple2(ref className, ref ingSvc) = *unsafe { <ddlog_std::tuple2<String, ddlog_std::Ref<types__corev1::Service>>>::from_ddvalue_ref_unchecked( &__v ) };
                                                                                                                                         ::core::option::Option::Some(((ddlog_std::tuple2(ingSvc.meta.namespace.clone(), ingSvc.meta.name.clone())).into_ddvalue(), ((*className).clone()).into_ddvalue()))
                                                                                                                                     }
                                                                                                                                     __ddlog_generated_arrangement_function
                                                                                                                                 },
                                                                                                                                 next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                                                                                                  debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("networkingv1::IngressByName"), ::std::borrow::Cow::Borrowed("(networkingv1::IngressByName{.ing=(_: ddlog_std::Ref<networkingv1::Ingress>), .ns=_0, .name=_1}: networkingv1::IngressByName)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 22, 3, 22, 76)),
                                                                                                                                                                  ffun: None,
                                                                                                                                                                  arrangement: (15,0),
                                                                                                                                                                  jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                                                                                                  {
                                                                                                                                                                      let ref className = *unsafe { <String>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                                                                                                      let ref ing = match *unsafe { <types__networkingv1::IngressByName>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                                                                                                          types__networkingv1::IngressByName{ing: ref ing, ns: _, name: _} => (*ing).clone(),
                                                                                                                                                                          _ => return ::std::option::Option::None
                                                                                                                                                                      };
                                                                                                                                                                      ::std::option::Option::Some((ddlog_std::tuple2((*ing).clone(), (*className).clone())).into_ddvalue())
                                                                                                                                                                  }
                                                                                                                                                                  __f},
                                                                                                                                                                  next: Box::new(::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                                                                                                                                                                                  debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(ing)"),::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 20, 3, 22, 76)),
                                                                                                                                                                                                                  afun: {
                                                                                                                                                                                                                      fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                                                                                                                                                                                          ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                                                                                                                                                                                      {
                                                                                                                                                                                                                          let ddlog_std::tuple2(ref ing, ref className) = *unsafe { <ddlog_std::tuple2<ddlog_std::Ref<types__networkingv1::Ingress>, String>>::from_ddvalue_ref_unchecked( &__v ) };
                                                                                                                                                                                                                          ::core::option::Option::Some((((*ing).clone()).into_ddvalue(), (ddlog_std::tuple2((*ing).clone(), (*className).clone())).into_ddvalue()))
                                                                                                                                                                                                                      }
                                                                                                                                                                                                                      __ddlog_generated_arrangement_function
                                                                                                                                                                                                                  },
                                                                                                                                                                                                                  next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                                                                                                                                                                                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("networkingv1::IngressToService"), ::std::borrow::Cow::Borrowed("(networkingv1::IngressToService{.ing=(_0: ddlog_std::Ref<networkingv1::Ingress>), .svc=(_: ddlog_std::Ref<corev1::Service>)}: networkingv1::IngressToService)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 23, 3, 23, 43)),
                                                                                                                                                                                                                                                   ffun: None,
                                                                                                                                                                                                                                                   arrangement: (16,0),
                                                                                                                                                                                                                                                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                                                                                                                                                                                   {
                                                                                                                                                                                                                                                       let ddlog_std::tuple2(ref ing, ref className) = *unsafe { <ddlog_std::tuple2<ddlog_std::Ref<types__networkingv1::Ingress>, String>>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                                                                                                                                                                                       let ref svc = match *unsafe { <types__networkingv1::IngressToService>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                                                                                                                                                                                           types__networkingv1::IngressToService{ing: _, svc: ref svc} => (*svc).clone(),
                                                                                                                                                                                                                                                           _ => return ::std::option::Option::None
                                                                                                                                                                                                                                                       };
                                                                                                                                                                                                                                                       if !((&*(&ing.spec.ingressClassName)) == (&*className)) {return None;};
                                                                                                                                                                                                                                                       ::std::option::Option::Some(((IsPublic{svc: (*svc).clone()})).into_ddvalue())
                                                                                                                                                                                                                                                   }
                                                                                                                                                                                                                                                   __f},
                                                                                                                                                                                                                                                   next: Box::new(::std::option::Option::None)
                                                                                                                                                                                                                                               }),
                                                                                                                                                                                                              }))
                                                                                                                                                              }),
                                                                                                                             }))
                                                                             }),
                                            }),
    }
});