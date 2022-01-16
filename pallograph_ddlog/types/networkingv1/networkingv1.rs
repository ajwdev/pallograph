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
#[ddlog(rename = "networkingv1::Ingress")]
pub struct Ingress {
    pub meta: types__metav1::ObjectMeta,
    pub spec: IngressSpec,
    pub status: IngressStatus
}
impl abomonation::Abomonation for Ingress{}
impl ::std::fmt::Display for Ingress {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Ingress{meta,spec,status} => {
                __formatter.write_str("networkingv1::Ingress{")?;
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
impl ::std::fmt::Debug for Ingress {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "networkingv1::IngressByName")]
pub struct IngressByName {
    pub ing: ddlog_std::Ref<Ingress>,
    pub ns: String,
    pub name: String
}
impl abomonation::Abomonation for IngressByName{}
impl ::std::fmt::Display for IngressByName {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IngressByName{ing,ns,name} => {
                __formatter.write_str("networkingv1::IngressByName{")?;
                ::std::fmt::Debug::fmt(ing, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(ns, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for IngressByName {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "networkingv1::IngressRule")]
pub struct IngressRule {
    pub host: String,
    pub backend: String
}
impl abomonation::Abomonation for IngressRule{}
impl ::std::fmt::Display for IngressRule {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IngressRule{host,backend} => {
                __formatter.write_str("networkingv1::IngressRule{")?;
                differential_datalog::record::format_ddlog_str(host, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(backend, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for IngressRule {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "networkingv1::IngressSpec")]
pub struct IngressSpec {
    pub ingressClassName: String,
    pub rules: ddlog_std::Vec<ddlog_std::Ref<IngressRule>>
}
impl abomonation::Abomonation for IngressSpec{}
impl ::std::fmt::Display for IngressSpec {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IngressSpec{ingressClassName,rules} => {
                __formatter.write_str("networkingv1::IngressSpec{")?;
                differential_datalog::record::format_ddlog_str(ingressClassName, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(rules, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for IngressSpec {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "networkingv1::IngressStatus")]
pub struct IngressStatus {
}
impl abomonation::Abomonation for IngressStatus{}
impl ::std::fmt::Display for IngressStatus {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IngressStatus{} => {
                __formatter.write_str("networkingv1::IngressStatus{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for IngressStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "networkingv1::IngressToService")]
pub struct IngressToService {
    pub ing: ddlog_std::Ref<Ingress>,
    pub svc: ddlog_std::Ref<types__corev1::Service>
}
impl abomonation::Abomonation for IngressToService{}
impl ::std::fmt::Display for IngressToService {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IngressToService{ing,svc} => {
                __formatter.write_str("networkingv1::IngressToService{")?;
                ::std::fmt::Debug::fmt(ing, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(svc, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for IngressToService {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
pub fn __Key_networkingv1_Ingress(__key: &::differential_datalog::ddval::DDValue) -> ::differential_datalog::ddval::DDValue {
    let ref x = *unsafe {<ddlog_std::Ref<Ingress>>::from_ddvalue_ref_unchecked(__key) };
    (ddlog_std::tuple2(x.meta.namespace.clone(), x.meta.name.clone())).into_ddvalue()
}
pub static __Arng_networkingv1_IngressToService_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <IngressToService>::from_ddvalue_unchecked(__v) } {
                IngressToService{ing: ref _0, svc: _} => Some(((*_0).clone()).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_networkingv1_IngressByName_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <IngressByName>::from_ddvalue_unchecked(__v) } {
                IngressByName{ing: _, ns: ref _0, name: ref _1} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Rule_networkingv1_IngressToService_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* networkingv1::IngressToService[(networkingv1::IngressToService{.ing=ing, .svc=svc}: networkingv1::IngressToService)] :- networkingv1::Ingress[(ing@ ((&(networkingv1::Ingress{.meta=(_: metav1::ObjectMeta), .spec=(_: networkingv1::IngressSpec), .status=(_: networkingv1::IngressStatus)}: networkingv1::Ingress)): ddlog_std::Ref<networkingv1::Ingress>))], (var rules: ddlog_std::Ref<networkingv1::IngressRule>) = FlatMap(((((ddlog_std::deref: function(ddlog_std::Ref<networkingv1::Ingress>):networkingv1::Ingress)(ing)).spec).rules)), ((var backend: string) = (rules.backend)), corev1::ServiceByName[(corev1::ServiceByName{.svc=(svc: ddlog_std::Ref<corev1::Service>), .ns=((ing.meta).namespace), .name=(backend: string)}: corev1::ServiceByName)]. */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("networkingv1.dl", 29, 1, 34, 1)),
        rel: 14,
        xform: ::core::option::Option::Some(XFormCollection::FlatMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::flatmap(::ddlog_profiler::SourcePosition::new_range("networkingv1.dl", 31, 3, 31, 46)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<Box<dyn Iterator<Item=::differential_datalog::ddval::DDValue>>>
                                                {
                                                    let ref ing = match *unsafe { <ddlog_std::Ref<Ingress>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref ing => match ing {
                                                                       ref _0_ => match ((*_0_)).deref() {
                                                                                      Ingress{meta: _, spec: _, status: _} => (*ing).clone(),
                                                                                      _ => return ::core::option::Option::None
                                                                                  },
                                                                       _ => return ::core::option::Option::None
                                                                   },
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    let __flattened = ddlog_std::deref(ing).spec.rules.clone();
                                                    let ing = (*ing).clone();
                                                    Some(Box::new(__flattened.into_iter().map(move |rules| (ddlog_std::tuple2(rules.clone(), ing.clone())).into_ddvalue())))
                                                }
                                                __f},
                                                next: Box::new(::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(((ing.meta).namespace), backend)"),::ddlog_profiler::SourcePosition::new_range("networkingv1.dl", 30, 3, 32, 30)),
                                                                                                afun: {
                                                                                                    fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                                                                        ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                                                                    {
                                                                                                        let ddlog_std::tuple2(ref rules, ref ing) = *unsafe { <ddlog_std::tuple2<ddlog_std::Ref<IngressRule>, ddlog_std::Ref<Ingress>>>::from_ddvalue_ref_unchecked( &__v ) };
                                                                                                        let ref backend: String = match rules.backend.clone() {
                                                                                                            backend => backend,
                                                                                                            _ => return None
                                                                                                        };
                                                                                                        ::core::option::Option::Some(((ddlog_std::tuple2(ing.meta.namespace.clone(), (*backend).clone())).into_ddvalue(), ((*ing).clone()).into_ddvalue()))
                                                                                                    }
                                                                                                    __ddlog_generated_arrangement_function
                                                                                                },
                                                                                                next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                                                                 debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("corev1::ServiceByName"), ::std::borrow::Cow::Borrowed("(corev1::ServiceByName{.svc=(_: ddlog_std::Ref<corev1::Service>), .ns=_0, .name=(_1: string)}: corev1::ServiceByName)"), ::ddlog_profiler::SourcePosition::new_range("networkingv1.dl", 33, 3, 33, 50)),
                                                                                                                                 ffun: None,
                                                                                                                                 arrangement: (11,1),
                                                                                                                                 jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                                                                 {
                                                                                                                                     let ref ing = *unsafe { <ddlog_std::Ref<Ingress>>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                                                                     let ref svc = match *unsafe { <types__corev1::ServiceByName>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                                                                         types__corev1::ServiceByName{svc: ref svc, ns: _, name: _} => (*svc).clone(),
                                                                                                                                         _ => return ::std::option::Option::None
                                                                                                                                     };
                                                                                                                                     ::std::option::Option::Some(((IngressToService{ing: (*ing).clone(), svc: (*svc).clone()})).into_ddvalue())
                                                                                                                                 }
                                                                                                                                 __f},
                                                                                                                                 next: Box::new(::std::option::Option::None)
                                                                                                                             }),
                                                                                            }))
                                            }),
    }
});
pub static __Rule_networkingv1_IngressByName_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* networkingv1::IngressByName[(networkingv1::IngressByName{.ing=ing, .ns=ns, .name=name}: networkingv1::IngressByName)] :- networkingv1::Ingress[(ing@ ((&(networkingv1::Ingress{.meta=(_: metav1::ObjectMeta), .spec=(_: networkingv1::IngressSpec), .status=(_: networkingv1::IngressStatus)}: networkingv1::Ingress)): ddlog_std::Ref<networkingv1::Ingress>))], ((var ns: string) = ((ing.meta).namespace)), ((var name: string) = ((ing.meta).name)). */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("networkingv1.dl", 23, 1, 28, 1)),
        rel: 14,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("networkingv1.dl", 23, 1, 23, 30)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let ref ing = match *unsafe { <ddlog_std::Ref<Ingress>>::from_ddvalue_ref_unchecked(&__v) } {
                                                        ref ing => match ing {
                                                                       ref _0_ => match ((*_0_)).deref() {
                                                                                      Ingress{meta: _, spec: _, status: _} => (*ing).clone(),
                                                                                      _ => return ::core::option::Option::None
                                                                                  },
                                                                       _ => return ::core::option::Option::None
                                                                   },
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    let ref ns: String = match ing.meta.namespace.clone() {
                                                        ns => ns,
                                                        _ => return None
                                                    };
                                                    let ref name: String = match ing.meta.name.clone() {
                                                        name => name,
                                                        _ => return None
                                                    };
                                                    Some(((IngressByName{ing: (*ing).clone(), ns: (*ns).clone(), name: (*name).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});