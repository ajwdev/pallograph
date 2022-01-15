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
    pub namespace: String,
    pub name: String
}
impl abomonation::Abomonation for IngressController{}
impl ::std::fmt::Display for IngressController {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IngressController{namespace,name} => {
                __formatter.write_str("IngressController{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
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
#[ddlog(rename = "Ingresses")]
pub struct Ingresses {
    pub namespace: String,
    pub name: String,
    pub controller: String,
    pub serviceName: String
}
impl abomonation::Abomonation for Ingresses{}
impl ::std::fmt::Display for Ingresses {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Ingresses{namespace,name,controller,serviceName} => {
                __formatter.write_str("Ingresses{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(controller, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(serviceName, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Ingresses {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "IsPublic")]
pub struct IsPublic {
    pub namespace: String,
    pub pod: String
}
impl abomonation::Abomonation for IsPublic{}
impl ::std::fmt::Display for IsPublic {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IsPublic{namespace,pod} => {
                __formatter.write_str("IsPublic{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(pod, __formatter)?;
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
#[ddlog(rename = "Labels")]
pub struct Labels {
    pub k: String,
    pub v: String,
    pub ty: Object,
    pub namespace: String,
    pub name: String
}
impl abomonation::Abomonation for Labels{}
impl ::std::fmt::Display for Labels {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Labels{k,v,ty,namespace,name} => {
                __formatter.write_str("Labels{")?;
                differential_datalog::record::format_ddlog_str(k, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(v, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(ty, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Labels {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "Nodes")]
pub struct Nodes {
    pub name: String
}
impl abomonation::Abomonation for Nodes{}
impl ::std::fmt::Display for Nodes {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Nodes{name} => {
                __formatter.write_str("Nodes{")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Nodes {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "NodesToReplicaSet")]
pub struct NodesToReplicaSet {
    pub namespace: String,
    pub rs: String,
    pub node: String
}
impl abomonation::Abomonation for NodesToReplicaSet{}
impl ::std::fmt::Display for NodesToReplicaSet {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            NodesToReplicaSet{namespace,rs,node} => {
                __formatter.write_str("NodesToReplicaSet{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(rs, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(node, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for NodesToReplicaSet {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "Object")]
pub enum Object {
    #[ddlog(rename = "Pod")]
    Pod,
    #[ddlog(rename = "ReplicaSet")]
    ReplicaSet,
    #[ddlog(rename = "Node")]
    Node,
    #[ddlog(rename = "Service")]
    Service
}
impl abomonation::Abomonation for Object{}
impl ::std::fmt::Display for Object {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Object::Pod{} => {
                __formatter.write_str("Pod{")?;
                __formatter.write_str("}")
            },
            Object::ReplicaSet{} => {
                __formatter.write_str("ReplicaSet{")?;
                __formatter.write_str("}")
            },
            Object::Node{} => {
                __formatter.write_str("Node{")?;
                __formatter.write_str("}")
            },
            Object::Service{} => {
                __formatter.write_str("Service{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Object {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
impl ::std::default::Default for Object {
    fn default() -> Self {
        Object::Pod{}
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "Pods")]
pub struct Pods {
    pub namespace: String,
    pub name: String,
    pub node: String
}
impl abomonation::Abomonation for Pods{}
impl ::std::fmt::Display for Pods {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Pods{namespace,name,node} => {
                __formatter.write_str("Pods{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(node, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Pods {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "PodsToReplicaSet")]
pub struct PodsToReplicaSet {
    pub namespace: String,
    pub rs: String,
    pub pod: String
}
impl abomonation::Abomonation for PodsToReplicaSet{}
impl ::std::fmt::Display for PodsToReplicaSet {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PodsToReplicaSet{namespace,rs,pod} => {
                __formatter.write_str("PodsToReplicaSet{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(rs, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(pod, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for PodsToReplicaSet {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "ReplicaSets")]
pub struct ReplicaSets {
    pub namespace: String,
    pub name: String
}
impl abomonation::Abomonation for ReplicaSets{}
impl ::std::fmt::Display for ReplicaSets {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReplicaSets{namespace,name} => {
                __formatter.write_str("ReplicaSets{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for ReplicaSets {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "Selectors")]
pub struct Selectors {
    pub k: String,
    pub v: String,
    pub ty: Object,
    pub namespace: String,
    pub name: String
}
impl abomonation::Abomonation for Selectors{}
impl ::std::fmt::Display for Selectors {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Selectors{k,v,ty,namespace,name} => {
                __formatter.write_str("Selectors{")?;
                differential_datalog::record::format_ddlog_str(k, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(v, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(ty, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
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
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "ServiceType")]
pub enum ServiceType {
    #[ddlog(rename = "ClusterIP")]
    ClusterIP,
    #[ddlog(rename = "NodePort")]
    NodePort,
    #[ddlog(rename = "LoadBalancer")]
    LoadBalancer,
    #[ddlog(rename = "ExternalName")]
    ExternalName
}
impl abomonation::Abomonation for ServiceType{}
impl ::std::fmt::Display for ServiceType {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ServiceType::ClusterIP{} => {
                __formatter.write_str("ClusterIP{")?;
                __formatter.write_str("}")
            },
            ServiceType::NodePort{} => {
                __formatter.write_str("NodePort{")?;
                __formatter.write_str("}")
            },
            ServiceType::LoadBalancer{} => {
                __formatter.write_str("LoadBalancer{")?;
                __formatter.write_str("}")
            },
            ServiceType::ExternalName{} => {
                __formatter.write_str("ExternalName{")?;
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
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "Services")]
pub struct Services {
    pub namespace: String,
    pub name: String,
    pub ty: ServiceType
}
impl abomonation::Abomonation for Services{}
impl ::std::fmt::Display for Services {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Services{namespace,name,ty} => {
                __formatter.write_str("Services{")?;
                differential_datalog::record::format_ddlog_str(namespace, __formatter)?;
                __formatter.write_str(",")?;
                differential_datalog::record::format_ddlog_str(name, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(ty, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for Services {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
pub static __Arng_IngressController_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Set{
        debug_info: Default::default(),
        fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
        {
            match unsafe { <IngressController>::from_ddvalue_unchecked(__v) } {
                IngressController{namespace: ref _0, name: ref _1} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }
        }
        __f},
        distinct: false
    }
});
pub static __Arng_Ingresses_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <Ingresses>::from_ddvalue_unchecked(__v) } {
                Ingresses{namespace: ref _0, name: _, controller: ref _1, serviceName: _} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_Labels_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <Labels>::from_ddvalue_unchecked(__v) } {
                Labels{k: ref _0, v: ref _1, ty: Object::Pod{}, namespace: ref _2, name: _} => Some((ddlog_std::tuple3((*_0).clone(), (*_1).clone(), (*_2).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_Pods_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <Pods>::from_ddvalue_unchecked(__v) } {
                Pods{namespace: ref _0, name: ref _1, node: _} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_Selectors_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <Selectors>::from_ddvalue_unchecked(__v) } {
                Selectors{k: _, v: _, ty: Object::Service{}, namespace: ref _0, name: ref _1} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_Selectors_1 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <Selectors>::from_ddvalue_unchecked(__v) } {
                Selectors{k: ref _0, v: ref _1, ty: Object::ReplicaSet{}, namespace: ref _2, name: _} => Some((ddlog_std::tuple3((*_0).clone(), (*_1).clone(), (*_2).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_PodsToReplicaSet_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <PodsToReplicaSet>::from_ddvalue_unchecked(__v) } {
                PodsToReplicaSet{namespace: ref _0, rs: _, pod: ref _1} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_PodsToReplicaSet_1 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <PodsToReplicaSet>::from_ddvalue_unchecked(__v) } {
                PodsToReplicaSet{namespace: ref _0, rs: _, pod: ref _1} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: true
    }
});
pub static __Arng_NodesToReplicaSet_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <NodesToReplicaSet>::from_ddvalue_unchecked(__v) } {
                NodesToReplicaSet{namespace: ref _0, rs: ref _1, node: _} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: true
    }
});
pub static __Arng_Services_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <Services>::from_ddvalue_unchecked(__v) } {
                Services{namespace: ref _0, name: ref _1, ty: ServiceType::LoadBalancer{}} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Arng_IsPublic_0 : ::once_cell::sync::Lazy<program::Arrangement> = ::once_cell::sync::Lazy::new(|| {
    program::Arrangement::Map{
       debug_info:  Default::default(),
        afun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<(::differential_datalog::ddval::DDValue,::differential_datalog::ddval::DDValue)>
        {
            let __cloned = __v.clone();
            match unsafe { <IsPublic>::from_ddvalue_unchecked(__v) } {
                IsPublic{namespace: ref _0, pod: ref _1} => Some((ddlog_std::tuple2((*_0).clone(), (*_1).clone())).into_ddvalue()),
                _ => None
            }.map(|x|(x,__cloned))
        }
        __f},
        queryable: false
    }
});
pub static __Rule_Nodes_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* Nodes[(Nodes{.name=n}: Nodes)] :- Pods[(Pods{.namespace=(_: string), .name=(_: string), .node=(n: string)}: Pods)]. */
    ::differential_datalog::program::Rule::CollectionRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 21, 1, 23, 1)),
        rel: 6,
        xform: ::core::option::Option::Some(XFormCollection::FilterMap{
                                                debug_info: ::ddlog_profiler::OperatorDebugInfo::head(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 21, 1, 21, 10)),
                                                fmfun: {fn __f(__v: ::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                {
                                                    let ref n = match *unsafe { <Pods>::from_ddvalue_ref_unchecked(&__v) } {
                                                        Pods{namespace: _, name: _, node: ref n} => (*n).clone(),
                                                        _ => return ::core::option::Option::None
                                                    };
                                                    Some(((Nodes{name: (*n).clone()})).into_ddvalue())
                                                }
                                                __f},
                                                next: Box::new(None)
                                            }),
    }
});
pub static __Rule_PodsToReplicaSet_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* PodsToReplicaSet[(PodsToReplicaSet{.namespace=namespace, .rs=rs, .pod=pod}: PodsToReplicaSet)] :- Selectors[(Selectors{.k=(key: string), .v=(val: string), .ty=(ReplicaSet{}: Object), .namespace=(namespace: string), .name=(rs: string)}: Selectors)], Labels[(Labels{.k=(key: string), .v=(val: string), .ty=(Pod{}: Object), .namespace=(namespace: string), .name=(pod: string)}: Labels)]. */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 25, 1, 29, 1)),
        arr: (9, 1),
        xform: XFormArrangement::Join {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("Labels"), ::std::borrow::Cow::Borrowed("(Labels{.k=(_0: string), .v=(_1: string), .ty=(Pod{}: Object), .namespace=(_2: string), .name=(_: string)}: Labels)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 27, 3, 27, 40)),
                   ffun: None,
                   arrangement: (3,0),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let (ref key, ref val, ref namespace, ref rs) = match *unsafe { <Selectors>::from_ddvalue_ref_unchecked(__v1) } {
                           Selectors{k: ref key, v: ref val, ty: Object::ReplicaSet{}, namespace: ref namespace, name: ref rs} => ((*key).clone(), (*val).clone(), (*namespace).clone(), (*rs).clone()),
                           _ => return ::std::option::Option::None
                       };
                       let ref pod = match *unsafe { <Labels>::from_ddvalue_ref_unchecked(__v2) } {
                           Labels{k: _, v: _, ty: Object::Pod{}, namespace: _, name: ref pod} => (*pod).clone(),
                           _ => return ::std::option::Option::None
                       };
                       ::std::option::Option::Some(((PodsToReplicaSet{namespace: (*namespace).clone(), rs: (*rs).clone(), pod: (*pod).clone()})).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::std::option::Option::None)
               },
    }
});
pub static __Rule_NodesToReplicaSet_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* NodesToReplicaSet[(NodesToReplicaSet{.namespace=namespace, .rs=rs, .node=node}: NodesToReplicaSet)] :- PodsToReplicaSet[(PodsToReplicaSet{.namespace=(namespace: string), .rs=(rs: string), .pod=(pod: string)}: PodsToReplicaSet)], Pods[(Pods{.namespace=(namespace: string), .name=(pod: string), .node=(node: string)}: Pods)]. */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 31, 1, 35, 1)),
        arr: (7, 0),
        xform: XFormArrangement::Join {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("Pods"), ::std::borrow::Cow::Borrowed("(Pods{.namespace=(_0: string), .name=(_1: string), .node=(_: string)}: Pods)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 33, 3, 33, 29)),
                   ffun: None,
                   arrangement: (6,0),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let (ref namespace, ref rs, ref pod) = match *unsafe { <PodsToReplicaSet>::from_ddvalue_ref_unchecked(__v1) } {
                           PodsToReplicaSet{namespace: ref namespace, rs: ref rs, pod: ref pod} => ((*namespace).clone(), (*rs).clone(), (*pod).clone()),
                           _ => return ::std::option::Option::None
                       };
                       let ref node = match *unsafe { <Pods>::from_ddvalue_ref_unchecked(__v2) } {
                           Pods{namespace: _, name: _, node: ref node} => (*node).clone(),
                           _ => return ::std::option::Option::None
                       };
                       ::std::option::Option::Some(((NodesToReplicaSet{namespace: (*namespace).clone(), rs: (*rs).clone(), node: (*node).clone()})).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::std::option::Option::None)
               },
    }
});
pub static __Rule_IsPublic_0 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* IsPublic[(IsPublic{.namespace=namespace, .pod=pod}: IsPublic)] :- Services[(Services{.namespace=(namespace: string), .name=(serviceName: string), .ty=(LoadBalancer{}: ServiceType)}: Services)], Selectors[(Selectors{.k=(key: string), .v=(val: string), .ty=(Service{}: Object), .namespace=(namespace: string), .name=(serviceName: string)}: Selectors)], Labels[(Labels{.k=(key: string), .v=(val: string), .ty=(Pod{}: Object), .namespace=(namespace: string), .name=(pod: string)}: Labels)]. */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 36, 1, 41, 1)),
        arr: (10, 0),
        xform: XFormArrangement::Join {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("Selectors"), ::std::borrow::Cow::Borrowed("(Selectors{.k=(_: string), .v=(_: string), .ty=(Service{}: Object), .namespace=(_0: string), .name=(_1: string)}: Selectors)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 38, 3, 38, 55)),
                   ffun: None,
                   arrangement: (9,0),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let (ref namespace, ref serviceName) = match *unsafe { <Services>::from_ddvalue_ref_unchecked(__v1) } {
                           Services{namespace: ref namespace, name: ref serviceName, ty: ServiceType::LoadBalancer{}} => ((*namespace).clone(), (*serviceName).clone()),
                           _ => return ::std::option::Option::None
                       };
                       let (ref key, ref val) = match *unsafe { <Selectors>::from_ddvalue_ref_unchecked(__v2) } {
                           Selectors{k: ref key, v: ref val, ty: Object::Service{}, namespace: _, name: _} => ((*key).clone(), (*val).clone()),
                           _ => return ::std::option::Option::None
                       };
                       ::std::option::Option::Some((ddlog_std::tuple3((*key).clone(), (*val).clone(), (*namespace).clone())).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                                   debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(key, val, namespace)"),::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 37, 3, 38, 55)),
                                                                   afun: {
                                                                       fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                                           ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                                       {
                                                                           let ddlog_std::tuple3(ref key, ref val, ref namespace) = *unsafe { <ddlog_std::tuple3<String, String, String>>::from_ddvalue_ref_unchecked( &__v ) };
                                                                           ::core::option::Option::Some(((ddlog_std::tuple3((*key).clone(), (*val).clone(), (*namespace).clone())).into_ddvalue(), ((*namespace).clone()).into_ddvalue()))
                                                                       }
                                                                       __ddlog_generated_arrangement_function
                                                                   },
                                                                   next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                                    debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("Labels"), ::std::borrow::Cow::Borrowed("(Labels{.k=(_0: string), .v=(_1: string), .ty=(Pod{}: Object), .namespace=(_2: string), .name=(_: string)}: Labels)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 39, 3, 39, 40)),
                                                                                                    ffun: None,
                                                                                                    arrangement: (3,0),
                                                                                                    jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                                    {
                                                                                                        let ref namespace = *unsafe { <String>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                                        let ref pod = match *unsafe { <Labels>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                                            Labels{k: _, v: _, ty: Object::Pod{}, namespace: _, name: ref pod} => (*pod).clone(),
                                                                                                            _ => return ::std::option::Option::None
                                                                                                        };
                                                                                                        ::std::option::Option::Some(((IsPublic{namespace: (*namespace).clone(), pod: (*pod).clone()})).into_ddvalue())
                                                                                                    }
                                                                                                    __f},
                                                                                                    next: Box::new(::std::option::Option::None)
                                                                                                }),
                                                               }))
               },
    }
});
pub static __Rule_IsPublic_1 : ::once_cell::sync::Lazy<program::Rule> = ::once_cell::sync::Lazy::new(|| {
    /* IsPublic[(IsPublic{.namespace=namespace, .pod=pod}: IsPublic)] :- IsPublic[(IsPublic{.namespace=(namespace: string), .pod=(ingPod: string)}: IsPublic)], IngressController[(IngressController{.namespace=(namespace: string), .name=(ingPod: string)}: IngressController)], Ingresses[(Ingresses{.namespace=(namespace: string), .name=(_: string), .controller=(ingPod: string), .serviceName=(svc: string)}: Ingresses)], Selectors[(Selectors{.k=(key: string), .v=(val: string), .ty=(Service{}: Object), .namespace=(namespace: string), .name=(svc: string)}: Selectors)], Labels[(Labels{.k=(key: string), .v=(val: string), .ty=(Pod{}: Object), .namespace=(namespace: string), .name=(pod: string)}: Labels)]. */
    ::differential_datalog::program::Rule::ArrangementRule {
        debug_info: ::ddlog_profiler::RuleDebugInfo::new(::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 41, 1, 47, 1)),
        arr: (2, 0),
        xform: XFormArrangement::Semijoin {
                   debug_info: ::ddlog_profiler::OperatorDebugInfo::semijoin(::std::borrow::Cow::Borrowed("IngressController"), ::std::borrow::Cow::Borrowed("(IngressController{.namespace=(_0: string), .name=(_1: string)}: IngressController)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 43, 3, 43, 39)),
                   ffun: None,
                   arrangement: (0,0),
                   jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, ___v2: &()) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                   {
                       let (ref namespace, ref ingPod) = match *unsafe { <IsPublic>::from_ddvalue_ref_unchecked(__v1) } {
                           IsPublic{namespace: ref namespace, pod: ref ingPod} => ((*namespace).clone(), (*ingPod).clone()),
                           _ => return ::std::option::Option::None
                       };
                       ::std::option::Option::Some((ddlog_std::tuple2((*namespace).clone(), (*ingPod).clone())).into_ddvalue())
                   }
                   __f},
                   next: Box::new(::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                                   debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(namespace, ingPod)"),::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 42, 3, 43, 39)),
                                                                   afun: {
                                                                       fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                                           ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                                       {
                                                                           let ddlog_std::tuple2(ref namespace, ref ingPod) = *unsafe { <ddlog_std::tuple2<String, String>>::from_ddvalue_ref_unchecked( &__v ) };
                                                                           ::core::option::Option::Some(((ddlog_std::tuple2((*namespace).clone(), (*ingPod).clone())).into_ddvalue(), ((*namespace).clone()).into_ddvalue()))
                                                                       }
                                                                       __ddlog_generated_arrangement_function
                                                                   },
                                                                   next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                                    debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("Ingresses"), ::std::borrow::Cow::Borrowed("(Ingresses{.namespace=(_0: string), .name=(_: string), .controller=(_1: string), .serviceName=(_: string)}: Ingresses)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 44, 3, 44, 39)),
                                                                                                    ffun: None,
                                                                                                    arrangement: (1,0),
                                                                                                    jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                                    {
                                                                                                        let ref namespace = *unsafe { <String>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                                        let ref svc = match *unsafe { <Ingresses>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                                            Ingresses{namespace: _, name: _, controller: _, serviceName: ref svc} => (*svc).clone(),
                                                                                                            _ => return ::std::option::Option::None
                                                                                                        };
                                                                                                        ::std::option::Option::Some((ddlog_std::tuple2((*svc).clone(), (*namespace).clone())).into_ddvalue())
                                                                                                    }
                                                                                                    __f},
                                                                                                    next: Box::new(::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                                                                                                                    debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(namespace, svc)"),::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 42, 3, 44, 39)),
                                                                                                                                                    afun: {
                                                                                                                                                        fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                                                                                                                            ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                                                                                                                        {
                                                                                                                                                            let ddlog_std::tuple2(ref svc, ref namespace) = *unsafe { <ddlog_std::tuple2<String, String>>::from_ddvalue_ref_unchecked( &__v ) };
                                                                                                                                                            ::core::option::Option::Some(((ddlog_std::tuple2((*namespace).clone(), (*svc).clone())).into_ddvalue(), ((*namespace).clone()).into_ddvalue()))
                                                                                                                                                        }
                                                                                                                                                        __ddlog_generated_arrangement_function
                                                                                                                                                    },
                                                                                                                                                    next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                                                                                                                     debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("Selectors"), ::std::borrow::Cow::Borrowed("(Selectors{.k=(_: string), .v=(_: string), .ty=(Service{}: Object), .namespace=(_0: string), .name=(_1: string)}: Selectors)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 45, 3, 45, 47)),
                                                                                                                                                                                     ffun: None,
                                                                                                                                                                                     arrangement: (9,0),
                                                                                                                                                                                     jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                                                                                                                     {
                                                                                                                                                                                         let ref namespace = *unsafe { <String>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                                                                                                                         let (ref key, ref val) = match *unsafe { <Selectors>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                                                                                                                             Selectors{k: ref key, v: ref val, ty: Object::Service{}, namespace: _, name: _} => ((*key).clone(), (*val).clone()),
                                                                                                                                                                                             _ => return ::std::option::Option::None
                                                                                                                                                                                         };
                                                                                                                                                                                         ::std::option::Option::Some((ddlog_std::tuple3((*key).clone(), (*val).clone(), (*namespace).clone())).into_ddvalue())
                                                                                                                                                                                     }
                                                                                                                                                                                     __f},
                                                                                                                                                                                     next: Box::new(::core::option::Option::Some(::differential_datalog::program::XFormCollection::Arrange {
                                                                                                                                                                                                                                     debug_info: ::ddlog_profiler::OperatorDebugInfo::arrange(::std::borrow::Cow::Borrowed("(key, val, namespace)"),::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 42, 3, 45, 47)),
                                                                                                                                                                                                                                     afun: {
                                                                                                                                                                                                                                         fn __ddlog_generated_arrangement_function(__v: ::differential_datalog::ddval::DDValue) ->
                                                                                                                                                                                                                                             ::core::option::Option<(::differential_datalog::ddval::DDValue, ::differential_datalog::ddval::DDValue)>
                                                                                                                                                                                                                                         {
                                                                                                                                                                                                                                             let ddlog_std::tuple3(ref key, ref val, ref namespace) = *unsafe { <ddlog_std::tuple3<String, String, String>>::from_ddvalue_ref_unchecked( &__v ) };
                                                                                                                                                                                                                                             ::core::option::Option::Some(((ddlog_std::tuple3((*key).clone(), (*val).clone(), (*namespace).clone())).into_ddvalue(), ((*namespace).clone()).into_ddvalue()))
                                                                                                                                                                                                                                         }
                                                                                                                                                                                                                                         __ddlog_generated_arrangement_function
                                                                                                                                                                                                                                     },
                                                                                                                                                                                                                                     next: ::std::boxed::Box::new(XFormArrangement::Join {
                                                                                                                                                                                                                                                                      debug_info: ::ddlog_profiler::OperatorDebugInfo::join(::std::borrow::Cow::Borrowed("Labels"), ::std::borrow::Cow::Borrowed("(Labels{.k=(_0: string), .v=(_1: string), .ty=(Pod{}: Object), .namespace=(_2: string), .name=(_: string)}: Labels)"), ::ddlog_profiler::SourcePosition::new_range("pallograph.dl", 46, 3, 46, 40)),
                                                                                                                                                                                                                                                                      ffun: None,
                                                                                                                                                                                                                                                                      arrangement: (3,0),
                                                                                                                                                                                                                                                                      jfun: {fn __f(_: &::differential_datalog::ddval::DDValue, __v1: &::differential_datalog::ddval::DDValue, __v2: &::differential_datalog::ddval::DDValue) -> ::std::option::Option<::differential_datalog::ddval::DDValue>
                                                                                                                                                                                                                                                                      {
                                                                                                                                                                                                                                                                          let ref namespace = *unsafe { <String>::from_ddvalue_ref_unchecked( __v1 ) };
                                                                                                                                                                                                                                                                          let ref pod = match *unsafe { <Labels>::from_ddvalue_ref_unchecked(__v2) } {
                                                                                                                                                                                                                                                                              Labels{k: _, v: _, ty: Object::Pod{}, namespace: _, name: ref pod} => (*pod).clone(),
                                                                                                                                                                                                                                                                              _ => return ::std::option::Option::None
                                                                                                                                                                                                                                                                          };
                                                                                                                                                                                                                                                                          ::std::option::Option::Some(((IsPublic{namespace: (*namespace).clone(), pod: (*pod).clone()})).into_ddvalue())
                                                                                                                                                                                                                                                                      }
                                                                                                                                                                                                                                                                      __f},
                                                                                                                                                                                                                                                                      next: Box::new(::std::option::Option::None)
                                                                                                                                                                                                                                                                  }),
                                                                                                                                                                                                                                 }))
                                                                                                                                                                                 }),
                                                                                                                                                }))
                                                                                                }),
                                                               }))
               },
    }
});