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


pub static __STATIC_3: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"DoesNotExist"###));
pub static __STATIC_2: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"Exists"###));
pub static __STATIC_0: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"In"###));
pub static __STATIC_1: ::once_cell::sync::Lazy<String> = ::once_cell::sync::Lazy::new(|| String::from(r###"NotIn"###));
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "selectors::LabelSelector")]
pub struct LabelSelector {
    pub matchLabels: ddlog_std::Map<String, String>,
    pub matchExpressions: ddlog_std::Vec<ddlog_std::Ref<LabelSelectorRequirement>>
}
impl abomonation::Abomonation for LabelSelector{}
impl ::std::fmt::Display for LabelSelector {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            LabelSelector{matchLabels,matchExpressions} => {
                __formatter.write_str("selectors::LabelSelector{")?;
                ::std::fmt::Debug::fmt(matchLabels, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(matchExpressions, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for LabelSelector {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "selectors::LabelSelectorOperator")]
pub enum LabelSelectorOperator {
    #[ddlog(rename = "selectors::LabelSelectorOpIn")]
    LabelSelectorOpIn,
    #[ddlog(rename = "selectors::LabelSelectorOpNotIn")]
    LabelSelectorOpNotIn,
    #[ddlog(rename = "selectors::LabelSelectorOpExists")]
    LabelSelectorOpExists,
    #[ddlog(rename = "selectors::LabelSelectorOpDoesNotExist")]
    LabelSelectorOpDoesNotExist
}
impl abomonation::Abomonation for LabelSelectorOperator{}
impl ::std::fmt::Display for LabelSelectorOperator {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            LabelSelectorOperator::LabelSelectorOpIn{} => {
                __formatter.write_str("selectors::LabelSelectorOpIn{")?;
                __formatter.write_str("}")
            },
            LabelSelectorOperator::LabelSelectorOpNotIn{} => {
                __formatter.write_str("selectors::LabelSelectorOpNotIn{")?;
                __formatter.write_str("}")
            },
            LabelSelectorOperator::LabelSelectorOpExists{} => {
                __formatter.write_str("selectors::LabelSelectorOpExists{")?;
                __formatter.write_str("}")
            },
            LabelSelectorOperator::LabelSelectorOpDoesNotExist{} => {
                __formatter.write_str("selectors::LabelSelectorOpDoesNotExist{")?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for LabelSelectorOperator {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
impl ::std::default::Default for LabelSelectorOperator {
    fn default() -> Self {
        LabelSelectorOperator::LabelSelectorOpIn{}
    }
}
#[derive(Eq, Ord, Clone, Hash, PartialEq, PartialOrd, IntoRecord, Mutator, Default, Serialize, Deserialize, FromRecord)]
#[ddlog(rename = "selectors::LabelSelectorRequirement")]
pub struct LabelSelectorRequirement {
    pub reqkey: String,
    pub operator: LabelSelectorOperator,
    pub values: ddlog_std::Vec<String>
}
impl abomonation::Abomonation for LabelSelectorRequirement{}
impl ::std::fmt::Display for LabelSelectorRequirement {
    fn fmt(&self, __formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            LabelSelectorRequirement{reqkey,operator,values} => {
                __formatter.write_str("selectors::LabelSelectorRequirement{")?;
                differential_datalog::record::format_ddlog_str(reqkey, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(operator, __formatter)?;
                __formatter.write_str(",")?;
                ::std::fmt::Debug::fmt(values, __formatter)?;
                __formatter.write_str("}")
            }
        }
    }
}
impl ::std::fmt::Debug for LabelSelectorRequirement {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}
pub fn labelSelectorMatches(selector: & ddlog_std::Option<ddlog_std::Ref<LabelSelector>>, labels: & ddlog_std::Map<String, String>) -> bool
{   match (*selector) {
        ddlog_std::Option::None{} => false,
        ddlog_std::Option::Some{x: ref sel} => if (ddlog_std::map_is_empty((&sel.matchLabels)) && ddlog_std::vec_is_empty((&sel.matchExpressions))) {
                                                   true
                                               } else {
                                                   {
                                                       for ref lab in sel.matchLabels.iter() {
                                                           if ((&*(&ddlog_std::map_get(labels, (&(lab.0))))) != (&*(&(ddlog_std::Option::Some{x: (lab.1).clone()})))) {
                                                               return false
                                                           } else {
                                                               ()
                                                           }
                                                       };
                                                       for e in sel.matchExpressions.iter() {
                                                           {
                                                               let ref mut matches: bool = match e.operator {
                                                                                               LabelSelectorOperator::LabelSelectorOpIn{} => match ddlog_std::map_get(labels, (&e.reqkey)) {
                                                                                                                                                 ddlog_std::Option::None{} => false,
                                                                                                                                                 ddlog_std::Option::Some{x: ref val} => ddlog_std::vec_contains((&e.values), val)
                                                                                                                                             },
                                                                                               LabelSelectorOperator::LabelSelectorOpNotIn{} => match ddlog_std::map_get(labels, (&e.reqkey)) {
                                                                                                                                                    ddlog_std::Option::None{} => true,
                                                                                                                                                    ddlog_std::Option::Some{x: ref val} => (!ddlog_std::vec_contains((&e.values), val))
                                                                                                                                                },
                                                                                               LabelSelectorOperator::LabelSelectorOpExists{} => ddlog_std::map_contains_key(labels, (&e.reqkey)),
                                                                                               LabelSelectorOperator::LabelSelectorOpDoesNotExist{} => (!ddlog_std::map_contains_key(labels, (&e.reqkey)))
                                                                                           };
                                                               if (!(*matches).clone()) {
                                                                   return false
                                                               } else {
                                                                   ()
                                                               }
                                                           }
                                                       };
                                                       true
                                                   }
                                               }
    }
}
pub fn to_string(op: & LabelSelectorOperator) -> String
{   (*match (*op) {
          LabelSelectorOperator::LabelSelectorOpIn{} => (&*crate::__STATIC_0),
          LabelSelectorOperator::LabelSelectorOpNotIn{} => (&*crate::__STATIC_1),
          LabelSelectorOperator::LabelSelectorOpExists{} => (&*crate::__STATIC_2),
          LabelSelectorOperator::LabelSelectorOpDoesNotExist{} => (&*crate::__STATIC_3)
      }).clone()
}