//! Error type for CEL parsing and CEL->Z3 translation.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CelZ3Error {
    /// The CEL source failed to parse.
    #[error("CEL parse error: {0}")]
    Parse(String),

    /// An identifier path was used that the caller never declared in the `Env`.
    #[error("unknown identifier: {0}")]
    UnknownIdentifier(String),

    /// Operand/literal sorts did not line up (e.g. comparing a String to an Int).
    #[error("type mismatch in {context}: expected {expected}, found {found}")]
    TypeMismatch {
        expected: String,
        found: String,
        context: String,
    },

    /// A CEL construct we deliberately do not translate yet.
    #[error("unsupported CEL construct: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, CelZ3Error>;
