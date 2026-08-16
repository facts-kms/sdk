//! Public SDK facade for the Fact reference implementation.
//!
//! This crate intentionally depends on the lower-level protocol crates and not
//! on the CLI. The CLI should remain an adapter for argument parsing, terminal
//! I/O, and output formatting.

pub mod attestation;
pub mod commitment;
pub mod conformance;
pub mod decision;
pub mod delegation;
pub mod directory;
pub mod discussion;
pub mod environment;
pub mod identity;
pub mod invitation;
pub mod lifecycle;
pub mod models;
pub mod objects;
pub mod proposition;
pub mod provenance;
pub mod reference;
pub mod relationship;
pub mod runtime;
pub mod search;
pub mod settlement;
pub mod standing;
pub mod state;
pub mod sync;
pub mod tags;
pub mod validation;
pub mod workflow;

/// SDK result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type shared by SDK modules.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation: {0}")]
    Validation(String),
    #[error("schema: {0}")]
    Schema(#[from] fact_schema::Error),
    #[error("canonicalization: {0}")]
    Canonical(#[from] fact_canonical::Error),
    #[error("canonical Markdown: {0}")]
    Markdown(#[from] fact_canonical::MarkdownError),
    #[error("crypto: {0}")]
    Crypto(#[from] fact_crypto::Error),
    #[error("store: {0}")]
    Store(#[from] fact_store::Error),
    #[error("search: {0}")]
    Search(#[from] fact_search::Error),
    #[error("sync: {0}")]
    Sync(String),
    #[error("commitment: {0}")]
    Commitment(#[from] fact_commitment::Error),
    #[error("authorization: {0}")]
    Authorization(String),
    #[error("ledger is read-only until a local identity is recognized")]
    ReadOnlyLedger,
    #[error("missing object: {0}")]
    MissingObject(String),
    #[error("ambiguous reference: {0}")]
    AmbiguousReference(String),
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("projected: {0}")]
    Projected(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML decode: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("TOML encode: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("UUID: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("{0}")]
    Message(String),
}

impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Self::Message(value.to_owned())
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

impl From<fact_commitment::FrameError> for Error {
    fn from(value: fact_commitment::FrameError) -> Self {
        Self::Sync(value.to_string())
    }
}
