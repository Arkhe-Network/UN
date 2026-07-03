//! Tipos de erro unificados para arkhe-desci v0.2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DesciError {
    #[error("Plugin validation failed: {0}")]
    PluginValidation(String),
    #[error("Duplicate plugin id: {0}")]
    DuplicatePlugin(String),
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    #[error("PII detected: {0}")]
    PiiDetected(String),
    #[error("Content blocked: {category} — {reason}")]
    ContentBlocked { category: String, reason: String },
    #[error("Guardrail timeout after {0}s")]
    GuardrailTimeout(u64),
    #[error("Integrity violation: causal chain mismatch for trace {trace_id}")]
    ChainMismatch { trace_id: String },
    #[error("Duplicate step id: {0}")]
    DuplicateStep(String),
    #[error("Step not found: {0}")]
    StepNotFound(String),
    #[error("IPFS error: {0}")]
    IpfsError(String),
    #[error("WormGraph error: {0}")]
    WormGraphError(String),
    #[error("NodesDesci error: {0}")]
    NodesDesciError(String),
    #[error("Node not reachable: {url}")]
    NodeUnreachable { url: String },
    #[error("Dataset not found on node: {cid}")]
    DatasetNotFound { cid: String },
    #[error("ORCID error: {0}")]
    OrcidError(String),
    #[error("ORCID profile not found: {orcid_id}")]
    OrcidNotFound { orcid_id: String },
    #[error("DID resolution failed: {did}")]
    DidResolutionFailed { did: String },
    #[error("ORCID verification failed: {0}")]
    OrcidVerificationFailed(String),
    #[error("SEI contract error: {0}")]
    SeiError(String),
    #[error("Transaction failed: {tx_hash} — {reason}")]
    TxFailed { tx_hash: String, reason: String },
    #[error("Anchor not found: {cid}")]
    AnchorNotFound { cid: String },
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for DesciError {
    fn from(e: serde_json::Error) -> Self { Self::Serialization(e.to_string()) }
}
impl From<serde_yaml::Error> for DesciError {
    fn from(e: serde_yaml::Error) -> Self { Self::Serialization(e.to_string()) }
}
pub type Result<T> = std::result::Result<T, DesciError>;
