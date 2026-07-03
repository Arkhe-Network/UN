//! ARKHE
pub mod error;
pub mod plugin_governance;
pub mod assistant_guardrails;
pub mod workflow_traceability;
pub mod publishing;
pub mod nodes_desci;
pub mod orcid;
pub mod sei_giga;

pub use error::{DesciError, Result};
pub use plugin_governance::{PluginValidator, PluginManifest, ValidationResult, ValidationCheck};
pub use assistant_guardrails::{DeSciAssistantGuardrails, AssistantContext, GuardrailConfig, GuardrailCheckResult, GuardrailCategory, PiiMasker, PiiCheckResult, Redaction, PiiType};
pub use workflow_traceability::{ScientificWorkflowTrace, WorkflowStep, WorkflowType, StepId, StepStatus};
pub use publishing::{DatasetMetadata, IpfsPublishResult, PublishResult, WormGraphNotifier};
#[cfg(feature = "ipfs")]
pub use publishing::{IpfsClient, DeSciPublisher};
pub use nodes_desci::{NodeInfo, NodeStatus, NodeDataset, NodeSearchResult};
#[cfg(feature = "ipfs")]
pub use nodes_desci::NodesDesciClient;
pub use orcid::{OrcidProfile, OrcidDID, DidDocument, OrcidAttestation, derive_did, build_did_document, create_attestation, verify_attestation, DID_ORCID_PREFIX};
#[cfg(feature = "orcid")]
pub use orcid::OrcidClient;
pub use sei_giga::{AnchorMsg, RegisterIdentityMsg, AnchorInfo, IdentityInfo, AnchorEvent, compute_anchor_hash};
#[cfg(feature = "sei-giga")]
pub use sei_giga::SeiGigaClient;
