//! SEI GigaChain
use serde::{Deserialize, Serialize};
use tracing::info;
use crate::error::{DesciError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorMsg { pub cid: String, pub checksum_sha256: String, pub author_did: String, pub orcid_id: Option<String>, pub trace_id: Option<String>, pub metadata_uri: Option<String>, pub license: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterIdentityMsg { pub did: String, pub orcid_id: Option<String>, pub controller: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorInfo { pub cid: String, pub owner: String, pub author_did: String, pub orcid_id: Option<String>, pub trace_id: Option<String>, pub checksum_sha256: String, pub anchored_at: u64, pub block_height: u64, pub tx_hash: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo { pub did: String, pub orcid_id: Option<String>, pub controller: String, pub anchor_count: u64, pub registered_at: u64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorEvent { pub event_type: String, pub cid: String, pub author_did: String, pub block_height: u64, pub tx_hash: String }

#[cfg(feature = "sei-giga")]
pub struct SeiGigaClient { chain_id: String, contract_address: String, rpc_url: String, http: reqwest::Client }

#[cfg(feature = "sei-giga")]
impl SeiGigaClient {
    pub fn new(chain_id: &str, contract_address: &str, rpc_url: &str) -> Self { Self { chain_id: chain_id.into(), contract_address: contract_address.into(), rpc_url: rpc_url.into(), http: reqwest::Client::new() } }
    pub async fn anchor_dataset(&self, msg: &AnchorMsg) -> Result<AnchorEvent> {
        info!(cid = %msg.cid, did = %msg.author_did, "Anchoring dataset on SEI (stub)");
        Ok(AnchorEvent { event_type: "wasm-anchor".into(), cid: msg.cid.clone(), author_did: msg.author_did.clone(), block_height: 0, tx_hash: format!("0x{}", blake3::hash(msg.cid.as_bytes()).to_string()[..16].to_string()) })
    }
}

pub fn compute_anchor_hash(msg: &AnchorMsg) -> String {
    let payload = format!("{}:{}:{}:{}:{}", msg.cid, msg.checksum_sha256, msg.author_did, msg.orcid_id.as_deref().unwrap_or(""), msg.license);
    blake3::hash(payload.as_bytes()).to_string()
}
