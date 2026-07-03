//! Nodes
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use crate::error::{DesciError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo { pub node_id: String, pub url: String, pub name: String, pub region: String, pub status: NodeStatus, pub capabilities: Vec<String>, pub datasets_count: u64, pub last_seen: String, pub owner_did: Option<String>, #[serde(default)] pub metadata: serde_json::Value }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeStatus { Online, Offline, Degraded, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDataset { pub cid: String, pub name: String, pub format: String, pub size_bytes: u64, pub uploaded_by: String, pub uploaded_at: String, pub metadata: serde_json::Value, pub trace_id: Option<String>, pub orcid_id: Option<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSearchResult { pub node_id: String, pub node_url: String, pub datasets: Vec<NodeDataset>, pub total_matching: u64 }

#[cfg(feature = "ipfs")]
pub struct NodesDesciClient { base_url: String, http: reqwest::Client }

#[cfg(feature = "ipfs")]
impl NodesDesciClient {
    pub fn new(base_url: &str) -> Self { Self { base_url: base_url.trim_end_matches('/').to_string(), http: reqwest::Client::new() } }
    pub async fn healthcheck(&self) -> Result<NodeInfo> {
        let url = format!("{}/api/v1/health", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|_| DesciError::NodeUnreachable { url: self.base_url.clone() })?.error_for_status().map_err(|e| DesciError::NodesDesciError(e.to_string()))?;
        let mut info: NodeInfo = resp.json().await.map_err(|e| DesciError::NodesDesciError(e.to_string()))?;
        info.status = NodeStatus::Online;
        Ok(info)
    }
}
