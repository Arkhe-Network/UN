//! Publishing
use serde::{Deserialize, Serialize};
use tracing::info;
use crate::error::{DesciError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetMetadata { pub name: String, pub description: String, pub format: String, pub version: String, pub author_did: String, pub orcid_id: Option<String>, pub license: String, pub tags: Vec<String>, pub created_at: String, pub checksum_sha256: String, pub trace_id: Option<String>, pub node_desci_url: Option<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsPublishResult { pub cid: String, pub gateway_url: String, pub size_bytes: u64 }

#[cfg(feature = "ipfs")]
pub struct IpfsClient { api_url: String, gateway_url: String, http: reqwest::Client }

#[cfg(feature = "ipfs")]
impl IpfsClient {
    pub fn local() -> Self { Self { api_url: "http://127.0.0.1:5001/api/v0".into(), gateway_url: "http://127.0.0.1:8080/ipfs".into(), http: reqwest::Client::new() } }
    pub async fn add_bytes(&self, data: &[u8], filename: &str) -> Result<IpfsPublishResult> {
        let form = reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(data.to_vec()).file_name(filename.to_string()));
        let resp = self.http.post(format!("{}/add", self.api_url)).multipart(form).send().await.map_err(|e| DesciError::IpfsError(e.to_string()))?.error_for_status().map_err(|e| DesciError::IpfsError(e.to_string()))?.json::<serde_json::Value>().await.map_err(|e| DesciError::IpfsError(e.to_string()))?;
        let cid = resp["Hash"].as_str().ok_or_else(|| DesciError::IpfsError("No CID".into()))?.to_string();
        let size = resp["Size"].as_u64().unwrap_or(data.len() as u64);
        Ok(IpfsPublishResult { cid: cid.clone(), gateway_url: format!("{}/{}", self.gateway_url, cid), size_bytes: size })
    }
}

pub struct WormGraphNotifier { endpoint: String }
impl WormGraphNotifier {
    pub fn new(endpoint: &str) -> Self { Self { endpoint: endpoint.into() } }
    pub async fn notify_publication(&self, cid: &str, metadata: &DatasetMetadata) -> Result<String> {
        let notif_id = blake3::hash(format!("{}:{}:{}", cid, metadata.name, chrono::Utc::now().timestamp_millis()).as_bytes()).to_string();
        info!(notif_id = %notif_id, cid = %cid, dataset = %metadata.name, "WormGraph notification sent (stub)");
        Ok(notif_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResult { pub cid: String, pub gateway_url: String, pub size_bytes: u64, pub notification_id: String, pub metadata: DatasetMetadata }

#[cfg(feature = "ipfs")]
pub struct DeSciPublisher { ipfs: IpfsClient, wormgraph: WormGraphNotifier }

#[cfg(feature = "ipfs")]
impl DeSciPublisher {
    pub fn local() -> Self { Self { ipfs: IpfsClient::local(), wormgraph: WormGraphNotifier::new("http://localhost:50051") } }
    pub async fn publish_bytes(&self, data: &[u8], filename: &str, metadata: DatasetMetadata) -> Result<PublishResult> {
        let ipfs_r = self.ipfs.add_bytes(data, filename).await?;
        let notif_id = self.wormgraph.notify_publication(&ipfs_r.cid, &metadata).await?;
        Ok(PublishResult { cid: ipfs_r.cid, gateway_url: ipfs_r.gateway_url, size_bytes: ipfs_r.size_bytes, notification_id: notif_id, metadata })
    }
}
