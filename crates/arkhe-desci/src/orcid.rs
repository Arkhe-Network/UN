//! ORCID
use serde::{Deserialize, Serialize};
use crate::error::{DesciError, Result};

pub const DID_ORCID_PREFIX: &str = "did:arkhe:orcid";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrcidProfile { pub orcid_id: String, pub given_names: String, pub family_name: String, pub email: Option<String>, pub institution: Option<String>, pub country: Option<String>, pub works_count: u32, pub keywords: Vec<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrcidDID { pub did: String, pub orcid_id: String, pub did_document: DidDocument, pub verified: bool, pub verified_at: Option<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument { pub id: String, pub controller: Option<String>, #[serde(rename = "verificationMethod")] pub verification_methods: Vec<VerificationMethod>, pub service: Vec<DidService>, pub also_known_as: Vec<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod { pub id: String, #[serde(rename = "type")] pub vm_type: String, pub controller: String, pub public_key_multibase: Option<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService { pub id: String, #[serde(rename = "type")] pub service_type: String, pub service_endpoint: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrcidAttestation { pub attester_did: String, pub subject_did: String, pub orcid_id: String, pub claim_type: String, pub issued_at: String, pub expires_at: String, pub proof_hash: String }

#[cfg(feature = "orcid")]
pub struct OrcidClient { base_url: String, http: reqwest::Client }

#[cfg(feature = "orcid")]
impl OrcidClient {
    pub fn public() -> Self { Self { base_url: "https://pub.orcid.org/v3.0".into(), http: reqwest::Client::builder().default_headers({ let mut h = reqwest::header::HeaderMap::new(); h.insert("Accept", "application/json".parse().unwrap()); h }).build().unwrap() } }
    pub async fn get_profile(&self, orcid_id: &str) -> Result<OrcidProfile> {
        let clean_id = orcid_id.trim_start_matches("https://orcid.org/");
        let url = format!("{}/{}/record", self.base_url, clean_id);
        let resp = self.http.get(&url).send().await.map_err(|e| DesciError::OrcidError(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND { return Err(DesciError::OrcidNotFound { orcid_id: orcid_id.into() }); }
        let resp = resp.error_for_status().map_err(|e| DesciError::OrcidError(e.to_string()))?;
        let data: serde_json::Value = resp.json().await.map_err(|e| DesciError::OrcidError(e.to_string()))?;
        let name = &data["person"]["name"];
        Ok(OrcidProfile {
            orcid_id: clean_id.into(),
            given_names: name["given-names"]["value"].as_str().unwrap_or("").into(),
            family_name: name["family-name"]["value"].as_str().unwrap_or("").into(),
            email: None,
            institution: data["employment-summary"].get(0).and_then(|v| v.get("organization")).and_then(|v| v.get("name")).and_then(|v| v.as_str()).map(String::from),
            country: data["address"]["country"]["value"].as_str().map(String::from),
            works_count: data["activities-summary"]["works"]["group"].as_array().map(|a| a.len() as u32).unwrap_or(0),
            keywords: data["keywords"]["keyword"].as_array().map(|a| a.iter().filter_map(|k| k["content"].as_str().map(String::from)).collect()).unwrap_or_default(),
        })
    }
}

pub fn derive_did(orcid_id: &str) -> String {
    let clean = orcid_id.trim_start_matches("https://orcid.org/").replace('-', "");
    let hash = blake3::hash(clean.as_bytes()).to_string()[..16].to_string();
    format!("{}:{}", DID_ORCID_PREFIX, hash)
}

pub fn build_did_document(orcid_id: &str) -> OrcidDID {
    let did = derive_did(orcid_id);
    let vm_id = format!("{}#key-1", did);
    OrcidDID {
        did: did.clone(), orcid_id: orcid_id.trim_start_matches("https://orcid.org/").into(),
        did_document: DidDocument {
            id: did.clone(), controller: Some(did.clone()),
            verification_methods: vec![VerificationMethod { id: vm_id, vm_type: "Ed25519VerificationKey2020".into(), controller: did.clone(), public_key_multibase: None }],
            service: vec![DidService { id: format!("{}#orcid", did), service_type: "OrcidProfile".into(), service_endpoint: format!("https://orcid.org/{}", orcid_id) }, DidService { id: format!("{}#desci", did), service_type: "DesciNode".into(), service_endpoint: "https://nodes.desci.com".into() }],
            also_known_as: vec![format!("https://orcid.org/{}", orcid_id)],
        },
        verified: false, verified_at: None,
    }
}

pub fn create_attestation(attester_did: &str, subject_did: &str, orcid_id: &str, valid_hours: u64) -> OrcidAttestation {
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(valid_hours as i64);
    let claim = format!("{}:{}:{}:{}", attester_did, subject_did, orcid_id, now.timestamp());
    let proof_hash = blake3::hash(claim.as_bytes()).to_string();
    OrcidAttestation { attester_did: attester_did.into(), subject_did: subject_did.into(), orcid_id: orcid_id.into(), claim_type: "OrcidOwnership".into(), issued_at: now.to_rfc3339(), expires_at: expires.to_rfc3339(), proof_hash }
}

pub fn verify_attestation(att: &OrcidAttestation) -> bool {
    let claim = format!("{}:{}:{}:{}", att.attester_did, att.subject_did, att.orcid_id, chrono::DateTime::parse_from_rfc3339(&att.issued_at).map(|dt| dt.timestamp()).unwrap_or(0));
    let expected = blake3::hash(claim.as_bytes()).to_string();
    if att.proof_hash != expected { return false; }
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&att.expires_at) { if chrono::Utc::now() > exp.with_timezone(&chrono::Utc) { return false; } }
    true
}
