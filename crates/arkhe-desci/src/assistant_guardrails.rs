//! Guardrails
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PiiType { Email, PhoneNumber, Cpf, CreditCard, Ssn, IpAddress, Passport, BankAccount, Custom(String) }

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Email => write!(f, "email"), Self::PhoneNumber => write!(f, "phone"),
            Self::Cpf => write!(f, "cpf"), Self::CreditCard => write!(f, "credit_card"),
            Self::Ssn => write!(f, "ssn"), Self::IpAddress => write!(f, "ip"),
            Self::Passport => write!(f, "passport"), Self::BankAccount => write!(f, "bank_account"),
            Self::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction { pub pii_type: PiiType, pub start: usize, pub end: usize, pub original: String, pub masked: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiCheckResult { pub masked_text: String, pub redactions: Vec<Redaction>, pub has_pii: bool }

pub struct PiiMasker { patterns: Vec<(PiiType, regex::Regex, String)> }
impl PiiMasker {
    pub fn new() -> Self {
        let patterns = vec![
            (PiiType::Email, regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(), "[EMAIL]".into()),
            (PiiType::Cpf, regex::Regex::new(r"\b\d{3}[.]?\d{3}[.]?\d{3}[-]?\d{2}\b").unwrap(), "[CPF]".into()),
            (PiiType::PhoneNumber, regex::Regex::new(r"\(?\d{2}\)?\s?\d{4,5}[-.]?\d{4}").unwrap(), "[PHONE]".into()),
            (PiiType::CreditCard, regex::Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap(), "[CC]".into()),
            (PiiType::IpAddress, regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(), "[IP]".into()),
            (PiiType::Ssn, regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(), "[SSN]".into()),
        ];
        Self { patterns }
    }
    pub fn mask(&self, text: &str) -> PiiCheckResult {
        let mut all_matches = Vec::new();
        for (pii_type, re, replacement) in &self.patterns {
            for mat in re.find_iter(text) {
                all_matches.push((mat.start(), mat.end(), pii_type, replacement.as_str()));
            }
        }
        all_matches.sort_by(|a, b| b.0.cmp(&a.0));
        let mut masked = text.to_string();
        let mut redactions = Vec::new();
        for (start, end, pii_type, replacement) in all_matches {
            let original = text[start..end].to_string();
            masked = format!("{}{}{}", &masked[..start], replacement, &masked[end..]);
            redactions.push(Redaction { pii_type: pii_type.clone(), start, end, original, masked: replacement.to_string() });
        }
        redactions.reverse();
        PiiCheckResult { has_pii: !redactions.is_empty(), masked_text: masked, redactions }
    }
}
impl Default for PiiMasker { fn default() -> Self { Self::new() } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GuardrailCategory { HarmfulContent, SystemExploitation, UnauthorizedAccess, PiiExfiltration, DataDestruction, Custom(String) }

impl std::fmt::Display for GuardrailCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HarmfulContent => write!(f, "harmful_content"), Self::SystemExploitation => write!(f, "system_exploitation"),
            Self::UnauthorizedAccess => write!(f, "unauthorized_access"), Self::PiiExfiltration => write!(f, "pii_exfiltration"),
            Self::DataDestruction => write!(f, "data_destruction"), Self::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailCheckResult { pub safe: bool, pub category: Option<GuardrailCategory>, pub reason: Option<String>, pub risk_score: f32 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantContext { pub user_id: String, pub session_id: String, pub timestamp: String, pub active_tools: Vec<String>, pub workspace_path: String }
impl Default for AssistantContext {
    fn default() -> Self {
        Self { user_id: "anonymous".into(), session_id: format!("ses-{}", blake3::hash(&chrono::Utc::now().timestamp_millis().to_le_bytes()).to_string()[..8].to_string()), timestamp: chrono::Utc::now().to_rfc3339(), active_tools: Vec::new(), workspace_path: "/home/deScier".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailConfig { pub pii_masking_enabled: bool, pub content_check_enabled: bool, pub risk_threshold: f32, pub blocked_patterns: Vec<String>, pub timeout_seconds: u64 }
impl Default for GuardrailConfig {
    fn default() -> Self {
        Self { pii_masking_enabled: true, content_check_enabled: true, risk_threshold: 0.7, blocked_patterns: vec![r"rm\s+-rf\s+/".into(), r"mkfs\.".into(), r"dd\s+if=/dev/zero".into(), r">\s*/dev/sd".into(), r"chmod\s+777\s+/".into(), r"curl.*\|\s*(ba)?sh".into(), r"wget.*\|\s*(ba)?sh".into(), r":\(\)\s*\{".into()], timeout_seconds: 10 }
    }
}

pub struct DeSciAssistantGuardrails { config: GuardrailConfig, pii_masker: PiiMasker, blocked_regexes: Vec<regex::Regex>, risk_indicators: Vec<(&'static str, f32)>, sci_context: Vec<&'static str> }
impl DeSciAssistantGuardrails {
    pub fn new() -> Self { Self::with_config(GuardrailConfig::default()) }
    pub fn with_config(config: GuardrailConfig) -> Self {
        let blocked_regexes = config.blocked_patterns.iter().filter_map(|p| regex::Regex::new(p).ok()).collect();
        Self { pii_masker: PiiMasker::new(), blocked_regexes, risk_indicators: vec![("delete all", 0.8), ("drop table", 0.9), ("format disk", 0.9), ("overwrite", 0.4), ("bypass", 0.5), ("sudo", 0.3), ("password", 0.2), ("secret", 0.3), ("api key", 0.4), ("credential", 0.4), ("private key", 0.6)], sci_context: vec!["gene", "protein", "sequence", "alignment", "blast", "genome", "transcript", "expression", "pathway", "jupyter", "notebook", "analysis", "dataset", "variant", "mutation", "phylotree"], config }
    }
    pub fn check_message(&self, message: &str, _context: &AssistantContext) -> Result<(String, GuardrailCheckResult)> {
        for re in &self.blocked_regexes {
            if re.is_match(message) {
                warn!(pattern = %re.as_str(), "Blocked pattern");
                return Ok(("[CONTENT_BLOCKED]".into(), GuardrailCheckResult { safe: false, category: Some(GuardrailCategory::SystemExploitation), reason: Some("Matches blocked pattern".into()), risk_score: 1.0 }));
            }
        }
        let processed = if self.config.pii_masking_enabled {
            let result = self.pii_masker.mask(message);
            if result.has_pii { info!(count = result.redactions.len(), "PII masked"); }
            result.masked_text
        } else { message.to_string() };
        let risk = self.compute_local_risk(&processed);
        let check = if risk >= self.config.risk_threshold {
            GuardrailCheckResult { safe: false, category: Some(GuardrailCategory::HarmfulContent), reason: Some(format!("Risk {:.2} >= threshold {:.2}", risk, self.config.risk_threshold)), risk_score: risk }
        } else {
            GuardrailCheckResult { safe: true, category: None, reason: None, risk_score: risk }
        };
        Ok((processed, check))
    }
    pub fn check_url(&self, url: &str) -> Result<GuardrailCheckResult> {
        let host_and_port = url.trim_start_matches("http://").trim_start_matches("https://").split('/').next().unwrap_or("");
        let host = if host_and_port.starts_with("[") {
            let mut h = host_and_port.split(']').next().unwrap_or("").to_string();
            h.remove(0);
            h
        } else {
            host_and_port.split(':').next().unwrap_or("").to_string()
        };
        let blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
        if blocked_hosts.contains(&host.as_str()) {
            return Ok(GuardrailCheckResult { safe: false, category: Some(GuardrailCategory::UnauthorizedAccess), reason: Some("Internal URL blocked (SSRF)".into()), risk_score: 1.0 });
        }
        if let Ok(addr) = host.parse::<IpAddr>() {
            if is_private_ip(&addr) {
                return Ok(GuardrailCheckResult { safe: false, category: Some(GuardrailCategory::UnauthorizedAccess), reason: Some("Private IP blocked".into()), risk_score: 1.0 });
            }
        }
        Ok(GuardrailCheckResult { safe: true, category: None, reason: None, risk_score: 0.0 })
    }
    fn compute_local_risk(&self, text: &str) -> f32 {
        let lower = text.to_lowercase();
        let mut score: f32 = 0.0;
        for (indicator, weight) in &self.risk_indicators {
            if lower.contains(indicator) { score = score.max(*weight); }
        }
        let sci_hits = self.sci_context.iter().filter(|s| lower.contains(*s)).count();
        if sci_hits > 0 { score *= 0.5; }
        score.min(1.0)
    }
}
impl Default for DeSciAssistantGuardrails { fn default() -> Self { Self::new() } }
fn is_private_ip(addr: &IpAddr) -> bool { match addr { IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(), IpAddr::V6(v6) => v6.is_loopback(), } }
