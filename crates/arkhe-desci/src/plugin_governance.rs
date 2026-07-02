//! Governança de plugins DeSciOS
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use crate::error::{DesciError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub signature: Option<String>,
    pub install_script: String,
    #[serde(default)]
    pub requested_permissions: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub author_did: Option<String>,
    #[serde(default)]
    pub node_desci_ref: Option<String>,
}

impl PluginManifest {
    pub fn from_yaml(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DesciError::PluginValidation(format!("read {}: {}", path, e)))?;
        serde_yaml::from_str(&content)
            .map_err(|e| DesciError::PluginValidation(format!("YAML parse: {}", e)))
    }
    pub fn from_json_str(s: &str) -> Result<Self> {
        serde_json::from_str(s)
            .map_err(|e| DesciError::PluginValidation(format!("JSON parse: {}", e)))
    }
    pub fn to_json_str(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| DesciError::Serialization(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub invariant_id: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub plugin_id: String,
    pub passed: bool,
    pub checks: Vec<ValidationCheck>,
    pub summary: String,
}

const DANGEROUS_PATTERNS: &[&str] = &[
    "/etc/passwd", "/etc/shadow", "/root/", "/var/run/",
    "sudo ", "sudo\n", "chmod 777", "chmod -R 777",
    "rm -rf /", "mkfs.", "dd if=/dev/zero",
    "> /dev/sd", ":(){ :|:& };:",
    "curl.*|\\s*(ba)?sh", "wget.*|\\s*(ba)?sh",
];

#[derive(Debug, Clone)]
pub struct PluginValidator {
    allowed_sources: HashSet<String>,
    required_signatures: bool,
    max_permissions: usize,
    dangerous_patterns: Vec<regex::Regex>,
}

impl Default for PluginValidator {
    fn default() -> Self {
        let dangerous_patterns: Vec<regex::Regex> = DANGEROUS_PATTERNS
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        Self {
            allowed_sources: [
                "https://github.com".into(),
                "https://gitlab.com".into(),
                "https://nodes.desci.com".into(),
            ].into_iter().collect(),
            required_signatures: false,
            max_permissions: 5,
            dangerous_patterns,
        }
    }
}

impl PluginValidator {
    pub fn new(allowed_sources: Vec<String>, required_signatures: bool, max_permissions: usize) -> Self {
        let dangerous_patterns: Vec<regex::Regex> = DANGEROUS_PATTERNS
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        Self {
            allowed_sources: allowed_sources.into_iter().collect(),
            required_signatures,
            max_permissions,
            dangerous_patterns,
        }
    }

    pub fn validate(&self, manifest: &PluginManifest) -> Result<ValidationResult> {
        let mut checks = Vec::new();
        let mut all_passed = true;

        let sig_ok = if self.required_signatures && manifest.signature.is_none() {
            all_passed = false; false
        } else { true };
        checks.push(ValidationCheck {
            invariant_id: "INV-001".into(), passed: sig_ok,
            message: if sig_ok { "Signature OK".into() } else { "Missing signature".into() },
        });

        let mut matched_dangerous = Vec::new();
        for re in &self.dangerous_patterns {
            if re.is_match(&manifest.install_script) {
                matched_dangerous.push(re.as_str().to_string());
            }
        }
        let danger_ok = matched_dangerous.is_empty();
        if !danger_ok { all_passed = false; }
        checks.push(ValidationCheck {
            invariant_id: "INV-002".into(), passed: danger_ok,
            message: if danger_ok { "No dangerous patterns".into() } else { format!("Dangerous: {}", matched_dangerous.join(", ")) },
        });

        let perm_ok = manifest.requested_permissions.len() <= self.max_permissions;
        if !perm_ok { all_passed = false; }
        checks.push(ValidationCheck {
            invariant_id: "INV-003".into(), passed: perm_ok,
            message: format!("{} permissions (max {})", manifest.requested_permissions.len(), self.max_permissions),
        });

        let source_ok = self.allowed_sources.is_empty() || self.allowed_sources.iter().any(|s| manifest.source.starts_with(s));
        if !source_ok { all_passed = false; }
        checks.push(ValidationCheck {
            invariant_id: "INV-004".into(), passed: source_ok,
            message: if source_ok { "Source allowed".into() } else { format!("Source '{}' not allowed", manifest.source) },
        });

        let checksum_ok = !self.required_signatures || manifest.checksum.is_some();
        if !checksum_ok { all_passed = false; }
        checks.push(ValidationCheck {
            invariant_id: "INV-005".into(), passed: checksum_ok,
            message: if checksum_ok { "Checksum present".into() } else { "Missing checksum".into() },
        });

        let summary = if all_passed { format!("Plugin '{}' validated ✓", manifest.name) } else {
            let failed: Vec<_> = checks.iter().filter(|c| !c.passed).map(|c| c.invariant_id.as_str()).collect();
            format!("Plugin '{}' FAILED: {}", manifest.name, failed.join(", "))
        };

        if all_passed { info!(plugin = %manifest.id, "Plugin validated"); } else { warn!(plugin = %manifest.id, "Plugin validation failed"); }

        Ok(ValidationResult { plugin_id: manifest.id.clone(), passed: all_passed, checks, summary })
    }
}
