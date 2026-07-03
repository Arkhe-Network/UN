//! Rastreabilidade
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::info;
use crate::error::{DesciError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepId(String);
impl StepId { pub fn new(id: impl Into<String>) -> Self { Self(id.into()) } pub fn as_str(&self) -> &str { &self.0 } }
impl std::fmt::Display for StepId { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus { Pending, Running, Completed, Failed { error: String }, Skipped { reason: String } }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep { pub id: StepId, pub name: String, pub tool: String, pub status: StepStatus, pub parameters: serde_json::Value, pub inputs: Vec<String>, pub outputs: Vec<String>, pub started_at: Option<DateTime<Utc>>, pub completed_at: Option<DateTime<Utc>>, pub hash: Option<String>, pub agent_did: Option<String> }

impl WorkflowStep {
    pub fn new(id: impl Into<String>, name: &str, tool: &str) -> Self {
        Self { id: StepId::new(id), name: name.into(), tool: tool.into(), status: StepStatus::Pending, parameters: serde_json::Value::Object(serde_json::Map::new()), inputs: Vec::new(), outputs: Vec::new(), started_at: None, completed_at: None, hash: None, agent_did: None }
    }
    pub fn with_parameters(mut self, params: serde_json::Value) -> Self { self.parameters = params; self }
    pub fn with_inputs(mut self, inputs: Vec<String>) -> Self { self.inputs = inputs; self }
    pub fn with_agent(mut self, did: &str) -> Self { self.agent_did = Some(did.into()); self }
    pub fn start(&mut self) { self.status = StepStatus::Running; self.started_at = Some(Utc::now()); }
    pub fn complete(&mut self, outputs: Vec<String>) { self.status = StepStatus::Completed; self.outputs = outputs; self.completed_at = Some(Utc::now()); }
    pub fn fail(&mut self, err: impl Into<String>) { self.status = StepStatus::Failed { error: err.into() }; self.completed_at = Some(Utc::now()); }
    pub fn compute_hash(&self) -> String {
        let mut map = BTreeMap::new();
        map.insert("id", serde_json::Value::String(self.id.0.clone()));
        map.insert("name", serde_json::Value::String(self.name.clone()));
        map.insert("tool", serde_json::Value::String(self.tool.clone()));
        map.insert("parameters", self.parameters.clone());
        map.insert("inputs", serde_json::to_value(&self.inputs).unwrap_or_default());
        map.insert("outputs", serde_json::to_value(&self.outputs).unwrap_or_default());
        if let Some(ref did) = self.agent_did { map.insert("agent_did", serde_json::Value::String(did.clone())); }
        let canonical = serde_json::to_string(&map).unwrap_or_default();
        blake3::hash(canonical.as_bytes()).to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowType { Nextflow, Jupyter, Snakemake, Custom(String) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScientificWorkflowTrace { pub trace_id: String, pub workflow_name: String, pub workflow_type: WorkflowType, pub steps: Vec<WorkflowStep>, pub created_at: DateTime<Utc>, pub updated_at: DateTime<Utc>, pub causal_chain: String, pub metadata: BTreeMap<String, String>, pub owner_did: Option<String> }

impl ScientificWorkflowTrace {
    pub fn new(name: &str, wtype: WorkflowType) -> Self {
        let trace_id = blake3::hash(format!("{}:{}", name, Utc::now().timestamp_millis()).as_bytes()).to_string();
        let now = Utc::now();
        Self { trace_id, workflow_name: name.into(), workflow_type: wtype, steps: Vec::new(), created_at: now, updated_at: now, causal_chain: String::new(), metadata: BTreeMap::new(), owner_did: None }
    }
    pub fn with_owner(mut self, did: &str) -> Self { self.owner_did = Some(did.into()); self }
    pub fn with_metadata(mut self, k: &str, v: &str) -> Self { self.metadata.insert(k.into(), v.into()); self }
    pub fn add_step(&mut self, mut step: WorkflowStep) -> Result<()> {
        if self.steps.iter().any(|s| s.id == step.id) { return Err(DesciError::DuplicateStep(step.id.to_string())); }
        step.hash = Some(step.compute_hash());
        self.steps.push(step);
        self.recompute_chain();
        self.updated_at = Utc::now();
        Ok(())
    }
    fn recompute_chain(&mut self) {
        let mut chain = format!("{}:{}", self.trace_id, self.workflow_name);
        for step in &self.steps {
            let sh = step.hash.as_deref().unwrap_or("");
            chain = blake3::hash(format!("{}:{}", chain, sh).as_bytes()).to_string();
        }
        self.causal_chain = chain;
    }
    pub fn verify(&self) -> bool {
        let mut chain = format!("{}:{}", self.trace_id, self.workflow_name);
        for step in &self.steps {
            let expected = step.compute_hash();
            if step.hash.as_deref() != Some(&expected) { info!(step = %step.id, "Hash mismatch"); return false; }
            chain = blake3::hash(format!("{}:{}", chain, step.hash.as_deref().unwrap_or("")).as_bytes()).to_string();
        }
        if chain != self.causal_chain { info!("Causal chain mismatch"); return false; }
        true
    }
    pub fn total_count(&self) -> usize { self.steps.len() }
    pub fn completed_count(&self) -> usize { self.steps.iter().filter(|s| matches!(s.status, StepStatus::Completed)).count() }
}
