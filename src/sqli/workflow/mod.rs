//! SQL Injection Workflow Module
//!
//! Advanced attack chains and orchestration for complex scenarios.

pub mod stacked_detect;
pub mod second_order;
pub mod oob_listener;

use crate::sqli::{DatabaseType, SqliResult};

/// Workflow execution result
#[derive(Debug)]
pub struct WorkflowResult {
    pub name: String,
    pub success: bool,
    pub findings: Vec<SqliResult>,
    pub steps_completed: Vec<String>,
    pub errors: Vec<String>,
}

impl WorkflowResult {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            success: false,
            findings: Vec::new(),
            steps_completed: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn add_step(&mut self, step: &str) {
        self.steps_completed.push(step.to_string());
    }

    pub fn add_finding(&mut self, finding: SqliResult) {
        self.findings.push(finding);
    }

    pub fn add_error(&mut self, error: &str) {
        self.errors.push(error.to_string());
    }

    pub fn complete(&mut self) {
        self.success = !self.findings.is_empty();
    }
}

/// Configuration for workflow execution
#[derive(Debug, Clone)]
pub struct WorkflowConfig {
    /// Enable verbose logging
    pub verbose: bool,
    /// Maximum time per workflow (seconds)
    pub timeout: u64,
    /// Stop on first finding
    pub stop_on_first: bool,
    /// Database type hint (if known)
    pub db_hint: Option<DatabaseType>,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            verbose: false,
            timeout: 300, // 5 minutes
            stop_on_first: false,
            db_hint: None,
        }
    }
}

