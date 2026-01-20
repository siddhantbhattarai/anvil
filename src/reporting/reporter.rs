use crate::reporting::model::Finding;

#[derive(Default)]
pub struct Reporter {
    findings: Vec<Finding>,
}

impl Reporter {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}
