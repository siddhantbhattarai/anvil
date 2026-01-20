use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PayloadSet {
    pub name: String,
    pub payloads: Vec<String>,
}

pub fn load_payloads<P: AsRef<Path>>(path: P) -> anyhow::Result<PayloadSet> {
    let content = fs::read_to_string(&path)?;
    let payloads = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();

    let name = path
        .as_ref()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    Ok(PayloadSet { name, payloads })
}
