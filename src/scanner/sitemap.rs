use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize)]
pub struct Endpoint {
    pub path: String,
    pub methods: HashSet<String>,
    pub parameters: HashSet<String>,
}

#[derive(Debug, Serialize)]
pub struct SiteMap {
    pub base: String,
    pub endpoints: HashMap<String, Endpoint>,
}

impl SiteMap {
    pub fn new(base: String) -> Self {
        Self {
            base,
            endpoints: HashMap::new(),
        }
    }

    pub fn add_endpoint(
        &mut self,
        path: String,
        method: &str,
        params: Vec<String>,
    ) {
        let entry = self.endpoints.entry(path.clone()).or_insert(
            Endpoint {
                path,
                methods: HashSet::new(),
                parameters: HashSet::new(),
            },
        );

        entry.methods.insert(method.to_string());
        for p in params {
            entry.parameters.insert(p);
        }
    }
}
