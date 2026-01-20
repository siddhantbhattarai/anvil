use url::Url;

#[derive(Debug, Clone)]
pub struct Scope {
    allowed_hosts: Vec<String>,
}

impl Scope {
    pub fn new(target: &str) -> anyhow::Result<Self> {
        let url = Url::parse(target)?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid target host"))?;

        Ok(Self {
            allowed_hosts: vec![host.to_string()],
        })
    }

    pub fn is_in_scope(&self, url: &Url) -> bool {
        if let Some(host) = url.host_str() {
            self.allowed_hosts.iter().any(|h| h == host)
        } else {
            false
        }
    }
}
