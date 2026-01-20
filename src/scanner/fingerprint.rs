use crate::http::response::HttpResponse;

#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub server: Option<String>,
    pub os_hint: Option<String>,
    pub language_hint: Option<String>,
    pub framework_hint: Option<String>,
    pub waf_cdn_hint: Option<String>,
}

impl Fingerprint {
    pub fn new() -> Self {
        Self {
            server: None,
            os_hint: None,
            language_hint: None,
            framework_hint: None,
            waf_cdn_hint: None,
        }
    }
}

pub fn fingerprint_response(resp: &HttpResponse) -> Fingerprint {
    let mut fp = Fingerprint::new();

    if let Some(server) = resp.headers.get("server") {
        fp.server = Some(server.clone());

        let lower = server.to_lowercase();
        if lower.contains("ubuntu") || lower.contains("debian") {
            fp.os_hint = Some("Linux".to_string());
        }
    }

    if let Some(powered) = resp.headers.get("x-powered-by") {
        let lower = powered.to_lowercase();
        if lower.contains("php") {
            fp.language_hint = Some("PHP".to_string());
        } else if lower.contains("asp.net") {
            fp.language_hint = Some(".NET".to_string());
        }
    }

    if let Some(_ct) = resp.headers.get("content-type") {
        // Content type processed, framework detection done elsewhere
    }

    for (k, v) in resp.headers.iter() {
        let k = k.to_lowercase();
        let v = v.to_lowercase();

        if k.contains("cf-") || v.contains("cloudflare") {
            fp.waf_cdn_hint = Some("Cloudflare".to_string());
        } else if v.contains("akamai") {
            fp.waf_cdn_hint = Some("Akamai".to_string());
        }
    }

    fp
}
