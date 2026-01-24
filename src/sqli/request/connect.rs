//! HTTP connection handling for SQL injection

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use anyhow::Result;
use url::Url;

/// Request handler for SQL injection testing
pub struct Request<'a> {
    client: &'a HttpClient,
    base_url: Url,
    parameter: String,
}

impl<'a> Request<'a> {
    pub fn new(client: &'a HttpClient, base_url: Url, parameter: String) -> Self {
        Self {
            client,
            base_url,
            parameter,
        }
    }

    /// Send a payload and get the response body
    pub async fn query_page(&self, payload: &str) -> Result<String> {
        let mut url = self.base_url.clone();
        
        // Replace parameter value with payload
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| {
                if k == self.parameter {
                    (k.to_string(), payload.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();

        // If parameter not found, add it
        if !pairs.iter().any(|(k, _)| k == &self.parameter) {
            pairs.push((self.parameter.clone(), payload.to_string()));
        }

        // Rebuild query string
        url.query_pairs_mut().clear();
        for (k, v) in pairs {
            url.query_pairs_mut().append_pair(&k, &v);
        }

        let req = HttpRequest::get(url);
        let resp = self.client.execute(req).await?;
        
        Ok(resp.body_text())
    }

    /// Send request and get full response info
    pub async fn query_page_full(&self, payload: &str) -> Result<(String, u16, usize)> {
        let mut url = self.base_url.clone();
        
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| {
                if k == self.parameter {
                    (k.to_string(), payload.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();

        if !pairs.iter().any(|(k, _)| k == &self.parameter) {
            pairs.push((self.parameter.clone(), payload.to_string()));
        }

        url.query_pairs_mut().clear();
        for (k, v) in pairs {
            url.query_pairs_mut().append_pair(&k, &v);
        }

        let req = HttpRequest::get(url);
        let resp = self.client.execute(req).await?;
        
        let body = resp.body_text();
        let len = body.len();
        let status = resp.status;
        
        Ok((body, status, len))
    }
}
