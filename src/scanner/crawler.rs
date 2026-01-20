use crate::core::scope::Scope;
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::scanner::sitemap::SiteMap;
use reqwest::Method;
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use url::Url;

pub struct Crawler {
    pub max_depth: usize,
}

impl Crawler {
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    pub async fn crawl(
        &self,
        client: &HttpClient,
        start_url: Url,
        scope: &Scope,
    ) -> anyhow::Result<SiteMap> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut sitemap = SiteMap::new(start_url.as_str().to_string());

        queue.push_back((start_url.clone(), 0));

        while let Some((url, depth)) = queue.pop_front() {
            if depth > self.max_depth {
                continue;
            }

            if visited.contains(url.as_str()) {
                continue;
            }
            visited.insert(url.as_str().to_string());

            let req = HttpRequest::new(Method::GET, url.clone());
            let resp = match client.execute(req).await {
                Ok(r) => r,
                Err(_) => continue, // Skip failed requests
            };

            // Register endpoint
            let path = url.path().to_string();
            let params: Vec<String> = url
                .query_pairs()
                .map(|(k, _)| k.to_string())
                .collect();

            sitemap.add_endpoint(path.clone(), "GET", params);

            // Parse HTML body
            let body_html = resp.body_text();
            if body_html.is_empty() {
                continue;
            }

            let document = Html::parse_document(&body_html);

            // Extract links
            if let Ok(a_sel) = Selector::parse("a[href]") {
                for el in document.select(&a_sel) {
                    if let Some(href) = el.value().attr("href") {
                        if let Ok(next) = url.join(href) {
                            if scope.is_in_scope(&next) && !visited.contains(next.as_str()) {
                                queue.push_back((next, depth + 1));
                            }
                        }
                    }
                }
            }

            // Extract forms
            if let Ok(form_sel) = Selector::parse("form") {
                if let Ok(input_sel) = Selector::parse("input[name]") {
                    for form in document.select(&form_sel) {
                        let action = form.value().attr("action").unwrap_or(url.path());
                        let method = form.value().attr("method").unwrap_or("GET").to_uppercase();

                        if let Ok(form_url) = url.join(action) {
                            let mut form_params = Vec::new();
                            for input in form.select(&input_sel) {
                                if let Some(name) = input.value().attr("name") {
                                    form_params.push(name.to_string());
                                }
                            }

                            sitemap.add_endpoint(
                                form_url.path().to_string(),
                                &method,
                                form_params,
                            );
                        }
                    }
                }
            }
        }

        Ok(sitemap)
    }
}
