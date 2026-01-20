use crate::validation::baseline::Baseline;
use crate::http::response::HttpResponse;

#[derive(Debug)]
pub struct DiffResult {
    pub status_changed: bool,
    pub body_len_delta: isize,
    pub body_changed: bool,
}

pub fn diff(baseline: &Baseline, resp: &HttpResponse) -> DiffResult {
    DiffResult {
        status_changed: baseline.status != resp.status,
        body_len_delta: resp.body_len as isize - baseline.body_len as isize,
        body_changed: baseline.body_hash != resp.body_hash,
    }
}
