use crate::http::response::HttpResponse;

#[derive(Clone, Debug)]
pub struct Baseline {
    pub status: u16,
    pub body_len: usize,
    pub body_hash: String,
    pub elapsed_ms: u128,
}

impl Baseline {
    pub fn from_response(resp: &HttpResponse) -> Self {
        Self {
            status: resp.status,
            body_len: resp.body_len,
            body_hash: resp.body_hash.clone(),
            elapsed_ms: resp.elapsed_ms,
        }
    }
}
