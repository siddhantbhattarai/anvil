use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use std::sync::Arc;

#[derive(Clone)]
pub struct RateLimiter {
    interval: Duration,
    last_request: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    /// rate = requests per second
    pub fn new(rate: u32) -> Self {
        let interval = if rate == 0 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs_f64(1.0 / rate as f64)
        };

        Self {
            interval,
            last_request: Arc::new(Mutex::new(Instant::now() - interval)),
        }
    }

    pub async fn wait(&self) {
        let mut last = self.last_request.lock().await;
        let elapsed = last.elapsed();

        if elapsed < self.interval {
            tokio::time::sleep(self.interval - elapsed).await;
        }

        *last = Instant::now();
    }
}
