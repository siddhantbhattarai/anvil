use crate::validation::diff::DiffResult;

#[derive(Debug)]
pub struct Verdict {
    pub confidence: f32,
    pub interesting: bool,
}

pub fn evaluate(diff: &DiffResult) -> Verdict {
    let mut score: f32 = 0.0;

    if diff.status_changed {
        score += 0.4;
    }
    if diff.body_changed {
        score += 0.4;
    }
    if diff.body_len_delta.abs() > 100 {
        score += 0.2;
    }

    Verdict {
        confidence: score.min(1.0),
        interesting: score >= 0.6,
    }
}
