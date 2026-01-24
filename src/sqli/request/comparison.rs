//! Page comparison utilities

use super::super::core::settings::{DIFF_TOLERANCE, LOWER_RATIO_BOUND, UPPER_RATIO_BOUND};

/// Compare two pages and return similarity ratio
pub fn page_ratio(page1: &str, page2: &str) -> f64 {
    if page1.is_empty() && page2.is_empty() {
        return 1.0;
    }
    if page1.is_empty() || page2.is_empty() {
        return 0.0;
    }

    let len1 = page1.len();
    let len2 = page2.len();
    
    // Quick length-based comparison
    let len_ratio = if len1 > len2 {
        len2 as f64 / len1 as f64
    } else {
        len1 as f64 / len2 as f64
    };

    // If lengths are very different, pages are likely different
    if len_ratio < 0.5 {
        return len_ratio;
    }

    // Use sequence matching for more accurate comparison
    let common = longest_common_subsequence_length(page1, page2);
    let max_len = len1.max(len2);
    
    (2.0 * common as f64) / (len1 + len2) as f64
}

/// Check if two pages are similar enough
pub fn comparison(page1: &str, page2: &str, ratio_threshold: Option<f64>) -> bool {
    let ratio = page_ratio(page1, page2);
    let threshold = ratio_threshold.unwrap_or(0.98 - DIFF_TOLERANCE);
    ratio >= threshold
}

/// Get ratio between current page and baseline
pub fn get_ratio(page: &str, baseline: &str) -> f64 {
    page_ratio(page, baseline)
}

/// Check if ratio indicates true condition
pub fn is_true_ratio(ratio: f64, match_ratio: f64) -> bool {
    ratio > match_ratio - DIFF_TOLERANCE
}

/// Check if ratio indicates false condition  
pub fn is_false_ratio(ratio: f64, match_ratio: f64) -> bool {
    ratio < match_ratio + DIFF_TOLERANCE
}

/// Calculate longest common subsequence length (simplified)
fn longest_common_subsequence_length(s1: &str, s2: &str) -> usize {
    let chars1: Vec<char> = s1.chars().collect();
    let chars2: Vec<char> = s2.chars().collect();
    
    let m = chars1.len();
    let n = chars2.len();
    
    // For very long strings, use sampling
    if m > 5000 || n > 5000 {
        return sampled_common_length(s1, s2);
    }
    
    // Use space-optimized LCS
    let mut prev = vec![0usize; n + 1];
    let mut curr = vec![0usize; n + 1];
    
    for i in 1..=m {
        for j in 1..=n {
            if chars1[i - 1] == chars2[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j].max(curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }
    
    prev[n]
}

/// Sampled comparison for long strings
fn sampled_common_length(s1: &str, s2: &str) -> usize {
    // Sample every 10th character
    let sample1: String = s1.chars().step_by(10).collect();
    let sample2: String = s2.chars().step_by(10).collect();
    
    let common = sample1.chars()
        .zip(sample2.chars())
        .filter(|(a, b)| a == b)
        .count();
    
    common * 10
}

/// Remove dynamic content from page for comparison
pub fn remove_dynamic_content(page: &str) -> String {
    let mut result = page.to_string();
    
    // Remove common dynamic patterns
    let patterns = [
        // Timestamps
        r"\d{4}-\d{2}-\d{2}",
        r"\d{2}:\d{2}:\d{2}",
        // Session IDs
        r"[a-f0-9]{32}",
        r"PHPSESSID=[^&;]+",
        // Random tokens
        r"csrf[_-]?token=[^&;]+",
        r"nonce=[^&;]+",
    ];
    
    for pattern in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            result = re.replace_all(&result, "").to_string();
        }
    }
    
    result
}
