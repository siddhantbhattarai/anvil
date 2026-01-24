//! Core settings and constants for SQL injection

/// Minimum distance of ratio from match ratio to result in True
pub const DIFF_TOLERANCE: f64 = 0.05;
pub const CONSTANT_RATIO: f64 = 0.9;

/// Lower and upper values for match ratio
pub const LOWER_RATIO_BOUND: f64 = 0.02;
pub const UPPER_RATIO_BOUND: f64 = 0.98;

/// Minimum and maximum ratio values
pub const MIN_RATIO: f64 = 0.0;
pub const MAX_RATIO: f64 = 1.0;

/// NULL value for SQL
pub const NULL: &str = "NULL";

/// ORDER BY limits
pub const ORDER_BY_STEP: usize = 10;
pub const ORDER_BY_MAX: usize = 50;

/// UNION settings
pub const MIN_UNION_RESPONSES: usize = 5;
pub const UNION_MIN_RESPONSE_CHARS: usize = 10;
pub const UNION_STDEV_COEFF: f64 = 7.0;
pub const MIN_STATISTICAL_RANGE: f64 = 0.01;

/// Random markers for extraction
pub const CHAR_START: &str = "qvxvq";
pub const CHAR_STOP: &str = "qpkpq";
pub const CHAR_DELIMITER: &str = "qzqzq";

/// Error patterns for ORDER BY detection
pub const ORDER_BY_ERROR_PATTERNS: &[&str] = &[
    "warning",
    "error",
    "order by",
    "unknown column",
    "failed",
];

/// Column mismatch error patterns  
pub const COLUMN_MISMATCH_PATTERNS: &[&str] = &[
    "number of columns",
    "operand should contain",
    "used in select statements",
    "different number",
    "doesn't match",
];
