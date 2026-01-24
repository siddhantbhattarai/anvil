//! UNION-based SQL injection techniques

pub mod test;
pub mod r#use;

pub use test::{check_union, UnionVector, find_union_char_count, find_position, fingerprint_dbms};
pub use r#use::*;
