//! SQL injection techniques

pub mod union;
pub mod blind;
pub mod error;
pub mod dns;

pub use union::{check_union, UnionVector, union_use, get_databases, get_tables, get_columns, dump_table, get_current_db, get_current_user, get_version, get_users, get_passwords};
pub use blind::{check_boolean_blind, check_time_blind, BlindVector, extract_string, get_length};
pub use error::{check_error_based, ErrorVector, error_use, get_databases_error, get_tables_error};
pub use dns::{check_dns_exfiltration, DnsVector, dns_use};
