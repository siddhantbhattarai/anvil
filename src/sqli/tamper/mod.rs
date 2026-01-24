//! Tamper scripts for WAF/IPS bypass
//! 
//! These functions modify payloads to evade web application firewalls.

/// Tamper function type
pub type TamperFn = fn(&str) -> String;

/// Get tamper function by name
pub fn get_tamper(name: &str) -> Option<TamperFn> {
    match name.to_lowercase().as_str() {
        "space2comment" => Some(space2comment),
        "space2hash" => Some(space2hash),
        "space2mssqlhash" => Some(space2mssqlhash),
        "space2plus" => Some(space2plus),
        "space2randomblank" => Some(space2randomblank),
        "between" => Some(between),
        "randomcase" => Some(randomcase),
        "charencode" => Some(charencode),
        "chardoubleencode" => Some(chardoubleencode),
        "base64encode" => Some(base64encode),
        "appendnullbyte" => Some(appendnullbyte),
        "percentage" => Some(percentage),
        "uppercase" => Some(uppercase),
        "lowercase" => Some(lowercase),
        "equaltolike" => Some(equaltolike),
        "greatest" => Some(greatest),
        "multiplespaces" => Some(multiplespaces),
        "nonrecursivereplacement" => Some(nonrecursivereplacement),
        _ => None,
    }
}

/// List available tamper scripts
pub fn list_tampers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("space2comment", "Replace spaces with SQL comments /**/"),
        ("space2hash", "Replace spaces with # followed by newline (MySQL)"),
        ("space2mssqlhash", "Replace spaces with -- followed by newline (MSSQL)"),
        ("space2plus", "Replace spaces with plus signs"),
        ("space2randomblank", "Replace spaces with random blank characters"),
        ("between", "Replace > with NOT BETWEEN 0 AND"),
        ("randomcase", "Random upper/lower case for SQL keywords"),
        ("charencode", "URL-encode all characters"),
        ("chardoubleencode", "Double URL-encode all characters"),
        ("base64encode", "Base64-encode the payload"),
        ("appendnullbyte", "Append null byte at the end"),
        ("percentage", "Add % before each character"),
        ("uppercase", "Convert payload to uppercase"),
        ("lowercase", "Convert payload to lowercase"),
        ("equaltolike", "Replace = with LIKE"),
        ("greatest", "Replace > with GREATEST"),
        ("multiplespaces", "Add multiple spaces around SQL keywords"),
        ("nonrecursivereplacement", "Double keywords (e.g., SELSELECTECT)"),
    ]
}

/// Replace spaces with SQL comments
pub fn space2comment(payload: &str) -> String {
    payload.replace(' ', "/**/")
}

/// Replace spaces with # and newline (MySQL)
pub fn space2hash(payload: &str) -> String {
    payload.replace(' ', "#\n")
}

/// Replace spaces with -- and newline (MSSQL)
pub fn space2mssqlhash(payload: &str) -> String {
    payload.replace(' ', "--\n")
}

/// Replace spaces with plus signs
pub fn space2plus(payload: &str) -> String {
    payload.replace(' ', "+")
}

/// Replace spaces with random blank characters
pub fn space2randomblank(payload: &str) -> String {
    let blanks = ["\t", "\n", "\r"];
    let mut idx = 0;
    
    payload.chars().map(|c| {
        if c == ' ' {
            idx = (idx + 1) % blanks.len();
            blanks[idx].to_string()
        } else {
            c.to_string()
        }
    }).collect()
}

/// Replace > with NOT BETWEEN 0 AND
pub fn between(payload: &str) -> String {
    payload.replace('>', " NOT BETWEEN 0 AND ")
}

/// Random case for SQL keywords (alternating pattern)
pub fn randomcase(payload: &str) -> String {
    payload.chars().enumerate().map(|(i, c)| {
        if c.is_alphabetic() {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        } else {
            c.to_string()
        }
    }).collect()
}

/// URL-encode all characters
pub fn charencode(payload: &str) -> String {
    payload.chars().map(|c| {
        if c.is_ascii_alphanumeric() {
            c.to_string()
        } else {
            format!("%{:02X}", c as u8)
        }
    }).collect()
}

/// Double URL-encode all characters
pub fn chardoubleencode(payload: &str) -> String {
    payload.chars().map(|c| {
        format!("%25{:02X}", c as u8)
    }).collect()
}

/// Base64-encode the payload
pub fn base64encode(payload: &str) -> String {
    // Simple base64 encoding without external crate
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = payload.as_bytes();
    let mut result = String::new();
    
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        
        result.push(ALPHABET[(b0 >> 2)] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}

/// Append null byte at the end
pub fn appendnullbyte(payload: &str) -> String {
    format!("{}%00", payload)
}

/// Add % before each character
pub fn percentage(payload: &str) -> String {
    payload.chars().map(|c| format!("%{}", c)).collect()
}

/// Convert to uppercase
pub fn uppercase(payload: &str) -> String {
    payload.to_uppercase()
}

/// Convert to lowercase
pub fn lowercase(payload: &str) -> String {
    payload.to_lowercase()
}

/// Replace = with LIKE
pub fn equaltolike(payload: &str) -> String {
    payload.replace('=', " LIKE ")
}

/// Replace > with GREATEST
pub fn greatest(payload: &str) -> String {
    // Replace "a>b" with "GREATEST(a,b+1)=a"
    payload.replace('>', " GREATEST ")
}

/// Add multiple spaces around SQL keywords
pub fn multiplespaces(payload: &str) -> String {
    let keywords = ["SELECT", "FROM", "WHERE", "AND", "OR", "UNION", "ORDER", "BY", "GROUP", "HAVING", "NULL", "INSERT", "UPDATE", "DELETE"];
    let mut result = payload.to_string();
    
    for kw in keywords {
        let pattern = format!(" {} ", kw);
        let replacement = format!("   {}   ", kw);
        result = result.replace(&pattern, &replacement);
    }
    
    result
}

/// Double keywords to bypass simple filters
pub fn nonrecursivereplacement(payload: &str) -> String {
    let keywords = [
        ("SELECT", "SELSELECTECT"),
        ("UNION", "UNUNIONION"),
        ("WHERE", "WHWHEREERE"),
        ("FROM", "FRFROMOM"),
        ("AND", "AANDND"),
        ("OR", "OORR"),
    ];
    
    let mut result = payload.to_string();
    for (original, doubled) in keywords {
        result = result.replace(original, doubled);
    }
    
    result
}

/// Apply multiple tamper functions in sequence
pub fn apply_tampers(payload: &str, tampers: &[&str]) -> String {
    let mut result = payload.to_string();
    
    for tamper_name in tampers {
        if let Some(tamper_fn) = get_tamper(tamper_name) {
            result = tamper_fn(&result);
        }
    }
    
    result
}
