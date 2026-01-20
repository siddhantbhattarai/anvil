use clap::Parser;

/// ANVIL – Enterprise-grade Adversarial Security Testing Framework
#[derive(Parser, Debug)]
#[command(
    name = "anvil",
    version = "0.1.0",
    author = "Siddhant Bhattarai",
    about = "ANVIL – Enterprise-grade Adversarial Security Testing Framework",
    long_about = r#"
ANVIL is a modular, inference-driven security testing framework that surpasses
traditional tools like sqlmap through:

  • Reasoning-driven detection with confidence scoring
  • Statistical time-based analysis (resists jitter/noise)
  • Baseline modeling and response diffing
  • Clean separation of detection and exploitation
  • Enterprise-grade scope enforcement & rate limiting
  • Explainable, verifiable findings

SQL INJECTION DETECTION:
  • Boolean/Error-based inference
  • Time-based blind with statistical modeling
  • UNION-based extraction
  • Stacked queries detection
  • Out-of-band (OOB) via DNS/HTTP callbacks
  • Second-order SQLi detection

SQL INJECTION EXPLOITATION:
  • Database enumeration (--dbs)
  • Table enumeration (--tables)
  • Column enumeration (--columns)
  • Data extraction (--dump)
  • User/password enumeration (--users, --passwords)
  • Privilege enumeration (--privileges)

CROSS-SITE SCRIPTING (XSS) DETECTION:
  Professional evidence-driven XSS detection with zero false positives
  
  Detection Methodology:
  • Stage 1: Data reachability (benign marker probing)
  • Stage 2: Context classification (HTML/JS/Attribute/URL/CSS)
  • Stage 3: Encoding assessment (context-specific validation)
  • Stage 4: Structural breakout verification (explicit proof)
  • Stage 5: Dual confidence scoring (injection + execution)
  
  XSS Types Detected:
  • Reflected XSS (immediate execution in same response)
  • Stored/Persistent XSS (execution after persistence)
  • DOM-based XSS (client-side source-to-sink analysis)
  • Blind XSS (out-of-band callback confirmation)
  
  Professional Features:
  • "Confirmed" vs "Likely Exploitable" classification
  • Interaction requirement detection (click, hover, focus)
  • Context breakout verification (not just reflection)
  • One-line "WHY THIS IS XSS" justification
  • CSP detection as exploitability modifier
  • Confidence decoupled from severity
  
  Output Modes:
  • Default: Clean summary (what's vulnerable)
  • --verbose: Full methodology (how it was detected)
  • --output file: Complete report (documentation)
  
  Principle: Reflection ≠ Execution

SERVER-SIDE REQUEST FORGERY (SSRF) DETECTION:
  Evidence-driven SSRF detection with zero false positives
  
  Detection Methodology:
  • Stage 1: Parameter identification (URL/host/webhook fields)
  • Stage 2: Reachability testing (confirm outbound requests)
  • Stage 3: Controlled probes (internal IPs, metadata, schemes)
  • Stage 4: Evidence analysis (OOB, timing, response behavior)
  • Stage 5: Classification (Confirmed/Internal/Blind/Limited/Candidate)
  
  SSRF Types Detected:
  • Confirmed SSRF (OOB callback or metadata access proven)
  • Internal Network SSRF (internal IP reachable with proof)
  • Blind SSRF (asynchronous OOB only)
  • Limited SSRF (outbound request control but restricted)
  
  Professional Features:
  • Evidence-based classification (not payload reflection)
  • OOB callback system for blind SSRF
  • Cloud metadata endpoint detection (AWS/GCP/Azure)
  • Internal network probing (RFC1918, loopback, link-local)
  • Non-HTTP scheme testing (file, gopher, ftp, dict)
  • Timing differential analysis
  • Dual confidence scoring (request control + impact)
  
  Principle: Reflection ≠ SSRF (requires server-side network interaction)
"#,
    after_help = r#"EXAMPLES:

SQL Injection:
  anvil -t https://example.com/page?id=1 -p id --sqli
  anvil -t https://example.com/page?id=1 -p id --sqli --dbs
  anvil -t https://example.com/page?id=1 -p id --sqli -D testdb --tables
  anvil -t https://example.com/page?id=1 -p id --sqli -D testdb -T users --dump

Cross-Site Scripting (Default - Clean Summary):
  anvil -t https://example.com/search?q=test -p q --xss
  anvil -t https://example.com/comment -p message --xss --xss-stored
  
Cross-Site Scripting (Verbose - See Methodology):
  anvil -t https://example.com/search?q=test -p q --xss --verbose
  
Cross-Site Scripting (Report - Full Documentation):
  anvil -t https://example.com/search?q=test -p q --xss -o xss-report.txt
  anvil -t https://example.com/search?q=test -p q --xss --format json -o results.json

Server-Side Request Forgery (Default - All Tests):
  anvil -t https://example.com/fetch?url=http://example.com -p url --ssrf
  anvil -t https://example.com/webhook?callback=http://test.com --ssrf --ssrf-all
  
Server-Side Request Forgery (Specific Tests):
  anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-internal
  anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-metadata
  anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-schemes
  
Server-Side Request Forgery (Blind SSRF with OOB):
  anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-callback attacker.com

Authentication:
  anvil -t https://example.com/page?id=1 -p id --cookie "session=abc123" --sqli
  anvil -t https://example.com/page?id=1 -p id -H "Authorization: Bearer token" --sqli

Reporting:
  anvil -t https://example.com -p id --sqli -o report.txt
  anvil -t https://example.com -p id --sqli --format json -o results.json

DOCUMENTATION:
  docs/USAGE.md          Complete CLI reference
  docs/SQL-INJECTION.md  SQLi methodology & exploitation
  docs/XSS-DETECTION.md  XSS detection & validation
  docs/REPORTING.md      Report formats & output modes
  docs/QUICK_START.md    Getting started guide

  https://github.com/siddhantbhattarai/anvil"#
)]
pub struct Cli {
    /// Target URL (e.g. https://example.com/page.php?id=1)
    #[arg(short, long, required = true)]
    pub target: String,

    // ═══════════════════════════════════════════════════════════════════
    // CORE FEATURES
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL vulnerability scans (SQLi + XSS + others)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub all: bool,

    /// Enable fingerprinting (server, OS, framework detection)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub fingerprint: bool,

    /// Enable application crawling & parameter discovery
    #[arg(long, help_heading = "CORE FEATURES")]
    pub crawl: bool,

    /// Enable SQL Injection scanning (use --sqli for basic, see SQLI DETECTION for advanced)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub sqli: bool,

    /// Enable Cross-Site Scripting scanning (use --xss for basic, see XSS DETECTION for advanced)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub xss: bool,

    /// Enable Server-Side Request Forgery scanning
    #[arg(long, help_heading = "CORE FEATURES")]
    pub ssrf: bool,

    // ═══════════════════════════════════════════════════════════════════
    // XSS DETECTION OPTIONS
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL XSS detection types (reflected, stored, DOM, blind)
    #[arg(long = "xss-all", help_heading = "XSS DETECTION")]
    pub xss_all: bool,

    /// Enable stored/persistent XSS detection
    #[arg(long = "xss-stored", help_heading = "XSS DETECTION")]
    pub xss_stored: bool,

    /// Enable DOM-based XSS detection (client-side analysis)
    #[arg(long = "xss-dom", help_heading = "XSS DETECTION")]
    pub xss_dom: bool,

    /// Enable blind XSS detection with out-of-band callbacks
    #[arg(long = "xss-blind", help_heading = "XSS DETECTION")]
    pub xss_blind: bool,

    /// Callback domain for blind XSS (e.g., attacker.com)
    #[arg(long = "callback", help_heading = "XSS DETECTION", requires = "xss_blind")]
    pub xss_callback: Option<String>,

    /// Maximum payloads to test per context (default: 20)
    #[arg(long = "max-payloads", help_heading = "XSS DETECTION", default_value = "20")]
    pub max_payloads: usize,

    /// XSS context to target (html, attribute, js_string, js_code, url, polyglot)
    #[arg(long = "xss-context", help_heading = "XSS DETECTION")]
    pub xss_context: Option<String>,

    // ═══════════════════════════════════════════════════════════════════
    // SSRF DETECTION OPTIONS
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL SSRF detection types (internal, metadata, schemes)
    #[arg(long = "ssrf-all", help_heading = "SSRF DETECTION")]
    pub ssrf_all: bool,

    /// Test internal network ranges (RFC1918, loopback, link-local)
    #[arg(long = "ssrf-internal", help_heading = "SSRF DETECTION")]
    pub ssrf_internal: bool,

    /// Test cloud metadata endpoints (AWS, GCP, Azure)
    #[arg(long = "ssrf-metadata", help_heading = "SSRF DETECTION")]
    pub ssrf_metadata: bool,

    /// Test non-HTTP schemes (file, gopher, ftp, dict)
    #[arg(long = "ssrf-schemes", help_heading = "SSRF DETECTION")]
    pub ssrf_schemes: bool,

    /// Callback domain for blind SSRF detection (e.g., attacker.com)
    #[arg(long = "ssrf-callback", help_heading = "SSRF DETECTION")]
    pub ssrf_callback: Option<String>,

    /// Maximum payloads to test per parameter for SSRF (default: 20)
    #[arg(long = "ssrf-max-payloads", help_heading = "SSRF DETECTION", default_value = "20")]
    pub ssrf_max_payloads: usize,

    // ═══════════════════════════════════════════════════════════════════
    // SQL INJECTION DETECTION
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL SQLi detection techniques
    #[arg(long = "sqli-all", help_heading = "SQLI DETECTION")]
    pub sqli_all: bool,


    /// Scan for time-based (blind) SQL Injection
    #[arg(long = "time-sqli", help_heading = "SQLI DETECTION")]
    pub time_sqli: bool,

    /// Scan for stacked queries SQL Injection
    #[arg(long, help_heading = "SQLI DETECTION")]
    pub stacked: bool,

    /// Scan for out-of-band (OOB) SQL Injection
    #[arg(long, help_heading = "SQLI DETECTION")]
    pub oob: bool,

    /// Callback domain for OOB detection
    #[arg(long = "oob-callback", help_heading = "SQLI DETECTION")]
    pub oob_callback: Option<String>,

    /// Scan for second-order SQL Injection
    #[arg(long = "second-order", help_heading = "SQLI DETECTION")]
    pub second_order: bool,

    /// SQLi technique to use: B=Boolean, E=Error, U=Union, T=Time, S=Stacked
    #[arg(long, default_value = "BEUTS", help_heading = "SQLI DETECTION")]
    pub technique: String,

    // ═══════════════════════════════════════════════════════════════════
    // ENUMERATION (like sqlmap)
    // ═══════════════════════════════════════════════════════════════════

    /// Enumerate DBMS databases
    #[arg(long, help_heading = "ENUMERATION")]
    pub dbs: bool,

    /// Enumerate tables (use -D to specify database)
    #[arg(long, help_heading = "ENUMERATION")]
    pub tables: bool,

    /// Enumerate columns (use -D and -T to specify)
    #[arg(long, help_heading = "ENUMERATION")]
    pub columns: bool,

    /// Enumerate database schema (all DBs, tables, columns)
    #[arg(long, help_heading = "ENUMERATION")]
    pub schema: bool,

    /// Count number of entries in table(s)
    #[arg(long, help_heading = "ENUMERATION")]
    pub count: bool,

    /// Dump table entries (use -D, -T, -C to specify)
    #[arg(long, help_heading = "ENUMERATION")]
    pub dump: bool,

    /// Dump all databases tables entries
    #[arg(long = "dump-all", help_heading = "ENUMERATION")]
    pub dump_all: bool,

    /// Database to enumerate (-D database_name)
    #[arg(short = 'D', long = "database", help_heading = "ENUMERATION")]
    pub database: Option<String>,

    /// Table to enumerate (-T table_name)
    #[arg(short = 'T', long = "table", help_heading = "ENUMERATION")]
    pub table: Option<String>,

    /// Column(s) to enumerate (-C "col1,col2")
    #[arg(short = 'C', long = "col", help_heading = "ENUMERATION")]
    pub columns_list: Option<String>,

    /// First row to retrieve (--start 0)
    #[arg(long, default_value_t = 0, help_heading = "ENUMERATION")]
    pub start: usize,

    /// Last row to retrieve (--stop 10)
    #[arg(long, help_heading = "ENUMERATION")]
    pub stop: Option<usize>,

    // ═══════════════════════════════════════════════════════════════════
    // DATABASE INFORMATION
    // ═══════════════════════════════════════════════════════════════════

    /// Retrieve DBMS banner/version
    #[arg(long, help_heading = "DB INFO")]
    pub banner: bool,

    /// Retrieve current user
    #[arg(long = "current-user", help_heading = "DB INFO")]
    pub current_user: bool,

    /// Retrieve current database
    #[arg(long = "current-db", help_heading = "DB INFO")]
    pub current_db: bool,

    /// Retrieve server hostname
    #[arg(long, help_heading = "DB INFO")]
    pub hostname: bool,

    /// Check if current user is DBA
    #[arg(long = "is-dba", help_heading = "DB INFO")]
    pub is_dba: bool,

    // ═══════════════════════════════════════════════════════════════════
    // USER ENUMERATION
    // ═══════════════════════════════════════════════════════════════════

    /// Enumerate DBMS users
    #[arg(long, help_heading = "USER ENUM")]
    pub users: bool,

    /// Enumerate DBMS users password hashes
    #[arg(long, help_heading = "USER ENUM")]
    pub passwords: bool,

    /// Enumerate DBMS users privileges
    #[arg(long, help_heading = "USER ENUM")]
    pub privileges: bool,

    /// Enumerate DBMS users roles
    #[arg(long, help_heading = "USER ENUM")]
    pub roles: bool,

    // ═══════════════════════════════════════════════════════════════════
    // AUTHENTICATION
    // ═══════════════════════════════════════════════════════════════════

    /// Cookie string for authenticated scanning
    #[arg(long, help_heading = "AUTHENTICATION")]
    pub cookie: Option<String>,

    /// HTTP headers (can be used multiple times)
    #[arg(long = "header", short = 'H', help_heading = "AUTHENTICATION")]
    pub headers: Vec<String>,

    // ═══════════════════════════════════════════════════════════════════
    // INJECTION POINT
    // ═══════════════════════════════════════════════════════════════════

    /// Parameter to test directly
    #[arg(long, short = 'p', help_heading = "INJECTION")]
    pub param: Option<String>,

    /// POST data for testing
    #[arg(long, help_heading = "INJECTION")]
    pub data: Option<String>,

    /// HTTP method to use (GET, POST)
    #[arg(long, default_value = "GET", help_heading = "INJECTION")]
    pub method: String,

    /// Trigger URL for second-order SQLi
    #[arg(long = "trigger-url", help_heading = "INJECTION")]
    pub trigger_url: Option<String>,

    /// Extra POST data to include with payloads
    #[arg(long = "extra-data", help_heading = "INJECTION")]
    pub extra_data: Option<String>,

    /// Prefix string to inject before payload
    #[arg(long, help_heading = "INJECTION")]
    pub prefix: Option<String>,

    /// Suffix string to inject after payload
    #[arg(long, help_heading = "INJECTION")]
    pub suffix: Option<String>,

    // ═══════════════════════════════════════════════════════════════════
    // DETECTION TUNING
    // ═══════════════════════════════════════════════════════════════════

    /// Detection confidence threshold (0.0-1.0, default: 0.5)
    #[arg(long, default_value_t = 0.5, help_heading = "TUNING")]
    pub threshold: f32,

    /// Risk level (1=safe, 2=moderate, 3=aggressive)
    #[arg(long, default_value_t = 1, help_heading = "TUNING")]
    pub risk: u8,

    /// Test level (1=basic, 2=extended, 3=comprehensive)
    #[arg(long, default_value_t = 1, help_heading = "TUNING")]
    pub level: u8,

    // ═══════════════════════════════════════════════════════════════════
    // PERFORMANCE
    // ═══════════════════════════════════════════════════════════════════

    /// Maximum HTTP requests per second
    #[arg(long, default_value_t = 5, help_heading = "PERFORMANCE")]
    pub rate: u32,

    /// Crawl depth limit
    #[arg(long, default_value_t = 2, help_heading = "PERFORMANCE")]
    pub depth: u32,

    /// Time-based SQLi: samples per test
    #[arg(long = "time-samples", default_value_t = 6, help_heading = "PERFORMANCE")]
    pub time_samples: usize,

    /// Time-based SQLi: delay in seconds
    #[arg(long = "time-delay", default_value_t = 2, help_heading = "PERFORMANCE")]
    pub time_delay: u64,

    /// Number of threads for extraction
    #[arg(long, default_value_t = 1, help_heading = "PERFORMANCE")]
    pub threads: usize,

    // ═══════════════════════════════════════════════════════════════════
    // OUTPUT
    // ═══════════════════════════════════════════════════════════════════

    /// Skip the banner display
    #[arg(long, help_heading = "OUTPUT")]
    pub no_banner: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, help_heading = "OUTPUT")]
    pub quiet: bool,

    /// Verbose output (debug level)
    #[arg(short, long, help_heading = "OUTPUT")]
    pub verbose: bool,

    /// Output format (text, json, csv)
    #[arg(long, default_value = "text", help_heading = "OUTPUT")]
    pub format: String,

    /// Output file path
    #[arg(short, long, help_heading = "OUTPUT")]
    pub output: Option<String>,

    // ═══════════════════════════════════════════════════════════════════
    // LEGACY/COMPATIBILITY (like sqlmap)
    // ═══════════════════════════════════════════════════════════════════

    /// Enable proof mode (safe metadata extraction only)
    #[arg(long, help_heading = "LEGACY")]
    pub proof: bool,

    /// Enable exploitation (same as enumeration flags)
    #[arg(long, help_heading = "LEGACY")]
    pub exploit: bool,

    /// Extract database password hashes (same as --passwords)
    #[arg(long = "dump-hashes", help_heading = "LEGACY")]
    pub dump_hashes: bool,
}

impl Cli {
    /// Check if any enumeration flag is set
    pub fn has_enumeration(&self) -> bool {
        self.dbs
            || self.tables
            || self.columns
            || self.schema
            || self.dump
            || self.dump_all
            || self.count
            || self.banner
            || self.current_user
            || self.current_db
            || self.hostname
            || self.is_dba
            || self.users
            || self.passwords
            || self.privileges
            || self.roles
    }
}
