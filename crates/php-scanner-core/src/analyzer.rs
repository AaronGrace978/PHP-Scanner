//! Syntax-tree based analysis: intra-procedural taint tracking with per-file
//! function summaries, plus structural checks for dangerous API usage.

use crate::finding::{Confidence, FlowStep};
use once_cell::sync::Lazy;
use regex::Regex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Parser, Tree};

pub mod sink {
    pub const SQL: u32 = 1 << 0;
    pub const XSS: u32 = 1 << 1;
    pub const CMD: u32 = 1 << 2;
    pub const CODE: u32 = 1 << 3;
    pub const FILE: u32 = 1 << 4;
    pub const URL: u32 = 1 << 5;
    pub const HEADER: u32 = 1 << 6;
    pub const LDAP: u32 = 1 << 7;
    pub const XPATH: u32 = 1 << 8;
    pub const REGEX: u32 = 1 << 9;
    pub const DESER: u32 = 1 << 10;
    pub const SESSION: u32 = 1 << 11;
    pub const VARS: u32 = 1 << 12;
    /// Escaped for SQL string literals only; becomes SQL once placed between quotes.
    pub const SQL_ESCAPED: u32 = 1 << 13;
    pub const ALL: u32 = u32::MAX;
}

#[derive(Debug, Clone)]
pub struct RawFinding {
    pub rule_id: &'static str,
    pub message: String,
    pub confidence: Confidence,
    /// 0-based (row, byte column).
    pub start: (usize, usize),
    pub end: (usize, usize),
    pub flow: Vec<FlowStep>,
}

thread_local! {
    static PARSER: RefCell<Parser> = RefCell::new({
        let mut p = Parser::new();
        p.set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("tree-sitter-php grammar is compatible with tree-sitter runtime");
        p
    });
}

pub fn parse(src: &str) -> Option<Tree> {
    PARSER.with(|p| p.borrow_mut().parse(src, None))
}

pub fn analyze(src: &str, tree: &Tree) -> Vec<RawFinding> {
    let mut a = Analyzer::new(src);
    a.run(tree.root_node());
    a.findings
}

// ---------------------------------------------------------------------------------------
// Taint model
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    Source {
        desc: String,
        line: usize,
        framework: bool,
    },
    Param(usize),
}

#[derive(Debug, Clone)]
struct Taint {
    origins: Vec<Origin>,
    /// Sink kinds this value has been sanitised for.
    cleansed: u32,
    flow: Vec<FlowStep>,
    /// Stack of enclosing conditional/loop node ids where the value was assigned.
    scope: Vec<usize>,
}

fn is_prefix(prefix: &[usize], of: &[usize]) -> bool {
    prefix.len() <= of.len() && prefix.iter().zip(of).all(|(a, b)| a == b)
}

fn common_prefix(a: &[usize], b: &[usize]) -> Vec<usize> {
    a.iter()
        .zip(b)
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| *x)
        .collect()
}

const MAX_FLOW: usize = 12;
const MAX_ORIGINS: usize = 4;

impl Taint {
    fn source(desc: String, line: usize, framework: bool) -> Self {
        Taint {
            flow: vec![FlowStep {
                line,
                description: format!("User input read from {desc}"),
            }],
            origins: vec![Origin::Source {
                desc,
                line,
                framework,
            }],
            cleansed: 0,
            scope: Vec::new(),
        }
    }

    fn param(idx: usize, name: &str, line: usize) -> Self {
        Taint {
            origins: vec![Origin::Param(idx)],
            cleansed: 0,
            flow: vec![FlowStep {
                line,
                description: format!("Parameter {name}"),
            }],
            scope: Vec::new(),
        }
    }

    fn merge(mut self, other: Taint) -> Taint {
        for o in other.origins {
            if self.origins.len() < MAX_ORIGINS && !self.origins.contains(&o) {
                self.origins.push(o);
            }
        }
        self.cleansed &= other.cleansed;
        if self.flow.is_empty() {
            self.flow = other.flow;
        }
        self.scope = common_prefix(&self.scope, &other.scope);
        self
    }

    fn step(mut self, line: usize, description: String) -> Taint {
        if self.flow.len() < MAX_FLOW && self.flow.last().map(|s| s.line) != Some(line) {
            self.flow.push(FlowStep { line, description });
        }
        self
    }

    fn cleanse(mut self, kinds: u32) -> Taint {
        self.cleansed |= kinds;
        self
    }

    fn has_source(&self) -> bool {
        self.origins
            .iter()
            .any(|o| matches!(o, Origin::Source { .. }))
    }

    fn only_framework(&self) -> bool {
        self.origins.iter().all(|o| {
            !matches!(
                o,
                Origin::Source {
                    framework: false,
                    ..
                }
            )
        })
    }

    fn source_desc(&self) -> String {
        self.origins
            .iter()
            .find_map(|o| match o {
                Origin::Source { desc, .. } => Some(desc.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "user input".into())
    }
}

fn merge_opt(a: Option<Taint>, b: Option<Taint>) -> Option<Taint> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.merge(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

type Env = HashMap<String, Taint>;

enum ConcatPart<'t> {
    Lit(String),
    Expr(Node<'t>),
}

#[derive(Debug, Clone)]
struct ParamSink {
    param: usize,
    kinds: u32,
    rule: &'static str,
    sink: String,
    line: usize,
}

#[derive(Debug, Clone, Default)]
struct Summary {
    param_sinks: Vec<ParamSink>,
    returns: Option<Taint>,
}

// ---------------------------------------------------------------------------------------
// Knowledge base
// ---------------------------------------------------------------------------------------

const SUPERGLOBALS: &[&str] = &[
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_FILES",
    "$HTTP_GET_VARS",
    "$HTTP_POST_VARS",
    "$HTTP_COOKIE_VARS",
    "$HTTP_POST_FILES",
    "$HTTP_RAW_POST_DATA",
];

const SERVER_TAINTED_KEYS: &[&str] = &[
    "REQUEST_URI",
    "QUERY_STRING",
    "PHP_SELF",
    "PATH_INFO",
    "PATH_TRANSLATED",
    "ORIG_PATH_INFO",
    "REDIRECT_URL",
    "REDIRECT_QUERY_STRING",
    "CONTENT_TYPE",
    "argv",
];

/// Functions whose return value is safe for every sink.
static FULL_SANITIZERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "intval",
        "floatval",
        "doubleval",
        "boolval",
        "abs",
        "count",
        "sizeof",
        "strlen",
        "mb_strlen",
        "md5",
        "sha1",
        "hash",
        "hash_hmac",
        "crc32",
        "password_hash",
        "password_verify",
        "hash_equals",
        "base64_encode",
        "bin2hex",
        "is_numeric",
        "is_int",
        "is_string",
        "is_array",
        "isset",
        "empty",
        "in_array",
        "array_key_exists",
        "round",
        "floor",
        "ceil",
        "number_format",
        "date",
        "gmdate",
        "time",
        "strtotime",
        "mktime",
        "random_int",
        "random_bytes",
        "uniqid",
        "absint",
        "ctype_digit",
        "ctype_alnum",
        "ctype_alpha",
        "preg_match",
        "preg_match_all",
        "strcmp",
        "strcasecmp",
        "strpos",
        "stripos",
        "strrpos",
        "substr_count",
        "uuid",
        "sanitize_key",
        "spl_object_hash",
        "gettype",
        "get_class",
        "array_sum",
        "array_product",
        "ord",
        "max",
        "min",
    ]
    .into_iter()
    .collect()
});

/// Functions that neutralise data for specific sink kinds.
static PARTIAL_SANITIZERS: Lazy<HashMap<&'static str, u32>> = Lazy::new(|| {
    use sink::*;
    let enc = XSS | HEADER | SQL | CMD | FILE | LDAP | URL | XPATH;
    [
        ("htmlspecialchars", XSS),
        ("htmlentities", XSS),
        ("strip_tags", XSS),
        ("esc_html", XSS),
        ("esc_attr", XSS),
        ("esc_js", XSS),
        ("esc_textarea", XSS),
        ("esc_url", XSS),
        ("esc_url_raw", XSS),
        ("wp_kses", XSS),
        ("wp_kses_post", XSS),
        ("sanitize_text_field", XSS),
        ("sanitize_email", XSS),
        ("e", XSS),
        ("json_encode", XSS),
        ("urlencode", enc),
        ("rawurlencode", enc),
        ("http_build_query", enc),
        ("mysqli_real_escape_string", SQL_ESCAPED),
        ("mysql_real_escape_string", SQL_ESCAPED),
        ("mysql_escape_string", SQL_ESCAPED),
        ("mysqli_escape_string", SQL_ESCAPED),
        ("pg_escape_string", SQL_ESCAPED),
        ("pg_escape_literal", SQL),
        ("pg_escape_identifier", SQL),
        ("sqlite_escape_string", SQL_ESCAPED),
        ("db2_escape_string", SQL_ESCAPED),
        ("esc_sql", SQL),
        ("addslashes", SQL_ESCAPED),
        ("escapeshellarg", CMD),
        ("escapeshellcmd", CMD),
        ("basename", FILE),
        ("sanitize_file_name", FILE),
        ("ldap_escape", LDAP),
        ("preg_quote", REGEX),
    ]
    .into_iter()
    .collect()
});

/// Functions whose result carries the taint of their arguments.
static PROPAGATORS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "trim",
        "ltrim",
        "rtrim",
        "chop",
        "strtolower",
        "strtoupper",
        "ucfirst",
        "ucwords",
        "lcfirst",
        "substr",
        "mb_substr",
        "str_replace",
        "str_ireplace",
        "preg_replace",
        "sprintf",
        "vsprintf",
        "implode",
        "join",
        "explode",
        "str_pad",
        "str_repeat",
        "strrev",
        "nl2br",
        "stripslashes",
        "stripcslashes",
        "urldecode",
        "rawurldecode",
        "base64_decode",
        "html_entity_decode",
        "htmlspecialchars_decode",
        "json_decode",
        "array_merge",
        "array_merge_recursive",
        "array_values",
        "array_keys",
        "array_filter",
        "array_slice",
        "array_splice",
        "array_pop",
        "array_shift",
        "current",
        "reset",
        "end",
        "next",
        "prev",
        "array_unique",
        "array_reverse",
        "strval",
        "mb_strtolower",
        "mb_strtoupper",
        "mb_convert_encoding",
        "mb_convert_case",
        "iconv",
        "utf8_decode",
        "utf8_encode",
        "wordwrap",
        "chunk_split",
        "str_split",
        "mb_str_split",
        "substr_replace",
        "strstr",
        "stristr",
        "strrchr",
        "strtr",
        "parse_url",
        "pathinfo",
        "dirname",
        "array_column",
        "array_combine",
        "array_fill_keys",
        "array_pad",
        "array_flip",
        "iterator_to_array",
        "quotemeta",
        "addcslashes",
        "wp_unslash",
        "stripslashes_deep",
        "file_get_contents",
        "gzinflate",
        "gzuncompress",
        "gzdecode",
        "str_rot13",
        "hex2bin",
        "convert_uudecode",
        "array_map",
        "array_change_key_case",
        "ltrim",
        "normalizer_normalize",
        "transliterator_transliterate",
        "filter_var",
        "array_walk_recursive",
        "unserialize",
        "maybe_unserialize",
        "simplexml_load_string",
        "str_word_count",
        "preg_split",
        "preg_grep",
        "array_diff",
        "array_intersect",
        "array_replace",
        "array_search",
        "key",
        "each",
    ]
    .into_iter()
    .collect()
});

const DECODERS: &[&str] = &[
    "base64_decode",
    "gzinflate",
    "gzuncompress",
    "gzdecode",
    "str_rot13",
    "strrev",
    "hex2bin",
    "convert_uudecode",
    "urldecode",
    "rawurldecode",
    "bzdecompress",
    "lzf_decompress",
    "pack",
];

const REQUEST_METHODS: &[&str] = &[
    "input",
    "get",
    "post",
    "query",
    "all",
    "cookie",
    "header",
    "json",
    "getparam",
    "getparams",
    "getqueryparams",
    "getparsedbody",
    "getcontent",
    "only",
    "except",
    "getquery",
    "getpost",
    "get_post",
    "post_get",
    "getclientoriginalname",
    "getclientfilename",
    "string",
    "str",
    "getqueryparam",
    "getparsedbodyparam",
    "getcookieparams",
    "getheader",
    "getheaderline",
    "getbody",
    "getuploadedfiles",
    "getrawbody",
    "fromquery",
    "frompost",
];

#[derive(Clone, Copy)]
enum Args {
    Idx(&'static [usize]),
    All,
    Last,
}

struct SinkSpec {
    args: Args,
    kinds: u32,
    rule: &'static str,
}

static FUNCTION_SINKS: Lazy<HashMap<&'static str, SinkSpec>> = Lazy::new(|| {
    use sink::*;
    use Args::*;
    let mut m = HashMap::new();
    let mut add = |names: &[&'static str], args: Args, kinds: u32, rule: &'static str| {
        for n in names {
            m.insert(*n, SinkSpec { args, kinds, rule });
        }
    };
    add(
        &[
            "mysql_query",
            "mysql_unbuffered_query",
            "mssql_query",
            "sqlite_query",
            "sqlite_exec",
            "sqlite_unbuffered_query",
            "ibase_query",
            "ifx_query",
            "maxdb_query",
            "sybase_query",
        ],
        Idx(&[0]),
        SQL,
        "sql-injection",
    );
    add(
        &[
            "mysql_db_query",
            "mysqli_query",
            "mysqli_real_query",
            "mysqli_multi_query",
            "mysqli_prepare",
            "mysqli_send_query",
            "pg_send_query",
            "odbc_exec",
            "odbc_prepare",
            "db2_exec",
            "db2_prepare",
            "oci_parse",
            "sqlsrv_query",
            "sqlsrv_prepare",
            "pg_query_params",
            "cubrid_query",
        ],
        Idx(&[1]),
        SQL,
        "sql-injection",
    );
    add(&["pg_query"], Last, SQL, "sql-injection");
    add(&["pg_prepare"], Idx(&[2]), SQL, "sql-injection");
    add(
        &[
            "system",
            "exec",
            "shell_exec",
            "passthru",
            "popen",
            "proc_open",
            "expect_popen",
        ],
        Idx(&[0]),
        CMD,
        "command-injection",
    );
    add(&["pcntl_exec"], Idx(&[0, 1]), CMD, "command-injection");
    add(&["mail"], Idx(&[4]), CMD, "command-injection");
    add(&["eval", "assert"], Idx(&[0]), CODE, "code-injection");
    add(&["create_function"], Idx(&[0, 1]), CODE, "code-injection");
    add(
        &[
            "call_user_func",
            "call_user_func_array",
            "forward_static_call",
            "forward_static_call_array",
            "array_map",
            "register_shutdown_function",
            "register_tick_function",
            "ob_start",
            "iterator_apply",
            "spl_autoload_register",
            "set_error_handler",
            "set_exception_handler",
        ],
        Idx(&[0]),
        CODE,
        "code-injection",
    );
    add(
        &[
            "usort",
            "uasort",
            "uksort",
            "array_filter",
            "array_walk",
            "array_walk_recursive",
            "preg_replace_callback",
            "array_reduce",
        ],
        Idx(&[1]),
        CODE,
        "code-injection",
    );
    add(
        &[
            "file_get_contents",
            "file_put_contents",
            "fopen",
            "file",
            "readfile",
            "unlink",
            "rmdir",
            "mkdir",
            "opendir",
            "scandir",
            "dir",
            "glob",
            "highlight_file",
            "show_source",
            "php_strip_whitespace",
            "parse_ini_file",
            "readlink",
            "touch",
            "chmod",
            "chown",
            "chgrp",
            "tempnam",
            "simplexml_load_file",
            "fpassthru",
            "gzopen",
            "gzfile",
            "readgzfile",
            "bzopen",
            "lchown",
            "lchgrp",
            "getimagesize",
            "exif_read_data",
            "md5_file",
            "sha1_file",
            "hash_file",
            "filesize",
            "file_exists",
            "is_dir",
            "fileperms",
            "stat",
            "lstat",
        ],
        Idx(&[0]),
        FILE,
        "path-traversal",
    );
    add(
        &["copy", "rename", "symlink", "link"],
        Idx(&[0, 1]),
        FILE,
        "path-traversal",
    );
    add(
        &["move_uploaded_file"],
        Idx(&[1]),
        FILE,
        "unrestricted-file-upload",
    );
    add(
        &[
            "curl_init",
            "fsockopen",
            "pfsockopen",
            "get_headers",
            "stream_socket_client",
            "wp_remote_get",
            "wp_remote_post",
            "wp_remote_request",
            "wp_remote_head",
            "http_get",
        ],
        Idx(&[0]),
        URL,
        "ssrf",
    );
    add(
        &["wp_redirect", "redirect"],
        Idx(&[0]),
        HEADER,
        "open-redirect",
    );
    add(&["printf", "vprintf"], All, XSS, "xss");
    add(
        &[
            "print_r",
            "var_export",
            "die",
            "exit",
            "trigger_error",
            "user_error",
        ],
        Idx(&[0]),
        XSS,
        "xss",
    );
    add(
        &["unserialize", "maybe_unserialize"],
        Idx(&[0]),
        DESER,
        "insecure-deserialization",
    );
    add(
        &["ldap_search", "ldap_list", "ldap_read"],
        Idx(&[1, 2]),
        LDAP,
        "ldap-injection",
    );
    add(&["ldap_bind"], Idx(&[1]), LDAP, "ldap-injection");
    add(
        &[
            "preg_match",
            "preg_match_all",
            "preg_replace",
            "preg_replace_callback",
            "preg_split",
            "preg_grep",
            "preg_filter",
        ],
        Idx(&[0]),
        REGEX,
        "regex-injection",
    );
    add(&["session_id"], Idx(&[0]), SESSION, "session-fixation");
    add(
        &["extract", "import_request_variables"],
        Idx(&[0]),
        VARS,
        "variable-overwrite",
    );
    m
});

static METHOD_SINKS: Lazy<HashMap<&'static str, SinkSpec>> = Lazy::new(|| {
    use sink::*;
    use Args::*;
    let mut m = HashMap::new();
    let mut add = |names: &[&'static str], args: Args, kinds: u32, rule: &'static str| {
        for n in names {
            m.insert(*n, SinkSpec { args, kinds, rule });
        }
    };
    add(
        &[
            "query",
            "exec",
            "prepare",
            "multi_query",
            "real_query",
            "rawquery",
            "unprepared",
            "whereraw",
            "orwhereraw",
            "havingraw",
            "orhavingraw",
            "orderbyraw",
            "selectraw",
            "groupbyraw",
            "fromraw",
            "raw",
            "statement",
            "get_results",
            "get_row",
            "get_var",
            "get_col",
            "createquery",
            "createnativequery",
            "executequery",
            "executestatement",
            "executeupdate",
            "fetchallassociative",
            "fetchassociative",
            "fetchone",
            "fetchfirstcolumn",
            "fetchallkeyvalue",
            "rawexecute",
            "simple_query",
        ],
        Idx(&[0]),
        SQL,
        "sql-injection",
    );
    add(&["xpath", "evaluate"], Idx(&[0]), XPATH, "xpath-injection");
    add(
        &["fromshellcommandline"],
        Idx(&[0]),
        CMD,
        "command-injection",
    );
    add(&["request"], Idx(&[1]), URL, "ssrf");
    add(&["setcookie"], Idx(&[1]), HEADER, "header-injection");
    add(&["move"], Idx(&[1]), FILE, "unrestricted-file-upload");
    m
});

static CLASS_SINKS: Lazy<HashMap<&'static str, SinkSpec>> = Lazy::new(|| {
    use sink::*;
    use Args::*;
    let mut m = HashMap::new();
    m.insert(
        "process",
        SinkSpec {
            args: Idx(&[0]),
            kinds: CMD,
            rule: "command-injection",
        },
    );
    m.insert(
        "splfileobject",
        SinkSpec {
            args: Idx(&[0]),
            kinds: FILE,
            rule: "path-traversal",
        },
    );
    m.insert(
        "directoryiterator",
        SinkSpec {
            args: Idx(&[0]),
            kinds: FILE,
            rule: "path-traversal",
        },
    );
    m.insert(
        "recursivedirectoryiterator",
        SinkSpec {
            args: Idx(&[0]),
            kinds: FILE,
            rule: "path-traversal",
        },
    );
    m.insert(
        "soapclient",
        SinkSpec {
            args: Idx(&[0]),
            kinds: URL,
            rule: "ssrf",
        },
    );
    m.insert(
        "reflectionfunction",
        SinkSpec {
            args: Idx(&[0]),
            kinds: CODE,
            rule: "code-injection",
        },
    );
    m
});

static CRED_STRONG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(password|passwd|passphrase|secret|api_?key|private_?key|access_?token|auth_?token|client_?secret|secret_?key|access_?key|app_?key)$").unwrap()
});
static CRED_WEAK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(^|_|db|smtp|ftp|mysql|admin|root|user|mail|ldap)(pass|pwd)$").unwrap()
});
static PLACEHOLDER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(changeme|change_me|your[_\- ].*|xxx+|\*+|<.*>|\{.*\}|%.*%|\$\{.*\}|null|none|password|passwd|secret|example|test|testing|dummy|todo|fixme|placeholder|redacted|hidden|default|empty|n/a|required|string|true|false)$").unwrap()
});
static SECURITY_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(pass(word|wd)?|pwd|hash|token|secret|signature|hmac|digest|api_?key|nonce|csrf|otp)",
    )
    .unwrap()
});
static TOKEN_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(token|secret|password|passwd|nonce|salt|csrf|api_?key|otp|reset|session_?id|verification|activation|_key$|^key$)").unwrap()
});
static PASSWORD_ARG: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(pass(word|wd)?|pwd)").unwrap());

/// Method names too common to treat as SQL sinks unless the receiver looks like a database handle.
const GENERIC_SQL_METHODS: &[&str] = &[
    "query",
    "exec",
    "prepare",
    "multi_query",
    "real_query",
    "raw",
    "statement",
    "simple_query",
];
static DB_RECEIVER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(db|pdo|conn|mysql|sql|wpdb|database|link|dbh|connection|adapter|entitymanager|doctrine|capsule|^\$this->(db|pdo|conn))").unwrap()
});
static EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$").unwrap());
static IDENTIFIER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[a-z]+(?:_[a-z]+)+|[a-z]+(?:[A-Z][a-z]+)+)$").unwrap());

/// Mitigation directives from the php2shell advisory that only work at startup.
const PHP2SHELL_DIRECTIVES: &[&str] =
    &["session.upload_progress.enabled", "fatal_error_backtraces"];

const WEAK_RANDOM: &[&str] = &[
    "rand",
    "mt_rand",
    "lcg_value",
    "uniqid",
    "str_shuffle",
    "array_rand",
    "microtime",
    "shuffle",
];
const STRONG_RANDOM: &[&str] = &[
    "random_bytes",
    "random_int",
    "openssl_random_pseudo_bytes",
    "sodium_crypto_secretbox_keygen",
];

// ---------------------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------------------

struct Analyzer<'a> {
    src: &'a str,
    findings: Vec<RawFinding>,
    summaries: HashMap<String, Summary>,
    /// Summary under construction for the function currently being analysed.
    summary: Option<Summary>,
    /// When true, findings are suppressed (summary-building pass).
    silent: bool,
    /// Ids of the conditional/loop nodes enclosing the current statement.
    blocks: Vec<usize>,
    reported: HashSet<(&'static str, usize, usize)>,
    mysql_reported: bool,
}

fn line_of(n: Node) -> usize {
    n.start_position().row + 1
}

fn is_conditional(kind: &str) -> bool {
    matches!(
        kind,
        "if_statement"
            | "else_clause"
            | "else_if_clause"
            | "switch_statement"
            | "case_statement"
            | "default_statement"
            | "while_statement"
            | "do_statement"
            | "for_statement"
            | "foreach_statement"
            | "try_statement"
            | "catch_clause"
            | "match_expression"
            | "conditional_expression"
    )
}

fn named_children<'t>(n: Node<'t>) -> Vec<Node<'t>> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

fn short(s: &str, max: usize) -> String {
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > max {
        let mut out: String = collapsed.chars().take(max).collect();
        out.push('…');
        out
    } else {
        collapsed
    }
}

fn normalize_fn(name: &str) -> String {
    name.rsplit('\\')
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn any_descendant(n: Node, pred: &mut dyn FnMut(Node) -> bool) -> bool {
    if pred(n) {
        return true;
    }
    let mut c = n.walk();
    for ch in n.named_children(&mut c) {
        if any_descendant(ch, pred) {
            return true;
        }
    }
    false
}

impl<'a> Analyzer<'a> {
    fn new(src: &'a str) -> Self {
        Analyzer {
            src,
            findings: Vec::new(),
            summaries: HashMap::new(),
            summary: None,
            silent: false,
            blocks: Vec::new(),
            reported: HashSet::new(),
            mysql_reported: false,
        }
    }

    fn text(&self, n: Node) -> &'a str {
        &self.src[n.byte_range()]
    }

    fn run(&mut self, root: Node) {
        let mut functions = Vec::new();
        collect_functions(root, &mut functions);

        // Build summaries (twice, so helpers calling later-defined helpers resolve).
        self.silent = true;
        for _ in 0..2 {
            for f in &functions {
                let s = self.summarize(*f);
                if let Some(name) = self.function_name(*f) {
                    self.summaries.insert(name, s);
                }
            }
        }
        self.silent = false;

        for f in &functions {
            self.summarize(*f);
        }
        let mut env = Env::new();
        self.visit(root, &mut env);
    }

    fn function_name(&self, f: Node) -> Option<String> {
        f.child_by_field_name("name")
            .map(|n| self.text(n).to_ascii_lowercase())
    }

    fn summarize(&mut self, f: Node) -> Summary {
        let mut env = Env::new();
        if let Some(params) = f.child_by_field_name("parameters") {
            for (i, p) in named_children(params).into_iter().enumerate() {
                if let Some(v) = p.child_by_field_name("name") {
                    let name = self.text(v).to_string();
                    env.insert(name.clone(), Taint::param(i, &name, line_of(v)));
                }
            }
        }
        let prev = self.summary.replace(Summary::default());
        let prev_blocks = std::mem::take(&mut self.blocks);
        if let Some(body) = f.child_by_field_name("body") {
            self.visit(body, &mut env);
        }
        self.blocks = prev_blocks;
        std::mem::replace(&mut self.summary, prev).unwrap_or_default()
    }

    // ---- reporting -----------------------------------------------------------------------

    fn report(
        &mut self,
        n: Node,
        rule: &'static str,
        confidence: Confidence,
        message: String,
        flow: Vec<FlowStep>,
    ) {
        if self.silent {
            return;
        }
        let start = n.start_position();
        if !self.reported.insert((rule, start.row, start.column)) {
            return;
        }
        let end = n.end_position();
        self.findings.push(RawFinding {
            rule_id: rule,
            message,
            confidence,
            start: (start.row, start.column),
            end: (end.row, end.column),
            flow,
        });
    }

    /// Reports `taint` reaching a sink. Returns true if a finding (or summary entry) was produced.
    fn sink_hit(
        &mut self,
        at: Node,
        taint: &Taint,
        kinds: u32,
        rule: &'static str,
        sink_desc: &str,
    ) -> bool {
        if taint.cleansed & kinds != 0 {
            return false;
        }
        let line = line_of(at);
        let mut hit = false;
        if let Some(summary) = self.summary.as_mut() {
            for o in &taint.origins {
                if let Origin::Param(p) = o {
                    summary.param_sinks.push(ParamSink {
                        param: *p,
                        kinds,
                        rule,
                        sink: sink_desc.to_string(),
                        line,
                    });
                    hit = true;
                }
            }
        }
        if taint.has_source() {
            let src = taint.source_desc();
            let confidence = if taint.only_framework() {
                Confidence::Medium
            } else {
                Confidence::High
            };
            let flow = taint
                .clone()
                .step(line, format!("Reaches sink {sink_desc}"))
                .flow;
            self.report(
                at,
                rule,
                confidence,
                format!("User input from {src} reaches {sink_desc} without sanitisation."),
                flow,
            );
            hit = true;
        }
        hit
    }

    fn check_args(
        &mut self,
        call: Node,
        args: &[Node],
        spec: &SinkSpec,
        sink_desc: &str,
        env: &Env,
    ) -> bool {
        let selected: Vec<Node> = match spec.args {
            Args::All => args.to_vec(),
            Args::Last => args.last().copied().into_iter().collect(),
            Args::Idx(idx) => idx.iter().filter_map(|i| args.get(*i).copied()).collect(),
        };
        let mut hit = false;
        for a in selected {
            if let Some(t) = self.taint_of(a, env) {
                hit |= self.sink_hit(call, &t, spec.kinds, spec.rule, sink_desc);
            }
        }
        hit
    }

    // ---- traversal -----------------------------------------------------------------------

    fn visit(&mut self, n: Node, env: &mut Env) {
        match n.kind() {
            "function_definition" | "method_declaration" => return,
            "anonymous_function" | "anonymous_function_creation_expression" => {
                let mut inner = Env::new();
                if let Some(uc) = named_children(n)
                    .into_iter()
                    .find(|c| c.kind() == "anonymous_function_use_clause")
                {
                    let mut vars = Vec::new();
                    collect_vars(uc, &mut vars);
                    for v in vars {
                        let key = self.text(v).to_string();
                        if let Some(t) = env.get(&key) {
                            inner.insert(key, t.clone());
                        }
                    }
                }
                if let Some(body) = n.child_by_field_name("body") {
                    let saved = self.summary.take();
                    let blocks = std::mem::take(&mut self.blocks);
                    self.visit(body, &mut inner);
                    self.blocks = blocks;
                    self.summary = saved;
                }
                return;
            }
            "arrow_function" => {
                let mut inner = env.clone();
                if let Some(body) = n.child_by_field_name("body") {
                    self.visit(body, &mut inner);
                }
                return;
            }
            "assignment_expression" | "reference_assignment_expression" => {
                let left = n.child_by_field_name("left");
                let right = n.child_by_field_name("right");
                if let Some(r) = right {
                    self.visit(r, env);
                }
                if let (Some(l), Some(r)) = (left, right) {
                    self.check_hardcoded(n, self.lvalue_name(l), r);
                    self.check_insecure_random(n, l, r);
                    let t = self.taint_of(r, env);
                    self.assign(l, t, env);
                }
                return;
            }
            "augmented_assignment_expression" => {
                let left = n.child_by_field_name("left");
                let right = n.child_by_field_name("right");
                if let Some(r) = right {
                    self.visit(r, env);
                }
                let op = self.operator(n);
                if let (Some(l), Some(r)) = (left, right) {
                    if op == ".=" || op == "??=" {
                        if let Some(t) = self.taint_of(r, env) {
                            self.assign_merge(l, Some(t), env);
                        }
                    }
                }
                return;
            }
            "foreach_statement" => {
                let children = named_children(n);
                let body = n.child_by_field_name("body");
                if let Some(iter) = children.first() {
                    self.visit(*iter, env);
                    let t = self.taint_of(*iter, env);
                    self.blocks.push(n.id());
                    for c in children.iter().skip(1) {
                        if Some(*c) == body {
                            continue;
                        }
                        let mut vars = Vec::new();
                        collect_vars(*c, &mut vars);
                        for v in vars {
                            let key = self.text(v).to_string();
                            let t = t
                                .clone()
                                .map(|t| t.step(line_of(v), format!("Iterated into {key}")));
                            self.bind(key, t, env);
                        }
                    }
                    self.blocks.pop();
                }
                if let Some(b) = body {
                    self.blocks.push(n.id());
                    self.visit(b, env);
                    self.blocks.pop();
                }
                return;
            }
            "return_statement" => {
                if let Some(e) = n.named_child(0) {
                    self.visit(e, env);
                    if self.summary.is_some() {
                        let t = self.taint_of(e, env);
                        if let Some(s) = self.summary.as_mut() {
                            s.returns = merge_opt(s.returns.take(), t);
                        }
                    }
                }
                return;
            }
            "echo_statement" | "print_intrinsic" | "exit_statement" => {
                let what = match n.kind() {
                    "echo_statement" => "echo",
                    "print_intrinsic" => "print",
                    _ => "exit()",
                };
                for c in named_children(n) {
                    let exprs = if c.kind() == "sequence_expression" {
                        flatten_sequence(c)
                    } else {
                        vec![c]
                    };
                    for e in exprs {
                        if let Some(t) = self.taint_of(e, env) {
                            self.sink_hit(n, &t, sink::XSS, "xss", what);
                        }
                    }
                }
            }
            "expression_statement" => {
                if self.is_short_echo(n) {
                    if let Some(e) = n.named_child(0) {
                        if let Some(t) = self.taint_of(e, env) {
                            self.sink_hit(n, &t, sink::XSS, "xss", "<?= ?> short echo");
                        }
                    }
                }
            }
            "function_call_expression" => self.check_function_call(n, env),
            "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression" => self.check_method_call(n, env),
            "object_creation_expression" => self.check_new(n, env),
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression" => self.check_include(n, env),
            "shell_command_expression" => {
                let t = self.taint_of(n, env);
                let hit = t
                    .map(|t| {
                        self.sink_hit(
                            n,
                            &t,
                            sink::CMD,
                            "command-injection",
                            "backtick shell execution",
                        )
                    })
                    .unwrap_or(false);
                if !hit
                    && named_children(n)
                        .iter()
                        .any(|c| c.kind() != "string_content" && c.kind() != "escape_sequence")
                {
                    self.report(
                        n,
                        "dangerous-exec",
                        Confidence::Low,
                        "Backtick operator executes a shell command built from variables.".into(),
                        vec![],
                    );
                }
            }
            "binary_expression" => self.check_loose_comparison(n),
            "array_element_initializer" => self.check_array_element(n),
            "const_element" => {
                let ch = named_children(n);
                if ch.len() >= 2 {
                    let name = self.text(ch[0]).to_string();
                    self.check_hardcoded(n, Some(name), ch[ch.len() - 1]);
                }
            }
            "property_element" => {
                let ch = named_children(n);
                if let (Some(var), Some(init)) = (ch.first(), ch.get(1)) {
                    let value = if init.kind() == "property_initializer" {
                        init.named_child(0)
                    } else {
                        Some(*init)
                    };
                    if let Some(v) = value {
                        let name = self.text(*var).trim_start_matches('$').to_string();
                        self.check_hardcoded(n, Some(name), v);
                    }
                }
            }
            "name" => {
                let t = self.text(n);
                if t == "LIBXML_NOENT" || t == "LIBXML_DTDLOAD" {
                    self.report(
                        n,
                        "xxe",
                        Confidence::Medium,
                        format!("{t} enables external entity / DTD loading during XML parsing."),
                        vec![],
                    );
                }
            }
            _ => {}
        }

        let cond = is_conditional(n.kind());
        if cond {
            self.blocks.push(n.id());
        }
        let mut c = n.walk();
        let children: Vec<Node> = n.named_children(&mut c).collect();
        for ch in children {
            self.visit(ch, env);
        }
        if cond {
            self.blocks.pop();
        }
    }

    fn is_short_echo(&self, n: Node) -> bool {
        let Some(prev) = n.prev_sibling() else {
            return false;
        };
        if prev.kind() != "text_interpolation" {
            return false;
        }
        let mut c = prev.walk();
        let last = prev.named_children(&mut c).last();
        matches!(last, Some(t) if t.kind() == "php_tag" && self.text(t) == "<?=")
    }

    fn operator(&self, n: Node) -> &'a str {
        if let Some(op) = n.child_by_field_name("operator") {
            return self.text(op);
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            if !ch.is_named() {
                return self.text(ch);
            }
        }
        ""
    }

    // ---- assignment ---------------------------------------------------------------------

    fn lvalue_key(&self, l: Node) -> Option<String> {
        match l.kind() {
            "variable_name" => Some(self.text(l).to_string()),
            "subscript_expression" => l.named_child(0).and_then(|b| self.lvalue_key(b)),
            "member_access_expression"
            | "nullsafe_member_access_expression"
            | "scoped_property_access_expression" => {
                Some(self.text(l).split_whitespace().collect())
            }
            "by_ref" => l.named_child(0).and_then(|b| self.lvalue_key(b)),
            _ => None,
        }
    }

    /// Human-readable name of an assignment target, used for credential heuristics.
    fn lvalue_name(&self, l: Node) -> Option<String> {
        match l.kind() {
            "variable_name" => Some(self.text(l).trim_start_matches('$').to_string()),
            "subscript_expression" => {
                let idx = named_children(l).into_iter().nth(1)?;
                self.string_value(idx)
            }
            "member_access_expression"
            | "nullsafe_member_access_expression"
            | "scoped_property_access_expression" => l
                .child_by_field_name("name")
                .map(|n| self.text(n).trim_start_matches('$').to_string()),
            _ => None,
        }
    }

    fn assign(&mut self, l: Node, t: Option<Taint>, env: &mut Env) {
        match l.kind() {
            "list_literal" | "array_creation_expression" => {
                let mut vars = Vec::new();
                collect_vars(l, &mut vars);
                for v in vars {
                    self.assign(v, t.clone(), env);
                }
            }
            "subscript_expression" => {
                // Writing one element never cleans the whole array.
                if t.is_some() {
                    self.assign_merge(l, t, env);
                }
            }
            _ => {
                let Some(key) = self.lvalue_key(l) else {
                    return;
                };
                let t = t.map(|t| t.step(line_of(l), format!("Assigned to {key}")));
                self.bind(key, t, env);
            }
        }
    }

    /// Strong update when assigning in the block (or an ancestor of the block)
    /// that produced the current value; weak (merging) update otherwise.
    fn bind(&self, key: String, t: Option<Taint>, env: &mut Env) {
        let strong = env
            .get(&key)
            .map(|e| is_prefix(&self.blocks, &e.scope))
            .unwrap_or(true);
        match (t, strong) {
            (Some(mut t), true) => {
                t.scope = self.blocks.clone();
                env.insert(key, t);
            }
            (Some(t), false) => {
                let mut merged = env.remove(&key).unwrap().merge(t);
                merged.scope = common_prefix(&merged.scope, &self.blocks);
                env.insert(key, merged);
            }
            (None, true) => {
                env.remove(&key);
            }
            (None, false) => {}
        }
    }

    fn assign_merge(&mut self, l: Node, t: Option<Taint>, env: &mut Env) {
        let (Some(key), Some(t)) = (self.lvalue_key(l), t) else {
            return;
        };
        let t = t.step(line_of(l), format!("Assigned to {key}"));
        let merged = match env.remove(&key) {
            Some(e) => {
                let mut m = e.merge(t);
                m.scope = common_prefix(&m.scope, &self.blocks);
                m
            }
            None => Taint {
                scope: self.blocks.clone(),
                ..t
            },
        };
        env.insert(key, merged);
    }

    // ---- taint evaluation ---------------------------------------------------------------

    fn taint_of(&self, n: Node, env: &Env) -> Option<Taint> {
        match n.kind() {
            "variable_name" => {
                let t = self.text(n);
                if SUPERGLOBALS.contains(&t) {
                    return Some(Taint::source(t.to_string(), line_of(n), false));
                }
                env.get(t).cloned()
            }
            "subscript_expression" => {
                let base = n.named_child(0)?;
                let base_text = self.text(base);
                if base_text == "$_SERVER" {
                    let key = named_children(n)
                        .get(1)
                        .and_then(|i| self.string_value(*i))?;
                    if key.starts_with("HTTP_") || SERVER_TAINTED_KEYS.contains(&key.as_str()) {
                        return Some(Taint::source(short(self.text(n), 60), line_of(n), false));
                    }
                    return None;
                }
                if base_text.starts_with("$_FILES") || base_text.starts_with("$HTTP_POST_FILES") {
                    let full = self.text(n);
                    if ["tmp_name", "size", "error"].iter().any(|k| {
                        full.contains(&format!("'{k}'")) || full.contains(&format!("\"{k}\""))
                    }) {
                        return None;
                    }
                }
                if SUPERGLOBALS.contains(&base_text) {
                    return Some(Taint::source(short(self.text(n), 60), line_of(n), false));
                }
                self.taint_of(base, env)
            }
            "member_access_expression"
            | "nullsafe_member_access_expression"
            | "scoped_property_access_expression" => {
                let key: String = self.text(n).split_whitespace().collect();
                if let Some(t) = env.get(&key) {
                    return Some(t.clone());
                }
                let obj = n.child_by_field_name("object")?;
                if self.text(obj) == "$this" {
                    return None;
                }
                self.taint_of(obj, env)
            }
            "encapsed_string" | "heredoc" => self.taint_of_concat(n, env),
            "heredoc_body"
            | "shell_command_expression"
            | "sequence_expression"
            | "array_creation_expression"
            | "array_element_initializer"
            | "parenthesized_expression"
            | "error_suppression_expression"
            | "by_ref"
            | "variadic_unpacking"
            | "dynamic_variable_name"
            | "argument" => {
                let mut acc = None;
                for c in named_children(n) {
                    if matches!(
                        c.kind(),
                        "string_content" | "escape_sequence" | "heredoc_start" | "heredoc_end"
                    ) {
                        continue;
                    }
                    acc = merge_opt(acc, self.taint_of(c, env));
                }
                acc
            }
            "binary_expression" => {
                let op = self.operator(n);
                match op {
                    "." => self.taint_of_concat(n, env),
                    "??" | "?:" => merge_opt(
                        n.child_by_field_name("left")
                            .and_then(|l| self.taint_of(l, env)),
                        n.child_by_field_name("right")
                            .and_then(|r| self.taint_of(r, env)),
                    ),
                    _ => None,
                }
            }
            "conditional_expression" => {
                let body = n
                    .child_by_field_name("body")
                    .or_else(|| n.child_by_field_name("condition"));
                merge_opt(
                    body.and_then(|b| self.taint_of(b, env)),
                    n.child_by_field_name("alternative")
                        .and_then(|a| self.taint_of(a, env)),
                )
            }
            "match_expression" => {
                let mut acc = None;
                if let Some(body) = n.child_by_field_name("body") {
                    for arm in named_children(body) {
                        if let Some(rv) = arm.child_by_field_name("return_expression") {
                            acc = merge_opt(acc, self.taint_of(rv, env));
                        }
                    }
                }
                acc
            }
            "cast_expression" => {
                let ty = n
                    .child_by_field_name("type")
                    .map(|t| self.text(t).to_ascii_lowercase())
                    .unwrap_or_default();
                if matches!(
                    ty.as_str(),
                    "int" | "integer" | "float" | "double" | "real" | "bool" | "boolean" | "unset"
                ) {
                    return None;
                }
                n.child_by_field_name("value")
                    .and_then(|v| self.taint_of(v, env))
            }
            "assignment_expression" | "reference_assignment_expression" => n
                .child_by_field_name("right")
                .and_then(|r| self.taint_of(r, env)),
            "function_call_expression" => self.taint_of_call(n, env),
            "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression" => self.taint_of_method(n, env),
            _ => None,
        }
    }

    /// Taint of a string built by interpolation or `.` concatenation. Values escaped
    /// for SQL string literals only count as SQL-safe when enclosed in quotes.
    fn taint_of_concat(&self, n: Node, env: &Env) -> Option<Taint> {
        let mut parts = Vec::new();
        self.concat_parts(n, &mut parts);
        let mut acc = None;
        for (i, p) in parts.iter().enumerate() {
            let ConcatPart::Expr(e) = p else { continue };
            let Some(mut t) = self.taint_of(*e, env) else {
                continue;
            };
            if t.cleansed & sink::SQL_ESCAPED != 0 {
                let before = match i.checked_sub(1).and_then(|j| parts.get(j)) {
                    Some(ConcatPart::Lit(s)) => s.chars().last(),
                    _ => None,
                };
                let after = match parts.get(i + 1) {
                    Some(ConcatPart::Lit(s)) => s.chars().next(),
                    _ => None,
                };
                if matches!(before, Some('\'') | Some('"')) && before == after {
                    t = t.cleanse(sink::SQL);
                }
            }
            acc = merge_opt(acc, Some(t));
        }
        acc
    }

    fn concat_parts<'t>(&self, n: Node<'t>, out: &mut Vec<ConcatPart<'t>>) {
        let push_lit = |out: &mut Vec<ConcatPart<'t>>, s: &str| match out.last_mut() {
            Some(ConcatPart::Lit(prev)) => prev.push_str(s),
            _ => out.push(ConcatPart::Lit(s.to_string())),
        };
        match n.kind() {
            "binary_expression" if self.operator(n) == "." => {
                if let Some(l) = n.child_by_field_name("left") {
                    self.concat_parts(l, out);
                }
                if let Some(r) = n.child_by_field_name("right") {
                    self.concat_parts(r, out);
                }
            }
            "parenthesized_expression" => {
                if let Some(c) = n.named_child(0) {
                    self.concat_parts(c, out);
                }
            }
            "string" | "nowdoc" => push_lit(out, &self.string_value(n).unwrap_or_default()),
            "encapsed_string" | "heredoc" | "heredoc_body" => {
                for c in named_children(n) {
                    match c.kind() {
                        "string_content" | "escape_sequence" => push_lit(out, self.text(c)),
                        "heredoc_start" | "heredoc_end" => {}
                        "heredoc_body" => self.concat_parts(c, out),
                        _ => out.push(ConcatPart::Expr(c)),
                    }
                }
            }
            _ => out.push(ConcatPart::Expr(n)),
        }
    }

    fn args<'t>(&self, call: Node<'t>) -> Vec<Node<'t>> {
        let args_node = call.child_by_field_name("arguments").or_else(|| {
            named_children(call)
                .into_iter()
                .find(|c| c.kind() == "arguments")
        });
        let Some(args) = args_node else {
            return Vec::new();
        };
        named_children(args)
            .into_iter()
            .filter(|a| a.kind() == "argument" || a.kind() == "variadic_unpacking")
            .filter_map(|a| {
                if a.kind() == "variadic_unpacking" {
                    return Some(a);
                }
                let mut c = a.walk();
                let last = a.named_children(&mut c).last();
                last
            })
            .collect()
    }

    fn call_name(&self, call: Node) -> Option<String> {
        let f = call.child_by_field_name("function")?;
        match f.kind() {
            "name" | "qualified_name" => Some(normalize_fn(self.text(f))),
            _ => None,
        }
    }

    fn method_name(&self, call: Node) -> Option<String> {
        call.child_by_field_name("name")
            .map(|n| self.text(n).to_ascii_lowercase())
    }

    fn args_taint(&self, args: &[Node], env: &Env) -> Option<Taint> {
        args.iter()
            .fold(None, |acc, a| merge_opt(acc, self.taint_of(*a, env)))
    }

    fn apply_return_summary(
        &self,
        call: Node,
        summary: &Summary,
        args: &[Node],
        env: &Env,
    ) -> Option<Taint> {
        let ret = summary.returns.as_ref()?;
        let mut acc: Option<Taint> = None;
        for o in &ret.origins {
            match o {
                Origin::Source { .. } => {
                    let mut t = ret.clone();
                    t.origins.retain(|x| matches!(x, Origin::Source { .. }));
                    acc = merge_opt(acc, Some(t));
                }
                Origin::Param(i) => {
                    if let Some(a) = args.get(*i) {
                        acc = merge_opt(acc, self.taint_of(*a, env));
                    }
                }
            }
        }
        let name = self
            .call_name(call)
            .or_else(|| self.method_name(call))
            .unwrap_or_default();
        acc.map(|t| {
            t.cleanse(ret.cleansed)
                .step(line_of(call), format!("Returned from {name}()"))
        })
    }

    fn taint_of_call(&self, n: Node, env: &Env) -> Option<Taint> {
        let name = self.call_name(n)?;
        let args = self.args(n);
        let line = line_of(n);
        match name.as_str() {
            "getallheaders" | "apache_request_headers" | "get_query_var" | "filter_input_array" => {
                return Some(Taint::source(format!("{name}()"), line, false));
            }
            "file_get_contents" | "fopen" | "file" | "stream_get_contents"
                if args
                    .first()
                    .map(|a| self.text(*a).contains("php://input"))
                    .unwrap_or(false) =>
            {
                return Some(Taint::source("php://input".into(), line, false));
            }
            "getenv"
                if args
                    .first()
                    .and_then(|a| self.string_value(*a))
                    .map(|s| s.starts_with("HTTP_"))
                    .unwrap_or(false) =>
            {
                return Some(Taint::source(short(self.text(n), 60), line, false));
            }
            "filter_input" | "filter_var" => {
                let flags = args
                    .iter()
                    .skip(if name == "filter_input" { 2 } else { 1 })
                    .map(|a| self.text(*a))
                    .collect::<String>();
                let validated = [
                    "VALIDATE_INT",
                    "VALIDATE_FLOAT",
                    "VALIDATE_BOOL",
                    "SANITIZE_NUMBER_INT",
                    "SANITIZE_NUMBER_FLOAT",
                    "VALIDATE_BOOLEAN",
                ]
                .iter()
                .any(|f| flags.contains(f));
                if validated {
                    return None;
                }
                let encoded = flags.contains("SANITIZE_SPECIAL_CHARS")
                    || flags.contains("SANITIZE_FULL_SPECIAL_CHARS");
                let t = if name == "filter_input" {
                    Some(Taint::source(short(self.text(n), 60), line, false))
                } else {
                    args.first().and_then(|a| self.taint_of(*a, env))
                };
                return t.map(|t| if encoded { t.cleanse(sink::XSS) } else { t });
            }
            "request" | "input" | "old" if !args.is_empty() => {
                return Some(Taint::source(short(self.text(n), 60), line, true));
            }
            _ => {}
        }
        if FULL_SANITIZERS.contains(name.as_str()) {
            return None;
        }
        if name == "array_map" {
            if let Some(cb) = args.first().and_then(|a| self.string_value(*a)) {
                let cb = normalize_fn(&cb);
                if FULL_SANITIZERS.contains(cb.as_str()) {
                    return None;
                }
                if let Some(mask) = PARTIAL_SANITIZERS.get(cb.as_str()) {
                    return self.args_taint(&args[1..], env).map(|t| t.cleanse(*mask));
                }
            }
        }
        if name == "preg_replace" && args.len() >= 3 {
            let pattern = self.string_value(args[0]).unwrap_or_default();
            let replacement = self.string_value(args[1]);
            if replacement.as_deref() == Some("") {
                if let Some(allowed) = allow_list_class(&pattern) {
                    let t = self.taint_of(args[2], env)?;
                    let unsafe_chars = [
                        '.', '/', '\\', ':', '%', '<', '>', '\'', '"', ';', '&', '|', '$', '`',
                        '(', ')', ' ', '=', '?', '#', '+',
                    ];
                    return if allowed.chars().any(|c| unsafe_chars.contains(&c)) {
                        Some(t.cleanse(sink::XSS | sink::SQL | sink::CMD))
                    } else {
                        None
                    };
                }
            }
        }
        if let Some(mask) = PARTIAL_SANITIZERS.get(name.as_str()) {
            // mysqli_*/pg_* escapers take the connection first and the value last.
            let value = if name.starts_with("mysqli_") || name.starts_with("pg_escape") {
                args.last()
            } else {
                args.first()
            };
            return value
                .and_then(|a| self.taint_of(*a, env))
                .map(|t| t.cleanse(*mask));
        }
        if let Some(s) = self.summaries.get(&name) {
            return self.apply_return_summary(n, s, &args, env);
        }
        if PROPAGATORS.contains(name.as_str()) {
            return self.args_taint(&args, env);
        }
        None
    }

    fn is_request_object(&self, obj: &str) -> bool {
        let o = obj.to_ascii_lowercase();
        o.contains("request")
            || o.ends_with("->input")
            || o == "$input"
            || o.ends_with("->query")
            || o.ends_with("->cookies")
    }

    fn taint_of_method(&self, n: Node, env: &Env) -> Option<Taint> {
        let method = self.method_name(n)?;
        let args = self.args(n);
        let line = line_of(n);
        let receiver = n
            .child_by_field_name("object")
            .or_else(|| n.child_by_field_name("scope"));
        let recv_text = receiver.map(|r| self.text(r)).unwrap_or("");

        if REQUEST_METHODS.contains(&method.as_str()) {
            let is_static = n.kind() == "scoped_call_expression";
            let static_req = is_static
                && matches!(
                    recv_text.trim_start_matches('\\'),
                    "Input" | "Request" | "Illuminate\\Support\\Facades\\Request"
                );
            if static_req || (!is_static && self.is_request_object(recv_text)) {
                return Some(Taint::source(short(self.text(n), 60), line, true));
            }
        }
        match method.as_str() {
            "quote" | "quoteidentifier" | "quotename" | "escape" => {
                return self.args_taint(&args, env).map(|t| t.cleanse(sink::SQL));
            }
            "escape_string" | "real_escape_string" | "escapestring" | "escape_str"
            | "escape_like_str" => {
                return self
                    .args_taint(&args, env)
                    .map(|t| t.cleanse(sink::SQL_ESCAPED));
            }
            "prepare" if recv_text.contains("wpdb") => {
                return self.args_taint(&args, env).map(|t| t.cleanse(sink::SQL));
            }
            "integer" | "boolean" | "float" | "has" | "filled" | "exists" | "count" | "getid" => {
                return None
            }
            _ => {}
        }
        if let Some(s) = self.summaries.get(&method) {
            return self.apply_return_summary(n, s, &args, env);
        }
        // Fluent wrappers around tainted data (e.g. $request->query->get()).
        if let Some(r) = receiver {
            if r.kind() != "name" && self.text(r) != "$this" {
                if let Some(t) = self.taint_of(r, env) {
                    if matches!(
                        method.as_str(),
                        "get"
                            | "getvalue"
                            | "tostring"
                            | "__tostring"
                            | "trim"
                            | "first"
                            | "value"
                            | "getclientoriginalname"
                            | "getclientoriginalextension"
                    ) {
                        return Some(t);
                    }
                }
            }
        }
        None
    }

    fn string_value(&self, n: Node) -> Option<String> {
        match n.kind() {
            "string" | "encapsed_string" | "nowdoc" | "heredoc" => {
                let mut out = String::new();
                let mut ok = true;
                collect_string(n, self.src, &mut out, &mut ok);
                ok.then_some(out)
            }
            _ => None,
        }
    }

    fn is_literal(&self, n: Node) -> bool {
        match n.kind() {
            "string"
            | "nowdoc"
            | "integer"
            | "float"
            | "boolean"
            | "null"
            | "name"
            | "qualified_name"
            | "class_constant_access_expression" => true,
            "encapsed_string" | "heredoc" => self.string_value(n).is_some(),
            "binary_expression" | "parenthesized_expression" => {
                named_children(n).iter().all(|c| self.is_literal(*c))
            }
            _ => false,
        }
    }

    fn references_superglobal(&self, n: Node) -> bool {
        any_descendant(n, &mut |c| {
            c.kind() == "variable_name" && SUPERGLOBALS.contains(&&self.src[c.byte_range()])
        })
    }

    fn contains_call_to(&self, n: Node, names: &[&str]) -> bool {
        any_descendant(n, &mut |c| {
            c.kind() == "function_call_expression"
                && c.child_by_field_name("function")
                    .map(|f| names.contains(&normalize_fn(&self.src[f.byte_range()]).as_str()))
                    .unwrap_or(false)
        })
    }

    // ---- sink checks --------------------------------------------------------------------

    fn apply_param_summary(&mut self, call: Node, name: &str, args: &[Node], env: &Env) {
        let Some(summary) = self.summaries.get(name).cloned() else {
            return;
        };
        for ps in &summary.param_sinks {
            let Some(arg) = args.get(ps.param) else {
                continue;
            };
            let Some(t) = self.taint_of(*arg, env) else {
                continue;
            };
            if t.cleansed & ps.kinds != 0 {
                continue;
            }
            let t = t.step(
                line_of(call),
                format!("Passed to {name}() as argument #{}", ps.param + 1),
            );
            let desc = format!("{} (line {}) via helper {name}()", ps.sink, ps.line);
            self.sink_hit(call, &t, ps.kinds, ps.rule, &desc);
        }
    }

    fn check_function_call(&mut self, n: Node, env: &Env) {
        let args = self.args(n);
        let Some(func) = n.child_by_field_name("function") else {
            return;
        };
        let Some(name) = self.call_name(n) else {
            // Dynamic call: $fn(...), $_GET['f'](...)
            if let Some(t) = self.taint_of(func, env) {
                let direct = self.references_superglobal(func);
                let rule = if direct {
                    "webshell-backdoor"
                } else {
                    "code-injection"
                };
                let desc = format!("dynamic function call {}()", short(self.text(func), 40));
                self.sink_hit(n, &t, sink::CODE, rule, &desc);
            }
            return;
        };
        let sink_desc = format!("{name}()");
        let arg0 = args.first().copied();

        match name.as_str() {
            "eval" | "assert" | "create_function" => {
                if let Some(a) = arg0 {
                    if self.contains_call_to(a, DECODERS) {
                        self.report(
                            n,
                            "obfuscated-execution",
                            Confidence::High,
                            format!(
                                "{name}() executes decoded/decompressed data: {}",
                                short(self.text(a), 80)
                            ),
                            vec![],
                        );
                        return;
                    }
                    if self.references_superglobal(a) {
                        if let Some(t) = self.taint_of(a, env) {
                            if self.sink_hit(n, &t, sink::CODE, "webshell-backdoor", &sink_desc) {
                                return;
                            }
                        }
                    }
                }
                let spec = &FUNCTION_SINKS[name.as_str()];
                if self.check_args(n, &args, spec, &sink_desc, env) {
                    return;
                }
                if let Some(a) = arg0 {
                    let stringish = !matches!(
                        a.kind(),
                        "binary_expression"
                            | "unary_op_expression"
                            | "boolean"
                            | "function_call_expression"
                            | "member_call_expression"
                    ) || self.operator(a) == ".";
                    if name != "assert" || stringish {
                        let lit = self.is_literal(a);
                        if name != "assert" || !lit {
                            let (conf, msg) = if lit {
                                (
                                    Confidence::Low,
                                    format!("{name}() evaluates a constant string as PHP code."),
                                )
                            } else {
                                (Confidence::Medium, format!("{name}() evaluates a dynamically built string as PHP code."))
                            };
                            self.report(n, "dangerous-eval", conf, msg, vec![]);
                        }
                    }
                }
                return;
            }
            "system" | "exec" | "shell_exec" | "passthru" | "popen" | "proc_open"
            | "pcntl_exec" | "expect_popen" => {
                let spec = &FUNCTION_SINKS[name.as_str()];
                if !self.check_args(n, &args, spec, &sink_desc, env) {
                    if let Some(a) = arg0 {
                        if !self.is_literal(a) {
                            self.report(n, "dangerous-exec", Confidence::Low,
                                format!("{name}() runs a shell command built from non-constant data: {}", short(self.text(a), 80)), vec![]);
                        }
                    }
                }
            }
            "header" => {
                if let Some(a) = arg0 {
                    if let Some(t) = self.taint_of(a, env) {
                        let prefix = self.leading_literal(a).to_ascii_lowercase();
                        let rule = if prefix.trim_start().starts_with("location")
                            || prefix.trim_start().starts_with("refresh")
                        {
                            "open-redirect"
                        } else {
                            "header-injection"
                        };
                        self.sink_hit(n, &t, sink::HEADER, rule, "header()");
                    }
                }
            }
            "curl_setopt" => {
                let opt = args.get(1).map(|a| self.text(*a)).unwrap_or("");
                let val = args.get(2).copied();
                if opt.ends_with("CURLOPT_URL") {
                    if let Some(v) = val {
                        if let Some(t) = self.taint_of(v, env) {
                            self.sink_hit(n, &t, sink::URL, "ssrf", "curl_setopt(CURLOPT_URL)");
                        }
                    }
                } else if opt.ends_with("CURLOPT_SSL_VERIFYPEER")
                    || opt.ends_with("CURLOPT_SSL_VERIFYHOST")
                {
                    if let Some(v) = val {
                        if is_falsy_literal(self.text(v)) {
                            self.report(n, "tls-verification-disabled", Confidence::High,
                                format!("{} is disabled; connections are open to man-in-the-middle attacks.", opt.trim_start_matches('\\')), vec![]);
                        }
                    }
                }
            }
            "unserialize" | "maybe_unserialize" => {
                let spec = &FUNCTION_SINKS[name.as_str()];
                if !self.check_args(n, &args, spec, &sink_desc, env)
                    && name == "unserialize"
                    && args.len() < 2
                {
                    if let Some(a) = arg0 {
                        if !self.is_literal(a) {
                            self.report(
                                n,
                                "unsafe-unserialize",
                                Confidence::Medium,
                                "unserialize() called without the allowed_classes option.".into(),
                                vec![],
                            );
                        }
                    }
                }
            }
            "preg_replace" | "preg_filter" => {
                if let Some(pattern) = arg0.and_then(|a| self.string_value(a)) {
                    if regex_has_eval_modifier(&pattern) {
                        self.report(n, "preg-replace-eval", Confidence::High,
                            format!("{name}() uses the /e modifier, which evaluates the replacement as PHP code."), vec![]);
                        if let Some(r) = args.get(1) {
                            if let Some(t) = self.taint_of(*r, env) {
                                self.sink_hit(
                                    n,
                                    &t,
                                    sink::CODE,
                                    "code-injection",
                                    "preg_replace() /e replacement",
                                );
                            }
                        }
                    }
                }
                let spec = &FUNCTION_SINKS[name.as_str()];
                self.check_args(n, &args, spec, &sink_desc, env);
            }
            "parse_str" | "mb_parse_str" => {
                if args.len() == 1 {
                    if let Some(t) = self.taint_of(args[0], env) {
                        self.sink_hit(n, &t, sink::VARS, "variable-overwrite", &sink_desc);
                    }
                }
            }
            "md5" | "sha1" | "crc32" | "hash" | "md5_file" => {
                let target = if name == "hash" {
                    let algo = arg0
                        .and_then(|a| self.string_value(a))
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if !matches!(
                        algo.as_str(),
                        "md5" | "sha1" | "crc32" | "md4" | "sha256" | "sha512"
                    ) {
                        None
                    } else {
                        args.get(1).copied()
                    }
                } else {
                    arg0
                };
                if let Some(t) = target {
                    if PASSWORD_ARG.is_match(self.text(t))
                        && !self.text(t).to_ascii_lowercase().contains("reset")
                    {
                        self.report(
                            n,
                            "weak-password-hash",
                            Confidence::Medium,
                            format!(
                                "Password data hashed with fast digest {name}(): {}",
                                short(self.text(n), 80)
                            ),
                            vec![],
                        );
                    }
                }
            }
            "openssl_encrypt" | "openssl_decrypt" => {
                if let Some(m) = args.get(1).and_then(|a| self.string_value(*a)) {
                    let ml = m.to_ascii_lowercase();
                    if ml.contains("ecb")
                        || ml.starts_with("des")
                        || ml.starts_with("rc4")
                        || ml.starts_with("rc2")
                        || ml.starts_with("bf")
                    {
                        self.report(
                            n,
                            "weak-cipher",
                            Confidence::High,
                            format!("Weak cipher/mode '{m}' used with {name}()."),
                            vec![],
                        );
                    }
                }
            }
            "phpinfo" => self.report(
                n,
                "phpinfo-exposure",
                Confidence::High,
                "phpinfo() exposes server configuration.".into(),
                vec![],
            ),
            "ini_set" => {
                let key = arg0.and_then(|a| self.string_value(a)).unwrap_or_default();
                if PHP2SHELL_DIRECTIVES.contains(&key.as_str()) {
                    self.report(n, "php2shell-ineffective-mitigation", Confidence::High,
                        format!("ini_set('{key}') runs after the request is initialised; PHP's php2shell advisory requires php.ini, an FPM pool or server config."), vec![]);
                }
                if key == "display_errors" || key == "display_startup_errors" {
                    if let Some(v) = args.get(1) {
                        let val = self
                            .string_value(*v)
                            .unwrap_or_else(|| self.text(*v).to_string())
                            .to_ascii_lowercase();
                        if matches!(val.as_str(), "1" | "on" | "true" | "stdout" | "yes") {
                            self.report(
                                n,
                                "display-errors-enabled",
                                Confidence::High,
                                format!("ini_set('{key}') enables error output to clients."),
                                vec![],
                            );
                        }
                    }
                }
            }
            "libxml_disable_entity_loader" => {
                if arg0
                    .map(|a| is_falsy_literal(self.text(a)))
                    .unwrap_or(false)
                {
                    self.report(
                        n,
                        "xxe",
                        Confidence::High,
                        "External entity loader explicitly re-enabled.".into(),
                        vec![],
                    );
                }
            }
            "chmod" | "mkdir" | "umask" => {
                let idx = if name == "umask" { 0 } else { 1 };
                if let Some(mode) = args.get(idx) {
                    let m = self
                        .text(*mode)
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_ascii_lowercase()
                        .replace("0o", "0");
                    let bad = if name == "umask" {
                        m == "0" || m == "000"
                    } else {
                        m.ends_with("777") || m.ends_with("666") || m == "511"
                    };
                    if bad {
                        self.report(
                            n,
                            "insecure-file-permissions",
                            Confidence::High,
                            format!("{name}() with permissive mode {}.", self.text(*mode)),
                            vec![],
                        );
                    }
                }
            }
            _ => {}
        }

        if name.starts_with("mcrypt_") {
            self.report(
                n,
                "weak-cipher",
                Confidence::High,
                format!("{name}() belongs to the removed, unmaintained mcrypt extension."),
                vec![],
            );
        }
        if name.starts_with("mysql_") && !self.mysql_reported && !self.silent {
            self.mysql_reported = true;
            self.report(
                n,
                "deprecated-mysql",
                Confidence::High,
                format!("{name}() uses the mysql extension removed in PHP 7."),
                vec![],
            );
        }

        let handled = matches!(
            name.as_str(),
            "eval"
                | "assert"
                | "create_function"
                | "system"
                | "exec"
                | "shell_exec"
                | "passthru"
                | "popen"
                | "proc_open"
                | "pcntl_exec"
                | "expect_popen"
                | "unserialize"
                | "maybe_unserialize"
                | "preg_replace"
                | "preg_filter"
        );
        if !handled {
            if let Some(spec) = FUNCTION_SINKS.get(name.as_str()) {
                self.check_args(n, &args, spec, &sink_desc, env);
            }
        }
        self.apply_param_summary(n, &name, &args, env);
    }

    fn leading_literal(&self, n: Node) -> String {
        match n.kind() {
            "binary_expression" => n
                .child_by_field_name("left")
                .map(|l| self.leading_literal(l))
                .unwrap_or_default(),
            "encapsed_string" | "string" => named_children(n)
                .first()
                .filter(|c| c.kind() == "string_content")
                .map(|c| self.text(*c).to_string())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }

    fn check_method_call(&mut self, n: Node, env: &Env) {
        let Some(method) = self.method_name(n) else {
            return;
        };
        let args = self.args(n);
        let receiver = n
            .child_by_field_name("object")
            .or_else(|| n.child_by_field_name("scope"));
        let recv = receiver.map(|r| self.text(r)).unwrap_or("");
        let recv_l = recv.to_ascii_lowercase();
        let desc = format!("{}->{}()", short(recv, 30), method);

        match method.as_str() {
            "query" | "evaluate" if recv_l.contains("xpath") => {
                if let Some(a) = args.first() {
                    if let Some(t) = self.taint_of(*a, env) {
                        self.sink_hit(n, &t, sink::XPATH, "xpath-injection", &desc);
                    }
                }
            }
            "loadxml" | "load" | "loadhtml" => {}
            "request"
                if !(recv_l.contains("client")
                    || recv_l.contains("http")
                    || recv_l.contains("guzzle")) => {}
            "get" | "post" | "put" | "delete" | "patch" | "head"
                if recv_l.contains("client")
                    || recv_l.contains("http")
                    || recv_l.contains("guzzle") =>
            {
                if let Some(a) = args.first() {
                    if let Some(t) = self.taint_of(*a, env) {
                        self.sink_hit(n, &t, sink::URL, "ssrf", &desc);
                    }
                }
            }
            "move" if !(recv_l.contains("file") || recv_l.contains("upload")) => {}
            "redirect" | "redirectto" | "away" | "to"
                if recv_l.contains("redirect") || method == "redirect" =>
            {
                if let Some(a) = args.first() {
                    if let Some(t) = self.taint_of(*a, env) {
                        self.sink_hit(n, &t, sink::HEADER, "open-redirect", &desc);
                    }
                }
            }
            _ => {
                if let Some(spec) = METHOD_SINKS.get(method.as_str()) {
                    let is_sql = spec.rule == "sql-injection";
                    let generic = GENERIC_SQL_METHODS.contains(&method.as_str());
                    let skip = is_sql
                        && (recv_l.contains("xpath")
                            || recv_l.contains("request")
                            || recv_l.contains("$this->input"))
                        || generic && !DB_RECEIVER.is_match(recv);
                    if !skip {
                        self.check_args(n, &args, spec, &desc, env);
                    }
                }
            }
        }
        self.apply_param_summary(n, &method, &args, env);
    }

    fn check_new(&mut self, n: Node, env: &Env) {
        let Some(cls) = named_children(n)
            .into_iter()
            .find(|c| matches!(c.kind(), "name" | "qualified_name"))
        else {
            return;
        };
        let name = normalize_fn(self.text(cls));
        let args = self.args(n);
        if let Some(spec) = CLASS_SINKS.get(name.as_str()) {
            let desc = format!("new {}()", self.text(cls));
            self.check_args(n, &args, spec, &desc, env);
        }
    }

    fn check_include(&mut self, n: Node, env: &Env) {
        let Some(path) = n.named_child(0) else { return };
        let kw = n.kind().trim_end_matches("_expression");
        if let Some(t) = self.taint_of(path, env) {
            if self.sink_hit(n, &t, sink::FILE, "file-inclusion", kw) {
                return;
            }
        }
        let text = self.text(path);
        if text.contains("php://input") || text.contains("data://") || text.contains("data:text") {
            self.report(
                n,
                "webshell-backdoor",
                Confidence::High,
                format!("{kw} of a request/data stream executes attacker-supplied code."),
                vec![],
            );
            return;
        }
        let dynamic = any_descendant(path, &mut |c| {
            matches!(
                c.kind(),
                "variable_name"
                    | "member_access_expression"
                    | "function_call_expression"
                    | "member_call_expression"
            ) && !matches!(
                self.src[c.byte_range()].to_ascii_lowercase().as_str(),
                "dirname(__file__)" | "__dir__"
            )
        });
        let anchored = text.starts_with("__DIR__")
            || text.starts_with("dirname(__FILE__)")
            || text.contains("ABSPATH")
            || text.starts_with("APPPATH")
            || text.starts_with("BASEPATH");
        if dynamic && !anchored {
            self.report(
                n,
                "dynamic-include",
                Confidence::Low,
                format!("{kw} with a computed path: {}", short(text, 80)),
                vec![],
            );
        }
    }

    fn check_loose_comparison(&mut self, n: Node) {
        let op = self.operator(n);
        if !matches!(op, "==" | "!=" | "<>") {
            return;
        }
        let (Some(l), Some(r)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        let trivial = |x: Node| -> bool {
            let t = self.text(x).to_ascii_lowercase();
            matches!(x.kind(), "null" | "boolean" | "integer" | "float")
                || t == "''"
                || t == "\"\""
                || t == "null"
                || t == "true"
                || t == "false"
                || t.starts_with("strlen(")
                || t.starts_with("count(")
                || t.starts_with("mb_strlen(")
                || self
                    .string_value(x)
                    .map(|s| {
                        s.len() < 3
                            || s.chars()
                                .all(|c| c.is_ascii_alphabetic() && c.is_ascii_lowercase())
                                && s.len() < 12
                    })
                    .unwrap_or(false)
        };
        if trivial(l) || trivial(r) {
            return;
        }
        let sensitive = |x: Node| -> bool {
            let t = self.text(x);
            SECURITY_NAME.is_match(t)
                && !t.contains("password_verify")
                && !t.contains("hash_equals")
                && !t.contains("_type")
                && !t.contains("Type")
        };
        if sensitive(l) || sensitive(r) {
            self.report(n, "loose-comparison", Confidence::Medium,
                format!("Loose comparison '{}' on a security-sensitive value; use hash_equals() or ===.", short(self.text(n), 80)), vec![]);
        }
    }

    fn check_array_element(&mut self, n: Node) {
        let ch = named_children(n);
        if ch.len() != 2 {
            return;
        }
        let (k, v) = (ch[0], ch[1]);
        let key_text = self
            .string_value(k)
            .unwrap_or_else(|| self.text(k).to_string());
        let val = self.text(v).to_ascii_lowercase();
        let tls_off = match key_text.trim_start_matches('\\') {
            "verify_peer"
            | "verify_peer_name"
            | "verify"
            | "CURLOPT_SSL_VERIFYPEER"
            | "CURLOPT_SSL_VERIFYHOST"
            | "sslverify" => is_falsy_literal(&val),
            "allow_self_signed" => val == "true" || val == "1",
            _ => false,
        };
        if tls_off {
            self.report(
                n,
                "tls-verification-disabled",
                Confidence::High,
                format!(
                    "TLS verification disabled via '{key_text}' => {}.",
                    self.text(v)
                ),
                vec![],
            );
        }
        if k.kind() == "string" || k.kind() == "encapsed_string" {
            self.check_hardcoded(n, Some(key_text), v);
        }
    }

    fn check_hardcoded(&mut self, at: Node, name: Option<String>, value: Node) {
        let Some(mut name) = name else { return };
        if name == "define" {
            return;
        }
        name = name.trim_start_matches('$').to_string();
        if !(CRED_STRONG.is_match(&name) || CRED_WEAK.is_match(&name)) {
            return;
        }
        let Some(val) = self.string_value(value) else {
            return;
        };
        if !looks_like_secret_value(&val, &name) {
            return;
        }
        self.report(
            at,
            "hardcoded-credential",
            Confidence::Medium,
            format!(
                "'{name}' is assigned a hard-coded value ({}).",
                redact(&val)
            ),
            vec![],
        );
    }

    fn check_insecure_random(&mut self, at: Node, l: Node, r: Node) {
        let Some(name) = self.lvalue_name(l) else {
            return;
        };
        if !TOKEN_NAME.is_match(&name) {
            return;
        }
        if self.contains_call_to(r, WEAK_RANDOM) && !self.contains_call_to(r, STRONG_RANDOM) {
            self.report(
                at,
                "insecure-random",
                Confidence::Medium,
                format!(
                    "'{name}' is generated with a non-cryptographic random source: {}",
                    short(self.text(r), 80)
                ),
                vec![],
            );
        }
    }
}

fn collect_functions<'t>(n: Node<'t>, out: &mut Vec<Node<'t>>) {
    if matches!(n.kind(), "function_definition" | "method_declaration") {
        out.push(n);
    }
    let mut c = n.walk();
    for ch in n.named_children(&mut c) {
        collect_functions(ch, out);
    }
}

fn collect_vars<'t>(n: Node<'t>, out: &mut Vec<Node<'t>>) {
    if n.kind() == "variable_name" {
        out.push(n);
        return;
    }
    let mut c = n.walk();
    for ch in n.named_children(&mut c) {
        collect_vars(ch, out);
    }
}

fn flatten_sequence(n: Node) -> Vec<Node> {
    let mut out = Vec::new();
    for c in named_children(n) {
        if c.kind() == "sequence_expression" {
            out.extend(flatten_sequence(c));
        } else {
            out.push(c);
        }
    }
    out
}

fn collect_string(n: Node, src: &str, out: &mut String, ok: &mut bool) {
    for c in named_children(n) {
        match c.kind() {
            "string_content" | "string_value" | "nowdoc_string" => {
                out.push_str(&src[c.byte_range()])
            }
            "escape_sequence" => out.push_str(&src[c.byte_range()]),
            "heredoc_body" | "nowdoc_body" => collect_string(c, src, out, ok),
            "heredoc_start" | "heredoc_end" => {}
            _ => *ok = false,
        }
    }
}

/// For patterns like `/[^a-zA-Z0-9_-]/` (strip everything outside an allow-list),
/// returns the characters that survive, with ranges expanded to a representative.
fn allow_list_class(pattern: &str) -> Option<String> {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^(.)\[\^([^\]]+)\]\+?(.)[a-zA-Z]*$").unwrap());
    let c = RE.captures(pattern)?;
    if c[1] != c[3] {
        return None;
    }
    static OTHER_RANGE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^\\]-[^\]]").unwrap());
    let class = c[2]
        .replace("a-z", "a")
        .replace("A-Z", "A")
        .replace("0-9", "0")
        .replace("\\w", "a")
        .replace("\\d", "0");
    let without_escaped = class.replace("\\-", "");
    if OTHER_RANGE.is_match(
        without_escaped
            .trim_start_matches('-')
            .trim_end_matches('-'),
    ) {
        return None;
    }
    Some(class.replace("\\-", "-").replace('\\', ""))
}

fn is_falsy_literal(s: &str) -> bool {
    let s = s
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    matches!(s.as_str(), "false" | "0" | "\\false" | "no" | "off")
}

fn regex_has_eval_modifier(pattern: &str) -> bool {
    let p = pattern.trim();
    let mut chars = p.chars();
    let Some(open) = chars.next() else {
        return false;
    };
    if open.is_alphanumeric() || open == '\\' || open.is_whitespace() {
        return false;
    }
    let close = match open {
        '(' => ')',
        '{' => '}',
        '[' => ']',
        '<' => '>',
        c => c,
    };
    let Some(end) = p.rfind(close) else {
        return false;
    };
    if end == 0 {
        return false;
    }
    let mods = &p[end + close.len_utf8()..];
    mods.chars().all(|c| c.is_ascii_alphabetic()) && mods.contains('e')
}

fn looks_like_secret_value(val: &str, key: &str) -> bool {
    let v = val.trim();
    if v.len() < 4 || v.len() > 512 {
        return false;
    }
    if v.chars().any(char::is_whitespace) || v.contains('|') || v.starts_with('$') {
        return false;
    }
    if PLACEHOLDER.is_match(v)
        || v.eq_ignore_ascii_case(key)
        || EMAIL.is_match(v)
        || IDENTIFIER.is_match(v)
    {
        return false;
    }
    if v.chars().filter(|c| c.is_ascii_alphanumeric()).count() < 3 {
        return false;
    }
    if v.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && v.contains('_')
    {
        return false; // env-var name reference
    }
    let first = v.chars().next().unwrap();
    if v.chars().all(|c| c == first) {
        return false;
    }
    if v.contains("::") || v.starts_with("http") && !v.contains('@') {
        return false;
    }
    true
}

pub fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 4 {
        return "****".into();
    }
    let keep = (n / 6).clamp(1, 4);
    let head: String = s.chars().take(keep).collect();
    format!("{head}{}", "*".repeat((n - keep).min(12)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_modifier_detection() {
        assert!(regex_has_eval_modifier("/abc/e"));
        assert!(regex_has_eval_modifier("#x#ie"));
        assert!(regex_has_eval_modifier("(.*)e"));
        assert!(!regex_has_eval_modifier("/abc/i"));
        assert!(!regex_has_eval_modifier("/e/"));
    }

    #[test]
    fn allow_list_patterns() {
        assert_eq!(allow_list_class("/[^a-zA-Z0-9_]/").as_deref(), Some("aA0_"));
        assert_eq!(allow_list_class("/[^a-z0-9\\-]+/i").as_deref(), Some("a0-"));
        assert_eq!(allow_list_class("#[^\\w.]#").as_deref(), Some("a."));
        assert!(allow_list_class("/[^!-~]/").is_none());
        assert!(allow_list_class("/[abc]/").is_none());
    }

    #[test]
    fn secret_value_heuristics() {
        assert!(looks_like_secret_value("S3cr3t!pw", "password"));
        assert!(!looks_like_secret_value("", "password"));
        assert!(!looks_like_secret_value("Enter your password", "password"));
        assert!(!looks_like_secret_value("DB_PASSWORD", "password"));
        assert!(!looks_like_secret_value("changeme", "password"));
        assert!(!looks_like_secret_value("required|min:8", "password"));
        assert!(!looks_like_secret_value("[------]", "password"));
        assert!(!looks_like_secret_value("user_pass", "id_password"));
        assert!(!looks_like_secret_value("apiKey", "KEY_API_KEY"));
        assert!(!looks_like_secret_value("anon@ftp.com", "password"));
        assert!(looks_like_secret_value("hunter2", "password"));
    }
}
