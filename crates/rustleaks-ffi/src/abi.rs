//! Numbers and `repr(C)` types of the C ABI. `include/rustleaks.h` declares
//! the same values and layouts, and a unit test compares the two.

/// The ABI number. A wrapper passes it to `rustleaks_options_new`, which
/// fails unless it is equal. Change it whenever a function, a type layout or
/// the meaning of a value changes.
pub const ABI_VERSION: u32 = 1;

/// Status of a call that succeeded.
pub const STATUS_OK: i32 = 0;
/// A pointer, length, key, value or index is not valid.
pub const ERROR_INVALID_ARGUMENT: i32 = 1;
/// The ABI number of the caller is not the ABI number of the library.
pub const ERROR_ABI_MISMATCH: i32 = 2;
/// The configuration could not be loaded. The message is the full core
/// message and can quote configuration text.
pub const ERROR_CONFIG: i32 = 3;
/// A selected rule ID does not exist, or the selection is over a limit.
pub const ERROR_RULE_SELECTION: i32 = 4;
/// The engine could not be built from a valid configuration.
pub const ERROR_ENGINE: i32 = 5;
/// The input is longer than the engine's input limit.
pub const ERROR_INPUT_TOO_LARGE: i32 = 6;
/// Reserved for the language wrappers, for a call on a closed engine. The
/// library never returns it.
pub const ERROR_CLOSED: i32 = 7;
/// The library caught a panic. The call had no other effect.
pub const ERROR_PANIC: i32 = 8;

/// The value of a limit that turns the limit off.
pub const UNLIMITED: u64 = u64::MAX;

/// `rustleaks_options_set_u64` key: decode depth, default 0.
pub const OPTION_DECODE_DEPTH: u32 = 1;
/// `rustleaks_options_set_u64` key: base64 mode, `BASE64_*`, default
/// compatible.
pub const OPTION_BASE64_MODE: u32 = 2;
/// `rustleaks_options_set_u64` key: redaction percent, default 0.
pub const OPTION_REDACTION_PERCENT: u32 = 3;
/// `rustleaks_options_set_u64` key: inclusive input byte limit, default
/// 10,000,000.
pub const OPTION_MAX_INPUT_BYTES: u32 = 4;
/// `rustleaks_options_set_u64` key: decoded byte budget, default unlimited.
pub const OPTION_MAX_DECODED_BYTES: u32 = 5;
/// `rustleaks_options_set_u64` key: work unit budget, default unlimited.
pub const OPTION_MAX_WORK_UNITS: u32 = 6;
/// `rustleaks_options_set_u64` key: finding record budget, default 100,000.
pub const OPTION_MAX_FINDING_RECORDS: u32 = 7;
/// `rustleaks_options_set_u64` key: finding payload byte budget, default
/// unlimited.
pub const OPTION_MAX_FINDING_PAYLOAD_BYTES: u32 = 8;
/// `rustleaks_options_set_u64` key: collected span budget, default
/// unlimited.
pub const OPTION_MAX_COLLECTED_SPANS: u32 = 9;
/// `rustleaks_options_set_u64` key: normalization byte budget, default
/// unlimited.
pub const OPTION_MAX_NORMALIZATION_BYTES: u32 = 10;
/// `rustleaks_options_set_u64` key: number of workers that share the search
/// caches, and of scan threads. 0, the default, means one per available
/// CPU, up to 12. At most `MAX_WORKERS`.
pub const OPTION_WORKERS: u32 = 11;
/// The largest value of `OPTION_WORKERS`.
pub const MAX_WORKERS: u64 = 256;

/// `rustleaks_options_set_bool` key: honor allow comments, default true.
pub const OPTION_ALLOW_COMMENTS: u32 = 1;
/// `rustleaks_options_set_bool` key: run scans on the calling thread
/// instead of the engine's scan threads, default false. A scan can compile a
/// pattern with up to 200 groups on the thread that runs it, so set it only
/// when every calling thread has a large stack, such as 8 MiB.
/// Core can then also wait on the calling thread, for example when two scans
/// compile the same pattern at once, and on Apple platforms such a wait can
/// make a child forked from that thread crash in its first scan there.
pub const OPTION_SCAN_ON_CALLER_THREAD: u32 = 2;

/// Base64 mode `compatible`.
pub const BASE64_COMPATIBLE: u64 = 0;
/// Base64 mode `extended`.
pub const BASE64_EXTENDED: u64 = 1;

/// Scan argument bit: use `decode_depth`.
pub const SCAN_SET_DECODE_DEPTH: u64 = 1 << 0;
/// Scan argument bit: use `base64_mode`.
pub const SCAN_SET_BASE64_MODE: u64 = 1 << 1;
/// Scan argument bit: use `redaction_percent`.
pub const SCAN_SET_REDACTION_PERCENT: u64 = 1 << 2;
/// Scan argument bit: use `allow_comments`.
pub const SCAN_SET_ALLOW_COMMENTS: u64 = 1 << 3;
/// Scan argument bit: use `max_decoded_bytes`.
pub const SCAN_SET_MAX_DECODED_BYTES: u64 = 1 << 4;
/// Scan argument bit: use `max_work_units`.
pub const SCAN_SET_MAX_WORK_UNITS: u64 = 1 << 5;
/// Scan argument bit: use `max_finding_records`.
pub const SCAN_SET_MAX_FINDING_RECORDS: u64 = 1 << 6;
/// Scan argument bit: use `max_finding_payload_bytes`.
pub const SCAN_SET_MAX_FINDING_PAYLOAD_BYTES: u64 = 1 << 7;
/// Scan argument bit: use `max_collected_spans`.
pub const SCAN_SET_MAX_COLLECTED_SPANS: u64 = 1 << 8;
/// Scan argument bit: use `max_normalization_bytes`.
pub const SCAN_SET_MAX_NORMALIZATION_BYTES: u64 = 1 << 9;
/// Scan argument bit: use `deadline_ns`.
pub const SCAN_SET_DEADLINE: u64 = 1 << 10;
/// Every scan argument bit.
pub const SCAN_SET_ALL: u64 = (1 << 11) - 1;

/// The scan finished.
pub const TERMINATION_COMPLETE: i32 = 0;
/// The scan stopped because the cancel handle was set.
pub const TERMINATION_CANCELLED: i32 = 1;
/// The scan stopped because its deadline passed.
pub const TERMINATION_DEADLINE: i32 = 2;
/// The scan stopped because a budget ran out.
pub const TERMINATION_BUDGET: i32 = 3;
/// The scan stopped for a reason this ABI version does not name.
pub const TERMINATION_OTHER: i32 = 4;

/// No budget, or a budget this ABI version does not name.
pub const BUDGET_NONE: i32 = 0;
/// Decoded byte budget.
pub const BUDGET_DECODED_BYTES: i32 = 1;
/// Work unit budget.
pub const BUDGET_WORK_UNITS: i32 = 2;
/// Finding record budget.
pub const BUDGET_FINDING_RECORDS: i32 = 3;
/// Finding payload byte budget.
pub const BUDGET_FINDING_PAYLOAD_BYTES: i32 = 4;
/// Collected span budget.
pub const BUDGET_COLLECTED_SPANS: i32 = 5;
/// Normalization byte budget.
pub const BUDGET_NORMALIZATION_BYTES: i32 = 6;

/// A byte string that the library owns. `ptr` is null when `len` is 0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Bytes {
    /// First byte, or null.
    pub ptr: *const u8,
    /// Number of bytes.
    pub len: usize,
}

impl Bytes {
    /// A view of `bytes`, with a null pointer when it is empty.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            Self::EMPTY
        } else {
            Self {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
            }
        }
    }

    /// The empty view.
    pub const EMPTY: Self = Self {
        ptr: std::ptr::null(),
        len: 0,
    };
}

/// Per-scan arguments. A field is used only when its `SCAN_SET_*` bit is set
/// in `overrides`; otherwise the engine option applies. `path` applies when
/// `path_len` is not 0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ScanArgs {
    /// Path bytes, or null when `path_len` is 0.
    pub path: *const u8,
    /// Number of path bytes.
    pub path_len: usize,
    /// `SCAN_SET_*` bits.
    pub overrides: u64,
    /// Decode depth.
    pub decode_depth: u64,
    /// `BASE64_*` value.
    pub base64_mode: u64,
    /// Redaction percent.
    pub redaction_percent: u64,
    /// Decoded byte budget, or `UNLIMITED`.
    pub max_decoded_bytes: u64,
    /// Work unit budget, or `UNLIMITED`.
    pub max_work_units: u64,
    /// Finding record budget, or `UNLIMITED`.
    pub max_finding_records: u64,
    /// Finding payload byte budget, or `UNLIMITED`.
    pub max_finding_payload_bytes: u64,
    /// Collected span budget, or `UNLIMITED`.
    pub max_collected_spans: u64,
    /// Normalization byte budget, or `UNLIMITED`.
    pub max_normalization_bytes: u64,
    /// Nanoseconds from the start of the call until the scan stops.
    pub deadline_ns: u64,
    /// 1 to honor allow comments, 0 to report the findings on those lines.
    pub allow_comments: u8,
}

/// One rule of an engine, in report order.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuleView {
    /// Rule ID.
    pub id: Bytes,
    /// Rule description.
    pub description: Bytes,
    /// Tags, or null when `tag_count` is 0.
    pub tags: *const Bytes,
    /// Number of tags.
    pub tag_count: usize,
    /// Keywords, or null when `keyword_count` is 0.
    pub keywords: *const Bytes,
    /// Number of keywords.
    pub keyword_count: usize,
}

/// One finding of a result.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FindingView {
    /// Rule ID.
    pub rule_id: Bytes,
    /// Rule description.
    pub description: Bytes,
    /// Rule and decoding tags, or null when `tag_count` is 0.
    pub tags: *const Bytes,
    /// Number of tags.
    pub tag_count: usize,
    /// The secret.
    pub secret: Bytes,
    /// The text that the rule matched.
    pub match_text: Bytes,
    /// The source line that holds the match.
    pub line: Bytes,
    /// The path passed to the scan, unchanged.
    pub path: Bytes,
    /// First line of the match.
    pub start_line: u64,
    /// Last line of the match.
    pub end_line: u64,
    /// Column of the first byte of the match.
    pub start_column: u64,
    /// Column of the last byte of the match.
    pub end_column: u64,
    /// Start of the secret in the input, when `secret_range_exact` is 1.
    pub secret_start: u64,
    /// End of the secret in the input, when `secret_range_exact` is 1.
    pub secret_end: u64,
    /// Start of the match in the input, when `match_range_exact` is 1.
    pub match_start: u64,
    /// End of the match in the input, when `match_range_exact` is 1.
    pub match_end: u64,
    /// Shannon entropy of the secret.
    pub entropy: f64,
    /// 1 when `secret_start` and `secret_end` are exact input offsets.
    pub secret_range_exact: u8,
    /// 1 when `match_start` and `match_end` are exact input offsets.
    pub match_range_exact: u8,
}

/// How a scan ended and what it used.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusView {
    /// `TERMINATION_*` value.
    pub termination: i32,
    /// `BUDGET_*` value when `termination` is `TERMINATION_BUDGET`.
    pub budget: i32,
    /// The budget's inclusive limit.
    pub limit: u64,
    /// Units used before the operation that did not fit.
    pub consumed: u64,
    /// Units that operation asked for.
    pub requested: u64,
    /// Decoded bytes used.
    pub decoded_bytes: u64,
    /// Work units used.
    pub work_units: u64,
    /// Finding records used.
    pub finding_records: u64,
    /// Finding payload bytes used.
    pub finding_payload_bytes: u64,
    /// Collected spans used.
    pub collected_spans: u64,
    /// Normalization bytes used.
    pub normalization_bytes: u64,
}
