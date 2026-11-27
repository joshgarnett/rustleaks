/*
 * The private C ABI of the Rustleaks Go and Python bindings.
 *
 * This header is not a public interface. It changes with every ABI number.
 * A wrapper ships with a library of the same version and passes
 * RUSTLEAKS_ABI_VERSION to rustleaks_options_new, which fails with
 * RUSTLEAKS_ERROR_ABI_MISMATCH unless the numbers are equal.
 *
 * Status: every function returns RUSTLEAKS_OK (0) or a RUSTLEAKS_ERROR_*
 * kind. A panic inside the library returns RUSTLEAKS_ERROR_PANIC.
 * rustleaks_engine_new and rustleaks_scan also return an error handle when
 * they fail and their error pointer is not null. Free it with
 * rustleaks_error_free. Their error pointer can be NULL: the call then
 * returns only the status, and no error handle is made.
 *
 * Pointers:
 * - A function that returns a handle first writes NULL to its out
 *   parameter, and writes the handle only when it returns RUSTLEAKS_OK.
 * - A byte pointer with a length of 0 can be NULL. Otherwise it points to
 *   that many readable bytes that do not change during the call. The
 *   library copies every input before the call returns.
 * - A NULL or misaligned handle or out pointer gives
 *   RUSTLEAKS_ERROR_INVALID_ARGUMENT, except a NULL error pointer, which
 *   is allowed. A misaligned error pointer is invalid. The library cannot detect a freed or
 *   wrong handle; passing one is undefined behavior.
 * - Views (rustleaks_bytes, rule, finding and status views) point into the
 *   handle that produced them and are valid until that handle is freed. A
 *   view with a length or count of 0 has a NULL pointer.
 * - Free each handle once, with its own free function. Every free function
 *   accepts NULL.
 *
 * Threads: an engine can scan on many threads at once, and a cancel handle
 * can be set from any thread. Options, results and errors are used by one
 * thread at a time. rustleaks_engine_new builds the engine on a new thread
 * with an 8 MiB stack and starts one scan thread per worker with the same
 * stack. A scan runs on a free scan thread while the caller waits, unless
 * RUSTLEAKS_OPTION_SCAN_ON_CALLER_THREAD is set. rustleaks_engine_free joins
 * the scan threads. Starting a thread can fail in a restricted process; the
 * error is RUSTLEAKS_ERROR_ENGINE.
 *
 * Run at most rustleaks_engine_workers scans with one engine at once. A
 * scan beyond that waits in a queue for a free scan thread, and while it
 * waits neither its deadline nor its cancel handle is checked.
 *
 * Fork: a forked child has none of the parent's scan threads, and the
 * engine's locks may have been held at the fork. In the child, every engine
 * function on a handle made before the fork returns RUSTLEAKS_ERROR_CLOSED,
 * except rustleaks_engine_free, which releases nothing and returns
 * RUSTLEAKS_OK. Build a new engine in the child. The parent's handles stay
 * valid in the parent. Options, cancel handles, results and errors hold no
 * threads and can be used and freed in the child.
 *
 * Text: rule IDs, descriptions, tags, keywords and error messages are
 * UTF-8. Secrets, matches, lines and paths are the scanned and given bytes.
 */
#ifndef RUSTLEAKS_H
#define RUSTLEAKS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RUSTLEAKS_ABI_VERSION 1

/* Status and error kinds. */
#define RUSTLEAKS_OK 0
#define RUSTLEAKS_ERROR_INVALID_ARGUMENT 1
#define RUSTLEAKS_ERROR_ABI_MISMATCH 2
/* The message is the full core message and can quote configuration text. */
#define RUSTLEAKS_ERROR_CONFIG 3
#define RUSTLEAKS_ERROR_RULE_SELECTION 4
#define RUSTLEAKS_ERROR_ENGINE 5
#define RUSTLEAKS_ERROR_INPUT_TOO_LARGE 6
/*
 * An engine handle used in a process other than the one that made it, such
 * as a forked child. Wrappers also use it for an engine they closed.
 */
#define RUSTLEAKS_ERROR_CLOSED 7
#define RUSTLEAKS_ERROR_PANIC 8

/* A limit with this value is off. */
#define RUSTLEAKS_UNLIMITED UINT64_MAX

/* Keys for rustleaks_options_set_u64. */
#define RUSTLEAKS_OPTION_DECODE_DEPTH 1                /* default 0 */
#define RUSTLEAKS_OPTION_BASE64_MODE 2                 /* default compatible */
#define RUSTLEAKS_OPTION_REDACTION_PERCENT 3           /* default 0 */
#define RUSTLEAKS_OPTION_MAX_INPUT_BYTES 4             /* default 10000000 */
#define RUSTLEAKS_OPTION_MAX_DECODED_BYTES 5           /* default unlimited */
#define RUSTLEAKS_OPTION_MAX_WORK_UNITS 6              /* default unlimited */
#define RUSTLEAKS_OPTION_MAX_FINDING_RECORDS 7         /* default 100000 */
#define RUSTLEAKS_OPTION_MAX_FINDING_PAYLOAD_BYTES 8   /* default unlimited */
#define RUSTLEAKS_OPTION_MAX_COLLECTED_SPANS 9         /* default unlimited */
#define RUSTLEAKS_OPTION_MAX_NORMALIZATION_BYTES 10    /* default unlimited */
/*
 * Workers that share the search caches, and scan threads. 0, the default,
 * means one per available CPU, up to 12. At most RUSTLEAKS_MAX_WORKERS.
 */
#define RUSTLEAKS_OPTION_WORKERS 11
#define RUSTLEAKS_MAX_WORKERS 256

/* Keys for rustleaks_options_set_bool. */
#define RUSTLEAKS_OPTION_ALLOW_COMMENTS 1              /* default 1 */
/*
 * Default 0: scans run on the engine's scan threads. 1 runs scans on the
 * calling thread, which saves a thread hand-off per scan. A scan can compile
 * a pattern with up to 200 groups on the thread that runs it, so set it only
 * when every calling thread has a large stack, such as 8 MiB. Core can then
 * also wait on the calling thread, for example when two scans compile the
 * same pattern at once, and on Apple platforms such a wait can make a child
 * forked from that thread crash in its first scan there.
 */
#define RUSTLEAKS_OPTION_SCAN_ON_CALLER_THREAD 2

/* Base64 modes. */
#define RUSTLEAKS_BASE64_COMPATIBLE 0
#define RUSTLEAKS_BASE64_EXTENDED 1

/* Bits of rustleaks_scan_args.overrides. */
#define RUSTLEAKS_SCAN_SET_DECODE_DEPTH 1
#define RUSTLEAKS_SCAN_SET_BASE64_MODE 2
#define RUSTLEAKS_SCAN_SET_REDACTION_PERCENT 4
#define RUSTLEAKS_SCAN_SET_ALLOW_COMMENTS 8
#define RUSTLEAKS_SCAN_SET_MAX_DECODED_BYTES 16
#define RUSTLEAKS_SCAN_SET_MAX_WORK_UNITS 32
#define RUSTLEAKS_SCAN_SET_MAX_FINDING_RECORDS 64
#define RUSTLEAKS_SCAN_SET_MAX_FINDING_PAYLOAD_BYTES 128
#define RUSTLEAKS_SCAN_SET_MAX_COLLECTED_SPANS 256
#define RUSTLEAKS_SCAN_SET_MAX_NORMALIZATION_BYTES 512
#define RUSTLEAKS_SCAN_SET_DEADLINE 1024
#define RUSTLEAKS_SCAN_SET_ALL 2047

/* rustleaks_status_view.termination. */
#define RUSTLEAKS_TERMINATION_COMPLETE 0
#define RUSTLEAKS_TERMINATION_CANCELLED 1
#define RUSTLEAKS_TERMINATION_DEADLINE 2
#define RUSTLEAKS_TERMINATION_BUDGET 3
/* Stopped early for a reason this ABI version does not name. */
#define RUSTLEAKS_TERMINATION_OTHER 4

/* rustleaks_status_view.budget. */
#define RUSTLEAKS_BUDGET_NONE 0
#define RUSTLEAKS_BUDGET_DECODED_BYTES 1
#define RUSTLEAKS_BUDGET_WORK_UNITS 2
#define RUSTLEAKS_BUDGET_FINDING_RECORDS 3
#define RUSTLEAKS_BUDGET_FINDING_PAYLOAD_BYTES 4
#define RUSTLEAKS_BUDGET_COLLECTED_SPANS 5
#define RUSTLEAKS_BUDGET_NORMALIZATION_BYTES 6

typedef struct rustleaks_options rustleaks_options;
typedef struct rustleaks_engine rustleaks_engine;
typedef struct rustleaks_cancel rustleaks_cancel;
typedef struct rustleaks_result rustleaks_result;
typedef struct rustleaks_error rustleaks_error;

typedef struct rustleaks_bytes {
    const uint8_t *ptr;
    size_t len;
} rustleaks_bytes;

/*
 * Per-scan arguments. A field applies only when its RUSTLEAKS_SCAN_SET_* bit
 * is set in overrides; otherwise the engine option applies. Unknown bits
 * give RUSTLEAKS_ERROR_INVALID_ARGUMENT. path applies when path_len is not
 * 0. deadline_ns counts nanoseconds from the start of the call.
 * allow_comments is 0 or 1. Budgets take RUSTLEAKS_UNLIMITED.
 */
typedef struct rustleaks_scan_args {
    const uint8_t *path;
    size_t path_len;
    uint64_t overrides;
    uint64_t decode_depth;
    uint64_t base64_mode;
    uint64_t redaction_percent;
    uint64_t max_decoded_bytes;
    uint64_t max_work_units;
    uint64_t max_finding_records;
    uint64_t max_finding_payload_bytes;
    uint64_t max_collected_spans;
    uint64_t max_normalization_bytes;
    uint64_t deadline_ns;
    uint8_t allow_comments;
} rustleaks_scan_args;

typedef struct rustleaks_rule_view {
    rustleaks_bytes id;
    rustleaks_bytes description;
    const rustleaks_bytes *tags;
    size_t tag_count;
    const rustleaks_bytes *keywords;
    size_t keyword_count;
} rustleaks_rule_view;

/*
 * One finding. path is the path given to the scan, unchanged. Lines and
 * columns follow the report rules; a finding of a rule with only a path
 * pattern has line and column 0. The secret and match ranges are byte
 * offsets into the input, valid only when the matching *_exact field is 1.
 */
typedef struct rustleaks_finding_view {
    rustleaks_bytes rule_id;
    rustleaks_bytes description;
    const rustleaks_bytes *tags;
    size_t tag_count;
    rustleaks_bytes secret;
    rustleaks_bytes match_text;
    rustleaks_bytes line;
    rustleaks_bytes path;
    uint64_t start_line;
    uint64_t end_line;
    uint64_t start_column;
    uint64_t end_column;
    uint64_t secret_start;
    uint64_t secret_end;
    uint64_t match_start;
    uint64_t match_end;
    double entropy;
    uint8_t secret_range_exact;
    uint8_t match_range_exact;
} rustleaks_finding_view;

/*
 * How a scan ended. limit, consumed and requested describe the budget that
 * ran out when termination is RUSTLEAKS_TERMINATION_BUDGET, and are 0
 * otherwise. The other fields are what the scan used.
 */
typedef struct rustleaks_status_view {
    int32_t termination;
    int32_t budget;
    uint64_t limit;
    uint64_t consumed;
    uint64_t requested;
    uint64_t decoded_bytes;
    uint64_t work_units;
    uint64_t finding_records;
    uint64_t finding_payload_bytes;
    uint64_t collected_spans;
    uint64_t normalization_bytes;
} rustleaks_status_view;

/* Library identity. The version bytes live as long as the library. */
int32_t rustleaks_abi_version(uint32_t *out);
int32_t rustleaks_version(const uint8_t **out_ptr, size_t *out_len);

/*
 * Engine options. Without a configuration the engine has every built-in
 * rule. A configuration replaces them; [extend] useDefault = true adds them
 * again, and [extend] path fails because the library reads no files.
 * Without rule IDs every rule reports findings. A configuration with no
 * rules, including an empty one, is valid: it builds an engine that reports
 * nothing. Options are copied by rustleaks_engine_new and can be freed
 * after it.
 */
int32_t rustleaks_options_new(uint32_t abi_version, rustleaks_options **out);
int32_t rustleaks_options_set_config(rustleaks_options *options, const uint8_t *config, size_t config_len);
int32_t rustleaks_options_add_rule_id(rustleaks_options *options, const uint8_t *id, size_t id_len);
int32_t rustleaks_options_set_u64(rustleaks_options *options, uint32_t key, uint64_t value);
int32_t rustleaks_options_set_bool(rustleaks_options *options, uint32_t key, uint8_t value);
int32_t rustleaks_options_free(rustleaks_options *options);

/* Engines. Rules are listed in report order. */
int32_t rustleaks_engine_new(const rustleaks_options *options, rustleaks_engine **out, rustleaks_error **error);
int32_t rustleaks_engine_free(rustleaks_engine *engine);
int32_t rustleaks_engine_workers(const rustleaks_engine *engine, size_t *out);
/* The inclusive input limit in bytes, or RUSTLEAKS_UNLIMITED. */
int32_t rustleaks_engine_max_input_bytes(const rustleaks_engine *engine, uint64_t *out);
int32_t rustleaks_engine_rule_count(const rustleaks_engine *engine, size_t *out);
int32_t rustleaks_engine_rule(const rustleaks_engine *engine, size_t index, rustleaks_rule_view *out);

/* Cancel handles. Free one only after every scan that uses it returned. */
int32_t rustleaks_cancel_new(rustleaks_cancel **out);
int32_t rustleaks_cancel_set(const rustleaks_cancel *cancel);
int32_t rustleaks_cancel_free(rustleaks_cancel *cancel);

/*
 * Scans input_len bytes. args and cancel can be NULL. An input longer than
 * the engine's input limit fails with RUSTLEAKS_ERROR_INPUT_TOO_LARGE. A
 * scan that stops early still returns RUSTLEAKS_OK and a result; check its
 * status. A scan that completes is complete even if its deadline passed
 * after the last check.
 *
 * The deadline and the cancel handle are checked between engine work
 * units, not during one. One long step, such as one pattern search or the
 * keyword pass over a large plain-text input, runs to its end first, so a
 * scan can stop well after its deadline. Each check with a deadline reads
 * the clock.
 */
int32_t rustleaks_scan(const rustleaks_engine *engine, const uint8_t *input, size_t input_len, const rustleaks_scan_args *args, const rustleaks_cancel *cancel, rustleaks_result **out, rustleaks_error **error);

/* Results. */
int32_t rustleaks_result_status(const rustleaks_result *result, rustleaks_status_view *out);
int32_t rustleaks_result_count(const rustleaks_result *result, size_t *out);
int32_t rustleaks_result_finding(const rustleaks_result *result, size_t index, rustleaks_finding_view *out);
int32_t rustleaks_result_free(rustleaks_result *result);

/* Errors. */
int32_t rustleaks_error_kind(const rustleaks_error *error, int32_t *out);
int32_t rustleaks_error_message(const rustleaks_error *error, const uint8_t **out_ptr, size_t *out_len);
int32_t rustleaks_error_free(rustleaks_error *error);

#ifdef __cplusplus
}
#endif

#endif /* RUSTLEAKS_H */
