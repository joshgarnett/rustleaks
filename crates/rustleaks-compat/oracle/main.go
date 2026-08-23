// The oracle is development/test tooling, never a production dependency.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/fatih/semgroup"
	"github.com/spf13/viper"
	baseconfig "github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/detect/codec"
	"github.com/zricethezav/gitleaks/v8/logging"
	gitleaksregexp "github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const protocolVersion = 1
const regexProtocolVersion = 1
const detectProtocolVersion = 1
const allowlistProtocolVersion = 1
const decoderProtocolVersion = 1
const compositeProtocolVersion = 1
const sessionProtocolVersion = 1
const sourceProtocolVersion = 1
const gitProtocolVersion = 1
const reportProtocolVersion = 1
const upstreamRevision = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
const defaultConfigSHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"

type request struct {
	ProtocolVersion int             `json:"protocol_version"`
	ID              string          `json:"id"`
	UseDefault      bool            `json:"use_default"`
	ConfigBase64    string          `json:"config_base64,omitempty"`
	Fragment        requestFragment `json:"fragment"`
	Options         requestOptions  `json:"options,omitempty"`
}

type requestFragment struct {
	ContentBase64     string `json:"content_base64"`
	FileBase64        string `json:"file_base64,omitempty"`
	WindowsFileBase64 string `json:"windows_file_base64,omitempty"`
	SymlinkFileBase64 string `json:"symlink_file_base64,omitempty"`
	CommitBase64      string `json:"commit_base64,omitempty"`
	StartLine         int    `json:"start_line"`
	AuthorBase64      string `json:"author_base64,omitempty"`
	EmailBase64       string `json:"email_base64,omitempty"`
	DateBase64        string `json:"date_base64,omitempty"`
	MessageBase64     string `json:"message_base64,omitempty"`
	RemoteURLBase64   string `json:"remote_url_base64,omitempty"`
	RemotePlatform    string `json:"remote_platform,omitempty"`
	Inherited         bool   `json:"inherited_from_finding,omitempty"`
}

type requestOptions struct {
	MaxDecodeDepth    int  `json:"max_decode_depth"`
	MaxTargetMB       int  `json:"max_target_megabytes"`
	RedactPercent     uint `json:"redact_percent"`
	IgnoreAllowMarker bool `json:"ignore_allow_marker"`
}

type response struct {
	ProtocolVersion     int             `json:"protocol_version"`
	ID                  string          `json:"id"`
	UpstreamRevision    string          `json:"upstream_revision"`
	DefaultConfigSHA256 string          `json:"default_config_sha256"`
	GoVersion           string          `json:"go_version"`
	Findings            []oracleFinding `json:"findings"`
	Error               *oracleError    `json:"error"`
}

type oracleError struct {
	Class   string `json:"class"`
	Message string `json:"message"`
}

type oracleFinding struct {
	RuleID         string   `json:"rule_id"`
	DescriptionB64 string   `json:"description_base64"`
	StartLine      int      `json:"start_line"`
	EndLine        int      `json:"end_line"`
	StartColumn    int      `json:"start_column"`
	EndColumn      int      `json:"end_column"`
	LineB64        string   `json:"line_base64"`
	MatchB64       string   `json:"match_base64"`
	SecretB64      string   `json:"secret_base64"`
	FileB64        string   `json:"file_base64"`
	SymlinkFileB64 string   `json:"symlink_file_base64"`
	CommitB64      string   `json:"commit_base64"`
	LinkB64        string   `json:"link_base64"`
	EntropyBits    uint32   `json:"entropy_bits"`
	AuthorB64      string   `json:"author_base64"`
	EmailB64       string   `json:"email_base64"`
	DateB64        string   `json:"date_base64"`
	MessageB64     string   `json:"message_base64"`
	TagsB64        []string `json:"tags_base64"`
	FingerprintB64 string   `json:"fingerprint_base64"`
}

// detectRequest and detectResponse form the frozen direct-fragment protocol.
// They are intentionally separate from the bootstrap protocol above:
// adding fields here cannot silently change an older golden. Every value that
// may originate in source bytes is base64 encoded, including metadata and all
// finding text. The protocol scans exactly one fragment with decoding disabled
// by the corpus unless a request explicitly says otherwise.
type detectRequest struct {
	ProtocolVersion int             `json:"protocol_version"`
	ID              string          `json:"id"`
	BehaviorIDs     []string        `json:"behavior_ids"`
	TestCaseIDs     []string        `json:"test_case_ids"`
	AssertionIDs    []string        `json:"assertion_ids"`
	UseDefault      bool            `json:"use_default"`
	ConfigBase64    string          `json:"config_base64,omitempty"`
	Fragment        requestFragment `json:"fragment"`
	Options         requestOptions  `json:"options"`
}

type detectResponse struct {
	ProtocolVersion     int             `json:"protocol_version"`
	OracleMode          string          `json:"oracle_mode"`
	ID                  string          `json:"id"`
	BehaviorIDs         []string        `json:"behavior_ids"`
	TestCaseIDs         []string        `json:"test_case_ids"`
	AssertionIDs        []string        `json:"assertion_ids"`
	UpstreamRevision    string          `json:"upstream_revision"`
	DefaultConfigSHA256 string          `json:"default_config_sha256"`
	GoVersion           string          `json:"go_version"`
	ConfigSHA256        string          `json:"config_sha256"`
	InputSHA256         string          `json:"input_sha256"`
	TotalBytes          uint64          `json:"total_bytes"`
	Findings            []directFinding `json:"findings"`
	Error               *oracleError    `json:"error"`
}

type directFinding struct {
	RuleID            string                  `json:"rule_id"`
	DescriptionBase64 string                  `json:"description_base64"`
	StartLine         int                     `json:"start_line"`
	EndLine           int                     `json:"end_line"`
	StartColumn       int                     `json:"start_column"`
	EndColumn         int                     `json:"end_column"`
	LineBase64        string                  `json:"line_base64"`
	MatchBase64       string                  `json:"match_base64"`
	SecretBase64      string                  `json:"secret_base64"`
	FileBase64        string                  `json:"file_base64"`
	SymlinkFileBase64 string                  `json:"symlink_file_base64"`
	CommitBase64      string                  `json:"commit_base64"`
	LinkBase64        string                  `json:"link_base64"`
	EntropyBits       uint32                  `json:"entropy_bits"`
	AuthorBase64      string                  `json:"author_base64"`
	EmailBase64       string                  `json:"email_base64"`
	DateBase64        string                  `json:"date_base64"`
	MessageBase64     string                  `json:"message_base64"`
	TagsBase64        []string                `json:"tags_base64"`
	FingerprintBase64 string                  `json:"fingerprint_base64"`
	Fragment          *directFragmentSnapshot `json:"fragment"`
	RequiredFindings  []directRequiredFinding `json:"required_findings"`
}

// Direct detector findings do not retain a Fragment at this pinned revision,
// but the explicit nullable field prevents a future comparator from silently
// omitting the public report.Finding field.
type directFragmentSnapshot struct {
	RawBase64         string `json:"raw_base64"`
	BytesBase64       string `json:"bytes_base64"`
	FileBase64        string `json:"file_base64"`
	WindowsFileBase64 string `json:"windows_file_base64"`
	SymlinkFileBase64 string `json:"symlink_file_base64"`
	CommitBase64      string `json:"commit_base64"`
	StartLine         int    `json:"start_line"`
	Inherited         bool   `json:"inherited_from_finding"`
}

type directRequiredFinding struct {
	RuleID       string `json:"rule_id"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
	StartColumn  int    `json:"start_column"`
	EndColumn    int    `json:"end_column"`
	LineBase64   string `json:"line_base64"`
	MatchBase64  string `json:"match_base64"`
	SecretBase64 string `json:"secret_base64"`
}

// decoderRequest is the versioned decoder protocol. Byte-bearing values
// are base64 encoded so arbitrary Go strings reach the pinned codec unchanged.
// Decode requests may contain several inputs; every input is run through the
// same Decoder instance to expose cache-repeat behavior without relying on
// timing. Detect requests use the ordinary translated-config detector path.
type decoderRequest struct {
	ProtocolVersion   int             `json:"protocol_version"`
	ID                string          `json:"id"`
	BehaviorIDs       []string        `json:"behavior_ids"`
	TestCaseIDs       []string        `json:"test_case_ids"`
	Operation         string          `json:"operation"`
	InputsBase64      []string        `json:"inputs_base64,omitempty"`
	SourceBase64      string          `json:"source_base64,omitempty"`
	SourceTransform   string          `json:"source_transform,omitempty"`
	DecoderScope      string          `json:"decoder_scope,omitempty"`
	CarryPredecessors bool            `json:"carry_predecessors_across_inputs,omitempty"`
	PassLimit         int             `json:"pass_limit,omitempty"`
	ProbeRanges       [][2]int        `json:"probe_ranges,omitempty"`
	UseDefault        bool            `json:"use_default,omitempty"`
	ConfigBase64      string          `json:"config_base64,omitempty"`
	ConfigFixture     string          `json:"config_fixture,omitempty"`
	Fragment          requestFragment `json:"fragment,omitempty"`
	Options           requestOptions  `json:"options,omitempty"`
	DetectRepeatCount int             `json:"detect_repeat_count,omitempty"`
}

type decoderResponse struct {
	ProtocolVersion           int               `json:"protocol_version"`
	OracleMode                string            `json:"oracle_mode"`
	ID                        string            `json:"id"`
	BehaviorIDs               []string          `json:"behavior_ids"`
	TestCaseIDs               []string          `json:"test_case_ids"`
	UpstreamRevision          string            `json:"upstream_revision"`
	DefaultConfigSHA256       string            `json:"default_config_sha256"`
	GoVersion                 string            `json:"go_version"`
	Operation                 string            `json:"operation"`
	InputSHA256               string            `json:"input_sha256"`
	ConfigSHA256              string            `json:"config_sha256"`
	TotalBytes                uint64            `json:"total_bytes"`
	RequestedMaxDecodeDepth   int               `json:"requested_max_decode_depth"`
	RustAdapterMaxDecodeDepth int               `json:"rust_adapter_max_decode_depth"`
	Runs                      []decoderRun      `json:"runs"`
	Findings                  []directFinding   `json:"findings"`
	FindingRuns               [][]directFinding `json:"finding_runs"`
	Error                     *oracleError      `json:"error"`
}

type decoderRun struct {
	InputBase64      string              `json:"input_base64"`
	InputSHA256      string              `json:"input_sha256"`
	FullDecodeBase64 string              `json:"full_decode_base64"`
	Terminated       bool                `json:"terminated"`
	CacheBefore      []decoderCacheEntry `json:"cache_before"`
	CacheAfter       []decoderCacheEntry `json:"cache_after"`
	Passes           []decoderPass       `json:"passes"`
}

type decoderCacheEntry struct {
	EncodedBase64 string `json:"encoded_base64"`
	DecodedBase64 string `json:"decoded_base64"`
}

type decoderPass struct {
	Pass              int                 `json:"pass"`
	InputBase64       string              `json:"input_base64"`
	OutputBase64      string              `json:"output_base64"`
	CacheBefore       []decoderCacheEntry `json:"cache_before"`
	CacheAfter        []decoderCacheEntry `json:"cache_after"`
	Segments          []decoderSegment    `json:"segments"`
	TagsBase64        []string            `json:"tags_base64"`
	CurrentLineBase64 string              `json:"current_line_base64"`
	Probes            []decoderProbe      `json:"probes"`
}

type decoderSegment struct {
	Index              int      `json:"index"`
	Original           [2]int   `json:"original"`
	Encoded            [2]int   `json:"encoded"`
	Decoded            [2]int   `json:"decoded"`
	DecodedValueBase64 string   `json:"decoded_value_base64"`
	EncodingMask       int64    `json:"encoding_mask"`
	EncodingKinds      []string `json:"encoding_kinds"`
	Depth              int64    `json:"depth"`
	PredecessorIndices []int    `json:"predecessor_indices"`
}

type decoderProbe struct {
	Range                 [2]int `json:"range"`
	Adjusted              [2]int `json:"adjusted"`
	OverlapSegmentIndices []int  `json:"overlap_segment_indices"`
}

// compositeRequest is the required-rule and final-filter protocol.
// It is separate from the decoder protocol so required-finding and redaction
// schema changes cannot silently rewrite the decoder corpus.
type compositeRequest struct {
	ProtocolVersion int                     `json:"protocol_version"`
	ID              string                  `json:"id"`
	BehaviorIDs     []string                `json:"behavior_ids"`
	TestCaseIDs     []string                `json:"test_case_ids"`
	Operation       string                  `json:"operation"`
	UseDefault      bool                    `json:"use_default,omitempty"`
	ConfigBase64    string                  `json:"config_base64,omitempty"`
	ConfigFixture   string                  `json:"config_fixture,omitempty"`
	ConfigEntry     string                  `json:"config_entry,omitempty"`
	ConfigFiles     []allowlistConfigFile   `json:"config_files,omitempty"`
	ConfigWorkdir   string                  `json:"config_working_directory,omitempty"`
	Fragment        requestFragment         `json:"fragment,omitempty"`
	Options         requestOptions          `json:"options,omitempty"`
	Redaction       compositeFindingInput   `json:"redaction,omitempty"`
	FilterInputs    []compositeFindingInput `json:"filter_inputs,omitempty"`
	RedactPercent   uint                    `json:"redact_percent,omitempty"`
}

type compositeFindingInput struct {
	RuleID            string                  `json:"rule_id"`
	DescriptionBase64 string                  `json:"description_base64"`
	StartLine         int                     `json:"start_line"`
	EndLine           int                     `json:"end_line"`
	StartColumn       int                     `json:"start_column"`
	EndColumn         int                     `json:"end_column"`
	LineBase64        string                  `json:"line_base64"`
	MatchBase64       string                  `json:"match_base64"`
	SecretBase64      string                  `json:"secret_base64"`
	FileBase64        string                  `json:"file_base64"`
	SymlinkFileBase64 string                  `json:"symlink_file_base64"`
	CommitBase64      string                  `json:"commit_base64"`
	LinkBase64        string                  `json:"link_base64"`
	EntropyBits       uint32                  `json:"entropy_bits"`
	AuthorBase64      string                  `json:"author_base64"`
	EmailBase64       string                  `json:"email_base64"`
	DateBase64        string                  `json:"date_base64"`
	MessageBase64     string                  `json:"message_base64"`
	TagsBase64        []string                `json:"tags_base64"`
	FingerprintBase64 string                  `json:"fingerprint_base64"`
	Fragment          *directFragmentSnapshot `json:"fragment,omitempty"`
	RequiredFindings  []directRequiredFinding `json:"required_findings,omitempty"`
}

type compositeResponse struct {
	ProtocolVersion     int             `json:"protocol_version"`
	OracleMode          string          `json:"oracle_mode"`
	ID                  string          `json:"id"`
	BehaviorIDs         []string        `json:"behavior_ids"`
	TestCaseIDs         []string        `json:"test_case_ids"`
	UpstreamRevision    string          `json:"upstream_revision"`
	DefaultConfigSHA256 string          `json:"default_config_sha256"`
	GoVersion           string          `json:"go_version"`
	Operation           string          `json:"operation"`
	InputSHA256         string          `json:"input_sha256"`
	ConfigSHA256        string          `json:"config_sha256"`
	RedactPercent       uint            `json:"redact_percent"`
	Findings            []directFinding `json:"findings"`
	Original            *directFinding  `json:"original"`
	Redacted            *directFinding  `json:"redacted"`
	MaskSecretBase64    string          `json:"mask_secret_base64"`
	Error               *oracleError    `json:"error"`
}

// sessionRequest is the cross-fragment state protocol. Finding values reuse
// the complete byte-preserving composite schema. Ignore and
// baseline files are materialized only inside the oracle child; the corpus
// launches one bounded child per request so detector state never crosses a
// record boundary.
type sessionRequest struct {
	ProtocolVersion int                     `json:"protocol_version"`
	ID              string                  `json:"id"`
	BehaviorIDs     []string                `json:"behavior_ids"`
	TestCaseIDs     []string                `json:"test_case_ids"`
	Operation       string                  `json:"operation"`
	RedactPercent   uint                    `json:"redact_percent"`
	IgnoreFile      *sessionFileInput       `json:"ignore_file"`
	BaselineFile    *sessionFileInput       `json:"baseline_file"`
	Findings        []compositeFindingInput `json:"findings"`
}

type sessionFileInput struct {
	Name          string `json:"name"`
	ContentBase64 string `json:"content_base64"`
	Missing       bool   `json:"missing"`
}

type sessionResponse struct {
	ProtocolVersion     int                   `json:"protocol_version"`
	OracleMode          string                `json:"oracle_mode"`
	ID                  string                `json:"id"`
	BehaviorIDs         []string              `json:"behavior_ids"`
	TestCaseIDs         []string              `json:"test_case_ids"`
	UpstreamRevision    string                `json:"upstream_revision"`
	DefaultConfigSHA256 string                `json:"default_config_sha256"`
	GoVersion           string                `json:"go_version"`
	Operation           string                `json:"operation"`
	InputSHA256         string                `json:"input_sha256"`
	RedactPercent       uint                  `json:"redact_percent"`
	Ignore              sessionIgnoreResult   `json:"ignore"`
	Baseline            sessionBaselineResult `json:"baseline"`
	InputFindings       []directFinding       `json:"input_findings"`
	Decisions           []sessionDecision     `json:"decisions"`
	CollectedFindings   []directFinding       `json:"collected_findings"`
	CanonicalFindings   []directFinding       `json:"canonical_findings"`
	Error               *oracleError          `json:"error"`
}

type sessionIgnoreResult struct {
	Configured    bool     `json:"configured"`
	Loaded        bool     `json:"loaded"`
	EntriesBase64 []string `json:"entries_base64"`
	UniqueCount   int      `json:"unique_count"`
}

type sessionBaselineResult struct {
	Configured bool            `json:"configured"`
	Loaded     bool            `json:"loaded"`
	Findings   []directFinding `json:"findings"`
}

type sessionDecision struct {
	Index                      int    `json:"index"`
	GlobalFingerprintBase64    string `json:"global_fingerprint_base64"`
	QualifiedFingerprintBase64 string `json:"qualified_fingerprint_base64"`
	AssignedFingerprintBase64  string `json:"assigned_fingerprint_base64"`
	IgnoredByGlobal            bool   `json:"ignored_by_global"`
	IgnoredByCommit            bool   `json:"ignored_by_commit"`
	BaselineIsNew              bool   `json:"baseline_is_new"`
	Disposition                string `json:"disposition"`
}

// sourceRequest is the reader, file, and archive protocol. It records
// source fragments before detection so byte, path, duplicate, and issue
// behavior remain independently testable. Fixture paths are confined to the
// provenance-tracked compatibility fixture tree.
type sourceRequest struct {
	ProtocolVersion int                `json:"protocol_version"`
	ID              string             `json:"id"`
	BehaviorIDs     []string           `json:"behavior_ids"`
	TestCaseIDs     []string           `json:"test_case_ids"`
	Operation       string             `json:"operation"`
	ContentBase64   string             `json:"content_base64,omitempty"`
	PathBase64      string             `json:"path_base64,omitempty"`
	FixturePath     string             `json:"fixture_path,omitempty"`
	LogicalPath     string             `json:"logical_path,omitempty"`
	RootSubpath     string             `json:"root_subpath,omitempty"`
	ConfigFixture   string             `json:"config_fixture,omitempty"`
	IgnoreFixture   string             `json:"ignore_fixture,omitempty"`
	BufferSize      int                `json:"buffer_size,omitempty"`
	MaxPeekSize     int                `json:"max_peek_size,omitempty"`
	MaxFileSize     int                `json:"max_file_size,omitempty"`
	MaxArchiveDepth int                `json:"max_archive_depth,omitempty"`
	FollowSymlinks  bool               `json:"follow_symlinks,omitempty"`
	CancelBefore    bool               `json:"cancel_before,omitempty"`
	Detect          bool               `json:"detect,omitempty"`
	Stream          bool               `json:"stream,omitempty"`
	ReaderSchedule  []sourceReaderStep `json:"reader_schedule,omitempty"`
	Entries         []sourceEntry      `json:"entries,omitempty"`
	SkipPathsBase64 []string           `json:"skip_paths_base64,omitempty"`
	MissingRoot     bool               `json:"missing_root,omitempty"`
	YieldErrorAfter int                `json:"yield_error_after,omitempty"`
	WorkerLimit     int                `json:"worker_limit,omitempty"`
}

type sourceReaderStep struct {
	DataBase64 string `json:"data_base64"`
	Error      string `json:"error,omitempty"`
}

type sourceEntry struct {
	Path          string  `json:"path"`
	Kind          string  `json:"kind"`
	ContentBase64 string  `json:"content_base64,omitempty"`
	Target        string  `json:"target,omitempty"`
	Mode          *uint32 `json:"mode,omitempty"`
}

type sourceResponse struct {
	ProtocolVersion     int              `json:"protocol_version"`
	OracleMode          string           `json:"oracle_mode"`
	ID                  string           `json:"id"`
	BehaviorIDs         []string         `json:"behavior_ids"`
	TestCaseIDs         []string         `json:"test_case_ids"`
	UpstreamRevision    string           `json:"upstream_revision"`
	DefaultConfigSHA256 string           `json:"default_config_sha256"`
	GoVersion           string           `json:"go_version"`
	Platform            string           `json:"platform"`
	Operation           string           `json:"operation"`
	InputSHA256         string           `json:"input_sha256"`
	Fragments           []sourceFragment `json:"fragments"`
	CanonicalFragments  []sourceFragment `json:"canonical_fragments"`
	Findings            []directFinding  `json:"findings"`
	Issues              []sourceIssue    `json:"issues"`
	ReadCalls           int              `json:"read_calls"`
	ConcurrentCallbacks int32            `json:"max_concurrent_callbacks"`
	Error               *oracleError     `json:"error"`
}

type sourceFragment struct {
	RawBase64         string `json:"raw_base64"`
	BytesBase64       string `json:"bytes_base64"`
	BytesNil          bool   `json:"bytes_nil"`
	FileBase64        string `json:"file_base64"`
	WindowsFileBase64 string `json:"windows_file_base64"`
	SymlinkFileBase64 string `json:"symlink_file_base64"`
	CommitBase64      string `json:"commit_base64"`
	StartLine         int    `json:"start_line"`
	Inherited         bool   `json:"inherited_from_finding"`
}

type sourceIssue struct {
	Fragment sourceFragment `json:"fragment"`
	Class    string         `json:"class"`
	Message  string         `json:"message"`
}

// gitRequest is the versioned Git-source protocol. Repository
// names select committed compatibility fixtures; all Git execution happens in
// a private copy whose dotGit directory is renamed to .git only after copying.
type gitRequest struct {
	ProtocolVersion  int      `json:"protocol_version"`
	ID               string   `json:"id"`
	BehaviorIDs      []string `json:"behavior_ids"`
	TestCaseIDs      []string `json:"test_case_ids"`
	Operation        string   `json:"operation"`
	Repository       string   `json:"repository"`
	LogOptions       string   `json:"log_options,omitempty"`
	Staged           bool     `json:"staged,omitempty"`
	Mutation         string   `json:"mutation,omitempty"`
	Detect           bool     `json:"detect,omitempty"`
	ConfigFixture    string   `json:"config_fixture,omitempty"`
	LoadIgnore       bool     `json:"load_ignore,omitempty"`
	MaxArchiveDepth  int      `json:"max_archive_depth,omitempty"`
	AllowCommits     []string `json:"allow_commits,omitempty"`
	RemoteURL        string   `json:"remote_url,omitempty"`
	Platform         string   `json:"platform,omitempty"`
	CancelAfterStart bool     `json:"cancel_after_start,omitempty"`
}

type gitResponse struct {
	ProtocolVersion     int             `json:"protocol_version"`
	OracleMode          string          `json:"oracle_mode"`
	ID                  string          `json:"id"`
	BehaviorIDs         []string        `json:"behavior_ids"`
	TestCaseIDs         []string        `json:"test_case_ids"`
	UpstreamRevision    string          `json:"upstream_revision"`
	DefaultConfigSHA256 string          `json:"default_config_sha256"`
	GoVersion           string          `json:"go_version"`
	Platform            string          `json:"platform"`
	GitVersionBase64    string          `json:"git_version_base64"`
	Operation           string          `json:"operation"`
	ArgumentsBase64     []string        `json:"arguments_base64"`
	CommandBase64       string          `json:"command_base64"`
	Fragments           []gitFragment   `json:"fragments"`
	CanonicalFragments  []gitFragment   `json:"canonical_fragments"`
	Findings            []directFinding `json:"findings"`
	Issues              []gitIssue      `json:"issues"`
	Remote              *gitRemote      `json:"remote"`
	Error               *oracleError    `json:"error"`
}

type gitFragment struct {
	RawBase64         string         `json:"raw_base64"`
	BytesBase64       string         `json:"bytes_base64"`
	BytesNil          bool           `json:"bytes_nil"`
	FileBase64        string         `json:"file_base64"`
	WindowsFileBase64 string         `json:"windows_file_base64"`
	SymlinkFileBase64 string         `json:"symlink_file_base64"`
	CommitBase64      string         `json:"commit_base64"`
	StartLine         int            `json:"start_line"`
	Inherited         bool           `json:"inherited_from_finding"`
	CommitInfo        *gitCommitInfo `json:"commit_info"`
}

type gitCommitInfo struct {
	AuthorNameBase64  string     `json:"author_name_base64"`
	AuthorEmailBase64 string     `json:"author_email_base64"`
	DateBase64        string     `json:"date_base64"`
	MessageBase64     string     `json:"message_base64"`
	SHABase64         string     `json:"sha_base64"`
	Remote            *gitRemote `json:"remote"`
}

type gitRemote struct {
	Platform  string `json:"platform"`
	URLBase64 string `json:"url_base64"`
}

type gitIssue struct {
	Fragment gitFragment `json:"fragment"`
	Class    string      `json:"class"`
	Message  string      `json:"message"`
}

// reportRequest is the versioned report protocol. All text that
// can originate in a finding or template is base64 encoded so the adapter can
// expose Go string behavior for arbitrary bytes. Output is also base64 encoded
// because CSV and templates may emit bytes that JSON cannot represent.
type reportRequest struct {
	ProtocolVersion int                  `json:"protocol_version"`
	ID              string               `json:"id"`
	BehaviorIDs     []string             `json:"behavior_ids"`
	TestCaseIDs     []string             `json:"test_case_ids"`
	Format          string               `json:"format"`
	Findings        []reportFindingInput `json:"findings"`
	OrderedRules    []reportRuleInput    `json:"ordered_rules,omitempty"`
	TemplateBase64  string               `json:"template_base64,omitempty"`
	TemplateMode    string               `json:"template_mode,omitempty"`
	RedactPercent   *uint                `json:"redact_percent,omitempty"`
	FailAfterBytes  *int                 `json:"fail_after_bytes,omitempty"`
}

type reportFindingInput struct {
	RuleIDBase64      string   `json:"rule_id_base64"`
	DescriptionBase64 string   `json:"description_base64"`
	StartLine         int      `json:"start_line"`
	EndLine           int      `json:"end_line"`
	StartColumn       int      `json:"start_column"`
	EndColumn         int      `json:"end_column"`
	LineBase64        string   `json:"line_base64"`
	MatchBase64       string   `json:"match_base64"`
	SecretBase64      string   `json:"secret_base64"`
	FileBase64        string   `json:"file_base64"`
	SymlinkFileBase64 string   `json:"symlink_file_base64"`
	CommitBase64      string   `json:"commit_base64"`
	LinkBase64        string   `json:"link_base64"`
	EntropyBits       uint32   `json:"entropy_bits"`
	AuthorBase64      string   `json:"author_base64"`
	EmailBase64       string   `json:"email_base64"`
	DateBase64        string   `json:"date_base64"`
	MessageBase64     string   `json:"message_base64"`
	TagsBase64        []string `json:"tags_base64"`
	TagsNil           bool     `json:"tags_nil,omitempty"`
	FingerprintBase64 string   `json:"fingerprint_base64"`
}

type reportRuleInput struct {
	IDBase64          string `json:"id_base64"`
	DescriptionBase64 string `json:"description_base64"`
}

type reportResponse struct {
	ProtocolVersion     int             `json:"protocol_version"`
	OracleMode          string          `json:"oracle_mode"`
	ID                  string          `json:"id"`
	BehaviorIDs         []string        `json:"behavior_ids"`
	TestCaseIDs         []string        `json:"test_case_ids"`
	UpstreamRevision    string          `json:"upstream_revision"`
	DefaultConfigSHA256 string          `json:"default_config_sha256"`
	GoVersion           string          `json:"go_version"`
	Platform            string          `json:"platform"`
	Format              string          `json:"format"`
	FindingCount        int             `json:"finding_count"`
	OutputBase64        string          `json:"output_base64"`
	OutputBytes         int             `json:"output_bytes"`
	OutputSHA256        string          `json:"output_sha256"`
	RedactedFindings    []directFinding `json:"redacted_findings"`
	Error               *oracleError    `json:"error"`
}

// allowlistRequest is the versioned allowlist protocol. Method requests
// expose the observable public config.Allowlist API, including the second
// return value of CommitAllowed and ContainsStopWord. Detect requests exercise
// the ordinary translated-config pipeline and return the same complete finding
// projection as the direct detector protocol.
type allowlistRequest struct {
	ProtocolVersion int                   `json:"protocol_version"`
	ID              string                `json:"id"`
	BehaviorIDs     []string              `json:"behavior_ids"`
	TestCaseIDs     []string              `json:"test_case_ids"`
	AssertionIDs    []string              `json:"assertion_ids"`
	Operation       string                `json:"operation"`
	Method          string                `json:"method,omitempty"`
	Validate        bool                  `json:"validate,omitempty"`
	ValidateCount   int                   `json:"validate_count,omitempty"`
	NilAllowlist    bool                  `json:"nil_allowlist,omitempty"`
	BaseGlobal      bool                  `json:"base_global,omitempty"`
	Allowlist       allowlistInput        `json:"allowlist,omitempty"`
	InputBase64     string                `json:"input_base64,omitempty"`
	UseDefault      bool                  `json:"use_default,omitempty"`
	ConfigBase64    string                `json:"config_base64,omitempty"`
	ConfigFixture   string                `json:"config_fixture,omitempty"`
	ConfigEntry     string                `json:"config_entry,omitempty"`
	ConfigFiles     []allowlistConfigFile `json:"config_files,omitempty"`
	ConfigWorkdir   string                `json:"config_working_directory,omitempty"`
	Fragment        requestFragment       `json:"fragment,omitempty"`
	Options         requestOptions        `json:"options,omitempty"`
}

type allowlistConfigFile struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"content_base64"`
}

type allowlistInput struct {
	DescriptionBase64 string   `json:"description_base64,omitempty"`
	Condition         string   `json:"condition,omitempty"`
	CommitsBase64     []string `json:"commits_base64,omitempty"`
	PathsBase64       []string `json:"paths_base64,omitempty"`
	RegexTarget       string   `json:"regex_target,omitempty"`
	RegexesBase64     []string `json:"regexes_base64,omitempty"`
	StopWordsBase64   []string `json:"stopwords_base64,omitempty"`
}

type allowlistResponse struct {
	ProtocolVersion     int                    `json:"protocol_version"`
	OracleMode          string                 `json:"oracle_mode"`
	ID                  string                 `json:"id"`
	BehaviorIDs         []string               `json:"behavior_ids"`
	TestCaseIDs         []string               `json:"test_case_ids"`
	AssertionIDs        []string               `json:"assertion_ids"`
	UpstreamRevision    string                 `json:"upstream_revision"`
	DefaultConfigSHA256 string                 `json:"default_config_sha256"`
	GoVersion           string                 `json:"go_version"`
	Operation           string                 `json:"operation"`
	Validation          *allowlistValidation   `json:"validation"`
	Normalized          *canonicalAllowlist    `json:"normalized"`
	MethodResult        *allowlistMethodResult `json:"method_result"`
	ConfigSHA256        string                 `json:"config_sha256"`
	InputSHA256         string                 `json:"input_sha256"`
	TotalBytes          uint64                 `json:"total_bytes"`
	Findings            []directFinding        `json:"findings"`
	Error               *oracleError           `json:"error"`
}

type allowlistValidation struct {
	Attempted      bool   `json:"attempted"`
	AttemptedCount int    `json:"attempted_count"`
	Success        bool   `json:"success"`
	Error          string `json:"error"`
}

type allowlistMethodResult struct {
	Method             string `json:"method"`
	Allowed            bool   `json:"allowed"`
	MatchedValueBase64 string `json:"matched_value_base64"`
}

type configRequest struct {
	ProtocolVersion int          `json:"protocol_version"`
	ID              string       `json:"id"`
	Source          configSource `json:"source"`
}

type configSource struct {
	Kind         string `json:"kind"`
	Path         string `json:"path,omitempty"`
	Origin       string `json:"origin,omitempty"`
	ConfigBase64 string `json:"config_base64,omitempty"`
}

type configResponse struct {
	ProtocolVersion     int                `json:"protocol_version"`
	OracleMode          string             `json:"oracle_mode"`
	ID                  string             `json:"id"`
	UpstreamRevision    string             `json:"upstream_revision"`
	DefaultConfigSHA256 string             `json:"default_config_sha256"`
	GoVersion           string             `json:"go_version"`
	Source              configSourceResult `json:"source"`
	ConfigSHA256        string             `json:"config_sha256"`
	Effective           *canonicalConfig   `json:"effective"`
	Diagnostics         []configDiagnostic `json:"diagnostics"`
	Error               *configError       `json:"error"`
}

type configSourceResult struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Origin string `json:"origin"`
}

type configError struct {
	Class      string   `json:"class"`
	Stage      string   `json:"stage"`
	Message    string   `json:"message"`
	CauseChain []string `json:"cause_chain"`
}

type configDiagnostic struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields"`
}

type canonicalConfig struct {
	Title            string               `json:"title"`
	Description      string               `json:"description"`
	Path             string               `json:"path"`
	MinVersion       string               `json:"min_version"`
	Extend           canonicalExtend      `json:"extend"`
	OrderedRuleIDs   []string             `json:"ordered_rule_ids"`
	DuplicateRuleIDs []duplicateRule      `json:"duplicate_rule_ids"`
	Rules            []canonicalRule      `json:"rules"`
	GlobalAllowlists []canonicalAllowlist `json:"global_allowlists"`
	NormalizedKeys   []string             `json:"normalized_keywords"`
}

type canonicalExtend struct {
	Path          string   `json:"path"`
	URL           string   `json:"url"`
	UseDefault    bool     `json:"use_default"`
	DisabledRules []string `json:"disabled_rules"`
}

type duplicateRule struct {
	ID        string `json:"id"`
	Count     int    `json:"count"`
	Positions []int  `json:"positions"`
}

type canonicalRule struct {
	ID          string               `json:"id"`
	Description string               `json:"description"`
	Path        *string              `json:"path"`
	Regex       *string              `json:"regex"`
	SecretGroup int                  `json:"secret_group"`
	Entropy     any                  `json:"entropy"`
	EntropyBits uint64               `json:"entropy_bits"`
	Keywords    []string             `json:"keywords"`
	Tags        []string             `json:"tags"`
	Required    []canonicalRequired  `json:"required"`
	Allowlists  []canonicalAllowlist `json:"allowlists"`
	SkipReport  bool                 `json:"skip_report"`
}

type canonicalRequired struct {
	ID            string `json:"id"`
	WithinLines   *int   `json:"within_lines"`
	WithinColumns *int   `json:"within_columns"`
}

type canonicalAllowlist struct {
	Description string   `json:"description"`
	Condition   string   `json:"condition"`
	Commits     []string `json:"commits"`
	Paths       []string `json:"paths"`
	RegexTarget string   `json:"regex_target"`
	Regexes     []string `json:"regexes"`
	StopWords   []string `json:"stop_words"`
}

// regexRequest and regexResponse form a deliberately small, versioned protocol
// for regular-expression compatibility. Patterns and haystacks are base64 so
// JSON never normalizes arbitrary bytes before Go's regexp package observes
// them. Go regexp accepts strings, not byte slices: invalid UTF-8 bytes in those
// strings are decoded as separate utf8.RuneError values of width one, while all
// reported indexes remain offsets into the original string bytes.
type regexRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	ID              string `json:"id"`
	PatternBase64   string `json:"pattern_base64"`
	InputBase64     string `json:"input_base64"`
}

type regexResponse struct {
	ProtocolVersion     int                `json:"protocol_version"`
	OracleMode          string             `json:"oracle_mode"`
	ID                  string             `json:"id"`
	UpstreamRevision    string             `json:"upstream_revision"`
	DefaultConfigSHA256 string             `json:"default_config_sha256"`
	GoVersion           string             `json:"go_version"`
	UnicodeVersion      string             `json:"unicode_version"`
	PatternSHA256       string             `json:"pattern_sha256"`
	InputSHA256         string             `json:"input_sha256"`
	Compile             regexCompileResult `json:"compile"`
	MatchExists         bool               `json:"match_exists"`
	Matches             []regexMatch       `json:"matches"`
	Error               *oracleError       `json:"error"`
}

type regexCompileResult struct {
	Success       bool     `json:"success"`
	ErrorCategory string   `json:"error_category,omitempty"`
	ErrorMessage  string   `json:"error_message,omitempty"`
	CaptureCount  int      `json:"capture_count"`
	CaptureNames  []string `json:"capture_names"`
}

type regexMatch struct {
	Span     [2]int   `json:"span"`
	Captures [][2]int `json:"captures"`
}

func main() {
	inputPath := flag.String("input", "", "JSONL request file (stdin when empty)")
	outputPath := flag.String("output", "", "write JSONL output to this path")
	checkPath := flag.String("check", "", "compare generated JSONL with this path")
	configOne := flag.Bool("config-one", false, "run exactly one configuration request in this process")
	regexMode := flag.Bool("regex", false, "run regex JSONL requests instead of detector requests")
	detectMode := flag.Bool("detect", false, "run versioned direct-detector JSONL requests")
	allowlistMode := flag.Bool("allowlist", false, "run versioned allowlist JSONL requests")
	decoderMode := flag.Bool("decoder", false, "run versioned decoder/pass JSONL requests")
	compositeMode := flag.Bool("composite", false, "run versioned composite/redaction JSONL requests")
	sessionMode := flag.Bool("session", false, "run versioned session/baseline/ignore JSONL requests")
	sourceMode := flag.Bool("source", false, "run versioned reader/file/archive source JSONL requests")
	gitMode := flag.Bool("git", false, "run versioned Git source JSONL requests")
	reportMode := flag.Bool("report", false, "run versioned report JSONL requests")
	flag.Parse()

	input := os.Stdin
	if *inputPath != "" {
		file, err := os.Open(*inputPath)
		fatalIf(err)
		defer file.Close()
		input = file
	}

	if *configOne {
		fatalIf(runConfigOne(input, *outputPath, *checkPath))
		return
	}
	if *regexMode {
		fatalIf(runRegex(input, *outputPath, *checkPath))
		return
	}
	if *detectMode {
		fatalIf(runDetect(input, *outputPath, *checkPath))
		return
	}
	if *allowlistMode {
		fatalIf(runAllowlist(input, *outputPath, *checkPath))
		return
	}
	if *decoderMode {
		fatalIf(runDecoder(input, *outputPath, *checkPath))
		return
	}
	if *compositeMode {
		fatalIf(runComposite(input, *outputPath, *checkPath))
		return
	}
	if *sessionMode {
		fatalIf(runSession(input, *outputPath, *checkPath))
		return
	}
	if *sourceMode {
		fatalIf(runSource(input, *outputPath, *checkPath))
		return
	}
	if *gitMode {
		fatalIf(runGit(input, *outputPath, *checkPath))
		return
	}
	if *reportMode {
		fatalIf(runReport(input, *outputPath, *checkPath))
		return
	}

	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 16*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			fatalIf(fmt.Errorf("decode request: %w", err))
		}
		fatalIf(encoder.Encode(safeRun(req)))
	}
	fatalIf(scanner.Err())

	switch {
	case *checkPath != "":
		expected, err := os.ReadFile(*checkPath)
		fatalIf(err)
		if !bytes.Equal(output.Bytes(), expected) {
			fatalIf(firstDifference(expected, output.Bytes()))
		}
	case *outputPath != "":
		fatalIf(os.WriteFile(*outputPath, output.Bytes(), 0o644))
	default:
		_, err := os.Stdout.Write(output.Bytes())
		fatalIf(err)
	}
}

func runDetect(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 16*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req detectRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode detector request: %w", err)
		}
		if err := encoder.Encode(safeRunDetect(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runAllowlist(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 16*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req allowlistRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode allowlist request: %w", err)
		}
		if err := encoder.Encode(safeRunAllowlist(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runDecoder(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 32*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req decoderRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode decoder request: %w", err)
		}
		if err := encoder.Encode(safeRunDecoder(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runComposite(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 32*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req compositeRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode composite request: %w", err)
		}
		if err := encoder.Encode(safeRunComposite(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runSession(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 32*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req sessionRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode session request: %w", err)
		}
		if err := encoder.Encode(safeRunSession(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runSource(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 32*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req sourceRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode source request: %w", err)
		}
		if err := encoder.Encode(safeRunSource(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runGit(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 64*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req gitRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode Git request: %w", err)
		}
		if err := encoder.Encode(safeRunGit(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runReport(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 32*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req reportRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode report request: %w", err)
		}
		if err := encoder.Encode(safeRunReport(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func runRegex(input io.Reader, outputPath, checkPath string) error {
	var output bytes.Buffer
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 16*1024*1024)
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var req regexRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode regex request: %w", err)
		}
		if err := encoder.Encode(safeRunRegex(req)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func safeRunRegex(req regexRequest) (result regexResponse) {
	result = newRegexResponse(req)
	defer func() {
		if recovered := recover(); recovered != nil {
			result.MatchExists = false
			result.Matches = []regexMatch{}
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	return runRegexRequest(req, result)
}

func newRegexResponse(req regexRequest) regexResponse {
	return regexResponse{
		ProtocolVersion:     regexProtocolVersion,
		OracleMode:          "regex",
		ID:                  req.ID,
		UpstreamRevision:    upstreamRevision,
		DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion:           runtime.Version(),
		UnicodeVersion:      unicode.Version,
		Compile: regexCompileResult{
			CaptureNames: []string{},
		},
		Matches: []regexMatch{},
	}
}

func runRegexRequest(req regexRequest, result regexResponse) regexResponse {
	if req.ProtocolVersion != regexProtocolVersion {
		result.Error = &oracleError{
			Class: "protocol", Message: fmt.Sprintf("expected regex protocol %d", regexProtocolVersion),
		}
		return result
	}
	pattern, err := base64.StdEncoding.DecodeString(req.PatternBase64)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: "invalid pattern base64"}
		return result
	}
	input, err := base64.StdEncoding.DecodeString(req.InputBase64)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: "invalid input base64"}
		return result
	}
	result.PatternSHA256 = fmt.Sprintf("%x", sha256.Sum256(pattern))
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(input))

	compiled, err := regexp.Compile(string(pattern))
	if err != nil {
		result.Compile.ErrorCategory = regexErrorCategory(err)
		result.Compile.ErrorMessage = err.Error()
		return result
	}
	result.Compile.Success = true
	result.Compile.CaptureCount = compiled.NumSubexp()
	result.Compile.CaptureNames = append([]string{}, compiled.SubexpNames()...)
	for _, indexes := range compiled.FindAllStringSubmatchIndex(string(input), -1) {
		captures := make([][2]int, 0, len(indexes)/2)
		for index := 0; index < len(indexes); index += 2 {
			captures = append(captures, [2]int{indexes[index], indexes[index+1]})
		}
		result.Matches = append(result.Matches, regexMatch{
			Span: [2]int{indexes[0], indexes[1]}, Captures: captures,
		})
	}
	result.MatchExists = len(result.Matches) != 0
	return result
}

func regexErrorCategory(err error) string {
	var syntaxError *syntax.Error
	if errors.As(err, &syntaxError) {
		return string(syntaxError.Code)
	}
	return "compile"
}

func runConfigOne(input io.Reader, outputPath, checkPath string) error {
	scanner := bufio.NewScanner(input)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 16*1024*1024)
	var records [][]byte
	for scanner.Scan() {
		if line := bytes.TrimSpace(scanner.Bytes()); len(line) != 0 {
			records = append(records, bytes.Clone(line))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(records) != 1 {
		return fmt.Errorf("--config-one requires exactly one nonblank request, got %d", len(records))
	}
	var req configRequest
	if err := json.Unmarshal(records[0], &req); err != nil {
		return fmt.Errorf("decode config request: %w", err)
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(safeRunConfig(req)); err != nil {
		return err
	}
	return emitOutput(output.Bytes(), outputPath, checkPath)
}

func emitOutput(output []byte, outputPath, checkPath string) error {
	switch {
	case checkPath != "":
		expected, err := os.ReadFile(checkPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(output, expected) {
			return firstDifference(expected, output)
		}
	case outputPath != "":
		return os.WriteFile(outputPath, output, 0o644)
	default:
		_, err := os.Stdout.Write(output)
		return err
	}
	return nil
}

func safeRunDecoder(req decoderRequest) (result decoderResponse) {
	result = decoderResponse{
		ProtocolVersion: decoderProtocolVersion, OracleMode: "decoder", ID: req.ID,
		BehaviorIDs: cloneStrings(req.BehaviorIDs), TestCaseIDs: cloneStrings(req.TestCaseIDs),
		UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion: runtime.Version(), Operation: req.Operation,
		RequestedMaxDecodeDepth:   req.Options.MaxDecodeDepth,
		RustAdapterMaxDecodeDepth: max(0, req.Options.MaxDecodeDepth),
		Runs:                      []decoderRun{}, Findings: []directFinding{}, FindingRuns: [][]directFinding{},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Runs = []decoderRun{}
			result.Findings = []directFinding{}
			result.FindingRuns = [][]directFinding{}
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	if req.ProtocolVersion != decoderProtocolVersion {
		result.Error = &oracleError{Class: "protocol", Message: fmt.Sprintf("expected decoder protocol %d", decoderProtocolVersion)}
		return result
	}
	switch req.Operation {
	case "decode":
		return runDecoderCodec(req, result)
	case "detect":
		return runDecoderDetect(req, result)
	default:
		result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown decoder operation %q", req.Operation)}
		return result
	}
}

func runDecoderCodec(req decoderRequest, result decoderResponse) decoderResponse {
	if len(req.InputsBase64) == 0 {
		result.Error = &oracleError{Class: "request", Message: "decode operation requires at least one input"}
		return result
	}
	passLimit := req.PassLimit
	if passLimit == 0 {
		passLimit = 64
	}
	if passLimit < 1 || passLimit > 128 {
		result.Error = &oracleError{Class: "request", Message: "pass_limit must be in 1..128"}
		return result
	}
	if req.SourceTransform != "" {
		source, err := base64.StdEncoding.DecodeString(req.SourceBase64)
		if err != nil {
			result.Error = &oracleError{Class: "request", Message: "invalid source_base64 value"}
			return result
		}
		var transformed string
		switch req.SourceTransform {
		case "direct":
			transformed = string(source)
		case "path-escape":
			transformed = url.PathEscape(string(source))
		case "hex":
			transformed = hex.EncodeToString(source)
		default:
			result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown source_transform %q", req.SourceTransform)}
			return result
		}
		if len(req.InputsBase64) != 1 || req.InputsBase64[0] != b64(transformed) {
			result.Error = &oracleError{Class: "request", Message: "input does not equal pinned Go source transformation"}
			return result
		}
	}
	if req.DecoderScope == "" {
		req.DecoderScope = "shared"
	}
	if req.DecoderScope != "shared" && req.DecoderScope != "isolated" {
		result.Error = &oracleError{Class: "request", Message: "decoder_scope must be shared or isolated"}
		return result
	}
	sharedDecoder := codec.NewDecoder()
	var carriedPredecessors []*codec.EncodedSegment
	inputHasher := sha256.New()
	for _, encoded := range req.InputsBase64 {
		decoder := sharedDecoder
		if req.DecoderScope == "isolated" {
			decoder = codec.NewDecoder()
		}
		input, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			result.Error = &oracleError{Class: "request", Message: "invalid inputs_base64 value"}
			return result
		}
		_, _ = inputHasher.Write(input)
		current := string(input)
		var predecessors []*codec.EncodedSegment
		if req.CarryPredecessors {
			predecessors = carriedPredecessors
		}
		run := decoderRun{
			InputBase64: encoded, InputSHA256: fmt.Sprintf("%x", sha256.Sum256(input)),
			CacheBefore: inspectDecoderCache(decoder), CacheAfter: []decoderCacheEntry{}, Passes: []decoderPass{},
		}
		for passIndex := 1; passIndex <= passLimit; passIndex++ {
			cacheBefore := inspectDecoderCache(decoder)
			output, segments := decoder.Decode(current, predecessors)
			pass := canonicalDecoderPass(passIndex, current, output, segments, predecessors, req.ProbeRanges)
			pass.CacheBefore = cacheBefore
			pass.CacheAfter = inspectDecoderCache(decoder)
			run.Passes = append(run.Passes, pass)
			current = output
			predecessors = segments
			if len(segments) == 0 {
				run.Terminated = true
				break
			}
		}
		if req.CarryPredecessors {
			carriedPredecessors = predecessors
		}
		run.FullDecodeBase64 = b64(current)
		run.CacheAfter = inspectDecoderCache(decoder)
		result.Runs = append(result.Runs, run)
	}
	result.InputSHA256 = fmt.Sprintf("%x", inputHasher.Sum(nil))
	return result
}

func inspectDecoderCache(decoder *codec.Decoder) []decoderCacheEntry {
	value := reflect.ValueOf(decoder).Elem().FieldByName("decodedMap")
	result := make([]decoderCacheEntry, 0, value.Len())
	iterator := value.MapRange()
	for iterator.Next() {
		result = append(result, decoderCacheEntry{
			EncodedBase64: b64(iterator.Key().String()), DecodedBase64: b64(iterator.Value().String()),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].EncodedBase64 < result[j].EncodedBase64 })
	return result
}

func canonicalDecoderPass(passIndex int, input, output string, segments, predecessors []*codec.EncodedSegment, requested [][2]int) decoderPass {
	pass := decoderPass{
		Pass: passIndex, InputBase64: b64(input), OutputBase64: b64(output),
		CacheBefore: []decoderCacheEntry{}, CacheAfter: []decoderCacheEntry{},
		Segments:   inspectDecoderSegments(segments, predecessors),
		TagsBase64: b64Slice(codec.Tags(segments)), CurrentLineBase64: b64(codec.CurrentLine(segments, output)),
		Probes: []decoderProbe{},
	}
	probes := append([][2]int{}, requested...)
	probes = append(probes, [2]int{0, len(output)})
	for _, segment := range pass.Segments {
		probes = append(probes,
			segment.Decoded,
			[2]int{segment.Decoded[0], segment.Decoded[0]},
			[2]int{segment.Decoded[1], segment.Decoded[1]},
			[2]int{max(0, segment.Decoded[0]-1), min(len(output), segment.Decoded[1]+1)},
		)
	}
	seen := make(map[[2]int]struct{})
	for _, probe := range probes {
		if probe[0] < 0 || probe[1] < probe[0] || probe[1] > len(output) {
			continue
		}
		if _, exists := seen[probe]; exists {
			continue
		}
		seen[probe] = struct{}{}
		adjustedSlice := codec.AdjustMatchIndex(segments, []int{probe[0], probe[1]})
		overlaps := codec.SegmentsWithDecodedOverlap(segments, probe[0], probe[1])
		pass.Probes = append(pass.Probes, decoderProbe{
			Range: probe, Adjusted: [2]int{adjustedSlice[0], adjustedSlice[1]},
			OverlapSegmentIndices: decoderSegmentIndices(segments, overlaps),
		})
	}
	return pass
}

func inspectDecoderSegments(segments, predecessors []*codec.EncodedSegment) []decoderSegment {
	result := make([]decoderSegment, 0, len(segments))
	predecessorIndex := make(map[uintptr]int, len(predecessors))
	for index, predecessor := range predecessors {
		predecessorIndex[reflect.ValueOf(predecessor).Pointer()] = index
	}
	for index, segment := range segments {
		value := reflect.ValueOf(segment).Elem()
		mask := value.FieldByName("encodings").Int()
		item := decoderSegment{
			Index:              index,
			Original:           inspectStartEnd(value.FieldByName("original")),
			Encoded:            inspectStartEnd(value.FieldByName("encoded")),
			Decoded:            inspectStartEnd(value.FieldByName("decoded")),
			DecodedValueBase64: b64(value.FieldByName("decodedValue").String()),
			EncodingMask:       mask, EncodingKinds: decoderEncodingKinds(mask),
			Depth: value.FieldByName("depth").Int(), PredecessorIndices: []int{},
		}
		field := value.FieldByName("predecessors")
		for predecessor := 0; predecessor < field.Len(); predecessor++ {
			pointer := field.Index(predecessor).Pointer()
			mapped, exists := predecessorIndex[pointer]
			if !exists {
				mapped = -1
			}
			item.PredecessorIndices = append(item.PredecessorIndices, mapped)
		}
		result = append(result, item)
	}
	return result
}

func inspectStartEnd(value reflect.Value) [2]int {
	return [2]int{int(value.FieldByName("start").Int()), int(value.FieldByName("end").Int())}
}

func decoderEncodingKinds(mask int64) []string {
	result := []string{}
	for index, name := range []string{"percent", "unicode", "hex", "base64"} {
		if mask&(1<<index) != 0 {
			result = append(result, name)
		}
	}
	return result
}

func decoderSegmentIndices(all, selected []*codec.EncodedSegment) []int {
	index := make(map[uintptr]int, len(all))
	for position, segment := range all {
		index[reflect.ValueOf(segment).Pointer()] = position
	}
	result := make([]int, 0, len(selected))
	for _, segment := range selected {
		if position, exists := index[reflect.ValueOf(segment).Pointer()]; exists {
			result = append(result, position)
		}
	}
	return result
}

func runDecoderDetect(req decoderRequest, result decoderResponse) decoderResponse {
	fragment, err := req.Fragment.decode()
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	inputBytes := []byte(fragment.Raw)
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(inputBytes))
	configSourceCount := 0
	if req.UseDefault {
		configSourceCount++
	}
	if req.ConfigBase64 != "" {
		configSourceCount++
	}
	if req.ConfigFixture != "" {
		configSourceCount++
	}
	if configSourceCount != 1 {
		result.Error = &oracleError{Class: "request", Message: "detect operation requires exactly one config source"}
		return result
	}
	var cfg config.Config
	var raw []byte
	if req.ConfigFixture != "" {
		cfg, raw, err = loadDecoderFixture(req.ConfigFixture)
	} else {
		raw, err = detectorConfigBytes(detectRequest{UseDefault: req.UseDefault, ConfigBase64: req.ConfigBase64})
		if err == nil {
			cfg, err = loadConfig(request{UseDefault: req.UseDefault, ConfigBase64: req.ConfigBase64})
		}
	}
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	result.ConfigSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	detector := detect.NewDetector(cfg)
	detector.MaxDecodeDepth = req.Options.MaxDecodeDepth
	detector.MaxTargetMegaBytes = req.Options.MaxTargetMB
	detector.Redact = req.Options.RedactPercent
	detector.IgnoreGitleaksAllow = req.Options.IgnoreAllowMarker
	repeatCount := req.DetectRepeatCount
	if repeatCount == 0 {
		repeatCount = 1
	}
	if repeatCount < 1 || repeatCount > 16 {
		result.Error = &oracleError{Class: "request", Message: "detect_repeat_count must be in 1..16"}
		return result
	}
	for repeat := 0; repeat < repeatCount; repeat++ {
		run := []directFinding{}
		for _, finding := range detector.Detect(fragment) {
			run = append(run, canonicalDirectFinding(finding))
		}
		sort.SliceStable(run, func(i, j int) bool {
			a, _ := json.Marshal(run[i])
			b, _ := json.Marshal(run[j])
			return bytes.Compare(a, b) < 0
		})
		result.FindingRuns = append(result.FindingRuns, run)
	}
	result.Findings = append(result.Findings, result.FindingRuns[0]...)
	result.TotalBytes = detector.TotalBytes.Load()
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, _ := json.Marshal(result.Findings[i])
		b, _ := json.Marshal(result.Findings[j])
		return bytes.Compare(a, b) < 0
	})
	return result
}

func loadDecoderFixture(fixture string) (config.Config, []byte, error) {
	clean := filepath.Clean(fixture)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return config.Config{}, nil, errors.New("config_fixture must stay within upstream testdata/config")
	}
	upstreamRoot, err := filepath.Abs("../../../../gitleaks")
	if err != nil {
		return config.Config{}, nil, err
	}
	path := filepath.Join(upstreamRoot, "testdata/config", clean)
	raw, err := os.ReadFile(path)
	if err != nil {
		return config.Config{}, nil, err
	}
	viper.Reset()
	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		return config.Config{}, raw, err
	}
	var parsed config.ViperConfig
	if err := viper.Unmarshal(&parsed); err != nil {
		return config.Config{}, raw, err
	}
	cfg, err := parsed.Translate()
	return cfg, raw, err
}

func safeRunAllowlist(req allowlistRequest) (result allowlistResponse) {
	result = newAllowlistResponse(req)
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Findings = []directFinding{}
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	return runAllowlistRequest(req, result)
}

func newAllowlistResponse(req allowlistRequest) allowlistResponse {
	return allowlistResponse{
		ProtocolVersion:     allowlistProtocolVersion,
		OracleMode:          "allowlist",
		ID:                  req.ID,
		BehaviorIDs:         cloneStrings(req.BehaviorIDs),
		TestCaseIDs:         cloneStrings(req.TestCaseIDs),
		AssertionIDs:        cloneStrings(req.AssertionIDs),
		UpstreamRevision:    upstreamRevision,
		DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion:           runtime.Version(),
		Operation:           req.Operation,
		Findings:            []directFinding{},
	}
}

func runAllowlistRequest(req allowlistRequest, result allowlistResponse) allowlistResponse {
	if req.ProtocolVersion != allowlistProtocolVersion {
		result.Error = &oracleError{
			Class: "protocol", Message: fmt.Sprintf("expected allowlist protocol %d", allowlistProtocolVersion),
		}
		return result
	}
	switch req.Operation {
	case "method":
		return runAllowlistMethod(req, result)
	case "detect":
		return runAllowlistDetect(req, result)
	default:
		result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown operation %q", req.Operation)}
		return result
	}
}

func runAllowlistMethod(req allowlistRequest, result allowlistResponse) allowlistResponse {
	input, err := base64.StdEncoding.DecodeString(req.InputBase64)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: "invalid input base64"}
		return result
	}
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(input))

	var allowlist *config.Allowlist
	if req.BaseGlobal && req.NilAllowlist {
		result.Error = &oracleError{Class: "request", Message: "base_global and nil_allowlist are mutually exclusive"}
		return result
	}
	if req.BaseGlobal {
		allowlists := baseconfig.CreateGlobalConfig().Allowlists
		if len(allowlists) != 1 {
			result.Error = &oracleError{Class: "oracle", Message: fmt.Sprintf("expected one base global allowlist, got %d", len(allowlists))}
			return result
		}
		allowlist = allowlists[0]
	} else if !req.NilAllowlist {
		allowlist, err = decodeAllowlistInput(req.Allowlist)
		if err != nil {
			result.Error = &oracleError{Class: "request", Message: err.Error()}
			return result
		}
	}
	validateCount := req.ValidateCount
	if req.Validate && validateCount == 0 {
		validateCount = 1
	}
	if validateCount < 0 {
		result.Error = &oracleError{Class: "request", Message: "validate_count cannot be negative"}
		return result
	}
	if validateCount > 0 {
		validation := &allowlistValidation{Attempted: true, AttemptedCount: validateCount}
		if allowlist == nil {
			validation.Error = "cannot validate nil allowlist"
		} else {
			validation.Success = true
			for index := 0; index < validateCount; index++ {
				if err := allowlist.Validate(); err != nil {
					validation.Success = false
					validation.Error = err.Error()
					break
				}
			}
		}
		result.Validation = validation
	}
	if allowlist != nil {
		canonical := canonicalizeAllowlists([]*config.Allowlist{allowlist})[0]
		result.Normalized = &canonical
	}

	methodResult := &allowlistMethodResult{Method: req.Method}
	switch req.Method {
	case "commit":
		methodResult.Allowed, methodResult.MatchedValueBase64 = allowlistCommitAllowed(allowlist, string(input))
	case "path":
		methodResult.Allowed = allowlist != nil && allowlist.PathAllowed(string(input))
	case "regex":
		methodResult.Allowed = allowlist != nil && allowlist.RegexAllowed(string(input))
	case "stopword":
		methodResult.Allowed, methodResult.MatchedValueBase64 = allowlistStopwordAllowed(allowlist, string(input))
	default:
		result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown allowlist method %q", req.Method)}
		return result
	}
	result.MethodResult = methodResult
	return result
}

func allowlistCommitAllowed(allowlist *config.Allowlist, input string) (bool, string) {
	if allowlist == nil {
		return false, ""
	}
	allowed, matched := allowlist.CommitAllowed(input)
	return allowed, b64(matched)
}

func allowlistStopwordAllowed(allowlist *config.Allowlist, input string) (bool, string) {
	if allowlist == nil {
		return false, ""
	}
	allowed, matched := allowlist.ContainsStopWord(input)
	return allowed, b64(matched)
}

func decodeAllowlistInput(input allowlistInput) (*config.Allowlist, error) {
	decodeOne := func(value, field string) (string, error) {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("invalid %s base64", field)
		}
		return string(decoded), nil
	}
	decodeMany := func(values []string, field string) ([]string, error) {
		result := make([]string, 0, len(values))
		for _, value := range values {
			decoded, err := decodeOne(value, field)
			if err != nil {
				return nil, err
			}
			result = append(result, decoded)
		}
		return result, nil
	}

	description, err := decodeOne(input.DescriptionBase64, "description")
	if err != nil {
		return nil, err
	}
	commits, err := decodeMany(input.CommitsBase64, "commit")
	if err != nil {
		return nil, err
	}
	pathSources, err := decodeMany(input.PathsBase64, "path")
	if err != nil {
		return nil, err
	}
	regexSources, err := decodeMany(input.RegexesBase64, "regex")
	if err != nil {
		return nil, err
	}
	stopWords, err := decodeMany(input.StopWordsBase64, "stopword")
	if err != nil {
		return nil, err
	}
	condition := config.AllowlistMatchOr
	switch strings.ToUpper(input.Condition) {
	case "", "OR", "||":
	case "AND", "&&":
		condition = config.AllowlistMatchAnd
	default:
		return nil, fmt.Errorf("unknown allowlist condition %q", input.Condition)
	}
	paths := make([]*regexp.Regexp, 0, len(pathSources))
	for _, source := range pathSources {
		compiled, err := regexp.Compile(source)
		if err != nil {
			return nil, fmt.Errorf("compile path: %w", err)
		}
		paths = append(paths, compiled)
	}
	regexes := make([]*regexp.Regexp, 0, len(regexSources))
	for _, source := range regexSources {
		compiled, err := regexp.Compile(source)
		if err != nil {
			return nil, fmt.Errorf("compile regex: %w", err)
		}
		regexes = append(regexes, compiled)
	}
	return &config.Allowlist{
		Description: description, MatchCondition: condition, Commits: commits,
		Paths: paths, RegexTarget: input.RegexTarget, Regexes: regexes, StopWords: stopWords,
	}, nil
}

func runAllowlistDetect(req allowlistRequest, result allowlistResponse) allowlistResponse {
	fragment, err := req.Fragment.decode()
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	inputBytes := []byte(fragment.Raw)
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(inputBytes))
	cfg, rawConfig, err := loadAllowlistDetectorConfig(req)
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	result.ConfigSHA256 = fmt.Sprintf("%x", sha256.Sum256(rawConfig))
	detector := detect.NewDetector(cfg)
	detector.MaxDecodeDepth = req.Options.MaxDecodeDepth
	detector.MaxTargetMegaBytes = req.Options.MaxTargetMB
	detector.Redact = req.Options.RedactPercent
	detector.IgnoreGitleaksAllow = req.Options.IgnoreAllowMarker
	for _, finding := range detector.Detect(fragment) {
		result.Findings = append(result.Findings, canonicalDirectFinding(finding))
	}
	result.TotalBytes = detector.TotalBytes.Load()
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, _ := json.Marshal(result.Findings[i])
		b, _ := json.Marshal(result.Findings[j])
		return bytes.Compare(a, b) < 0
	})
	return result
}

func loadAllowlistDetectorConfig(req allowlistRequest) (config.Config, []byte, error) {
	sourceCount := 0
	if req.UseDefault {
		sourceCount++
	}
	if req.ConfigBase64 != "" {
		sourceCount++
	}
	if req.ConfigFixture != "" {
		sourceCount++
	}
	if len(req.ConfigFiles) != 0 || req.ConfigEntry != "" {
		sourceCount++
	}
	if sourceCount != 1 {
		return config.Config{}, nil, errors.New("detect operation requires exactly one config source")
	}
	if req.ConfigFixture == "" {
		if len(req.ConfigFiles) != 0 || req.ConfigEntry != "" {
			return loadAllowlistConfigBundle(req)
		}
		raw, err := detectorConfigBytes(detectRequest{UseDefault: req.UseDefault, ConfigBase64: req.ConfigBase64})
		if err != nil {
			return config.Config{}, nil, err
		}
		cfg, err := loadConfig(request{UseDefault: req.UseDefault, ConfigBase64: req.ConfigBase64})
		return cfg, raw, err
	}

	clean := filepath.Clean(req.ConfigFixture)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return config.Config{}, nil, errors.New("config_fixture must stay within upstream testdata/config")
	}
	upstreamRoot, err := filepath.Abs("../../../../gitleaks")
	if err != nil {
		return config.Config{}, nil, err
	}
	path := filepath.Join(upstreamRoot, "testdata/config", clean)
	raw, err := os.ReadFile(path)
	if err != nil {
		return config.Config{}, nil, err
	}
	viper.Reset()
	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		return config.Config{}, raw, err
	}
	var parsed config.ViperConfig
	if err := viper.Unmarshal(&parsed); err != nil {
		return config.Config{}, raw, err
	}
	// Pinned extension fixtures spell their parents relative to the upstream
	// config/detect package working directory used by go test, rather than
	// relative to the TOML file. Reproduce that ordinary-build observation.
	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		return config.Config{}, raw, err
	}
	if err := os.Chdir(filepath.Join(upstreamRoot, "config")); err != nil {
		return config.Config{}, raw, err
	}
	defer func() { _ = os.Chdir(originalWorkingDirectory) }()
	cfg, err := parsed.Translate()
	return cfg, raw, err
}

func loadAllowlistConfigBundle(req allowlistRequest) (config.Config, []byte, error) {
	if len(req.ConfigFiles) == 0 || req.ConfigEntry == "" {
		return config.Config{}, nil, errors.New("config bundle requires files and an entry")
	}
	temporary, err := os.MkdirTemp("", "rustleaks-allowlist-config-")
	if err != nil {
		return config.Config{}, nil, err
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	var entryRaw []byte
	seen := make(map[string]struct{})
	for _, file := range req.ConfigFiles {
		clean := filepath.Clean(file.Path)
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return config.Config{}, nil, fmt.Errorf("config file %q escapes bundle", file.Path)
		}
		if _, exists := seen[clean]; exists {
			return config.Config{}, nil, fmt.Errorf("duplicate config file %q", clean)
		}
		seen[clean] = struct{}{}
		content, err := base64.StdEncoding.DecodeString(file.ContentBase64)
		if err != nil {
			return config.Config{}, nil, fmt.Errorf("invalid config file %q base64", clean)
		}
		path := filepath.Join(temporary, clean)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return config.Config{}, nil, err
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return config.Config{}, nil, err
		}
		if clean == filepath.Clean(req.ConfigEntry) {
			entryRaw = content
		}
	}
	if entryRaw == nil {
		return config.Config{}, nil, errors.New("config bundle entry is missing")
	}
	entry := filepath.Join(temporary, filepath.Clean(req.ConfigEntry))
	viper.Reset()
	viper.SetConfigFile(entry)
	if err := viper.ReadInConfig(); err != nil {
		return config.Config{}, entryRaw, err
	}
	var parsed config.ViperConfig
	if err := viper.Unmarshal(&parsed); err != nil {
		return config.Config{}, entryRaw, err
	}
	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		return config.Config{}, entryRaw, err
	}
	workingDirectory := temporary
	if req.ConfigWorkdir != "" {
		clean := filepath.Clean(req.ConfigWorkdir)
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return config.Config{}, entryRaw, errors.New("config working directory escapes bundle")
		}
		workingDirectory = filepath.Join(temporary, clean)
		if err := os.MkdirAll(workingDirectory, 0o755); err != nil {
			return config.Config{}, entryRaw, err
		}
	}
	if err := os.Chdir(workingDirectory); err != nil {
		return config.Config{}, entryRaw, err
	}
	defer func() { _ = os.Chdir(originalWorkingDirectory) }()
	cfg, err := parsed.Translate()
	return cfg, entryRaw, err
}

func safeRunComposite(req compositeRequest) (result compositeResponse) {
	result = compositeResponse{
		ProtocolVersion: compositeProtocolVersion, OracleMode: "composite", ID: req.ID,
		BehaviorIDs: cloneStrings(req.BehaviorIDs), TestCaseIDs: cloneStrings(req.TestCaseIDs),
		UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion: runtime.Version(), Operation: req.Operation, RedactPercent: req.RedactPercent,
		Findings: []directFinding{},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Findings = []directFinding{}
			result.Original = nil
			result.Redacted = nil
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	if req.ProtocolVersion != compositeProtocolVersion {
		result.Error = &oracleError{Class: "protocol", Message: fmt.Sprintf("expected composite protocol %d", compositeProtocolVersion)}
		return result
	}
	switch req.Operation {
	case "detect":
		return runCompositeDetect(req, result)
	case "probe_missing_required":
		return runCompositeMissingRequiredProbe(req, result)
	case "redact":
		return runCompositeRedact(req, result)
	default:
		result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown composite operation %q", req.Operation)}
		return result
	}
}

func safeRunSession(req sessionRequest) (result sessionResponse) {
	result = sessionResponse{
		ProtocolVersion: sessionProtocolVersion, OracleMode: "session", ID: req.ID,
		BehaviorIDs: cloneStrings(req.BehaviorIDs), TestCaseIDs: cloneStrings(req.TestCaseIDs),
		UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion: runtime.Version(), Operation: req.Operation, RedactPercent: req.RedactPercent,
		Ignore:        sessionIgnoreResult{EntriesBase64: []string{}},
		Baseline:      sessionBaselineResult{Findings: []directFinding{}},
		InputFindings: []directFinding{}, Decisions: []sessionDecision{},
		CollectedFindings: []directFinding{}, CanonicalFindings: []directFinding{},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.CollectedFindings = []directFinding{}
			result.CanonicalFindings = []directFinding{}
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	canonicalInput, err := json.Marshal(req)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(canonicalInput))
	if req.ProtocolVersion != sessionProtocolVersion {
		result.Error = &oracleError{Class: "protocol", Message: fmt.Sprintf("expected session protocol %d", sessionProtocolVersion)}
		return result
	}
	if req.Operation != "session" {
		result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown session operation %q", req.Operation)}
		return result
	}
	return runSessionRequest(req, result)
}

type scheduledSourceReader struct {
	steps  []sourceReaderStep
	index  int
	offset int
	calls  int
}

func (r *scheduledSourceReader) Read(p []byte) (int, error) {
	r.calls++
	if r.index >= len(r.steps) {
		return 0, io.EOF
	}
	step := r.steps[r.index]
	data, err := base64.StdEncoding.DecodeString(step.DataBase64)
	if err != nil {
		r.index++
		return 0, fmt.Errorf("invalid scheduled data base64")
	}
	n := copy(p, data[r.offset:])
	r.offset += n
	if r.offset < len(data) {
		return n, nil
	}
	r.index++
	r.offset = 0
	switch step.Error {
	case "", "nil":
		return n, nil
	case "eof":
		return n, io.EOF
	case "error":
		return n, errors.New("scheduled read error")
	default:
		return n, fmt.Errorf("unknown scheduled error %q", step.Error)
	}
}

func safeRunSource(req sourceRequest) (result sourceResponse) {
	result = sourceResponse{
		ProtocolVersion: sourceProtocolVersion, OracleMode: "source", ID: req.ID,
		BehaviorIDs: cloneStrings(req.BehaviorIDs), TestCaseIDs: cloneStrings(req.TestCaseIDs),
		UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, Operation: req.Operation,
		Fragments: []sourceFragment{}, CanonicalFragments: []sourceFragment{},
		Findings: []directFinding{}, Issues: []sourceIssue{},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	canonicalInput, err := json.Marshal(req)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(canonicalInput))
	if req.ProtocolVersion != sourceProtocolVersion {
		result.Error = &oracleError{Class: "protocol", Message: fmt.Sprintf("expected source protocol %d", sourceProtocolVersion)}
		return result
	}
	switch req.Operation {
	case "boundary":
		return runSourceBoundary(req, result)
	case "file":
		return runSourceFile(req, result)
	case "files":
		return runSourceFiles(req, result)
	case "reader":
		return runSourceReader(req, result)
	default:
		result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown source operation %q", req.Operation)}
		return result
	}
}

func safeRunGit(req gitRequest) (result gitResponse) {
	result = gitResponse{
		ProtocolVersion: gitProtocolVersion, OracleMode: "git", ID: req.ID,
		BehaviorIDs: cloneStrings(req.BehaviorIDs), TestCaseIDs: cloneStrings(req.TestCaseIDs),
		UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Operation: req.Operation, ArgumentsBase64: []string{}, Fragments: []gitFragment{},
		CanonicalFragments: []gitFragment{}, Findings: []directFinding{}, Issues: []gitIssue{},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	if req.ProtocolVersion != gitProtocolVersion {
		result.Error = &oracleError{Class: "protocol", Message: fmt.Sprintf("expected Git protocol %d", gitProtocolVersion)}
		return result
	}
	return runGitRequest(req, result)
}

var errReportWriter = errors.New("injected report writer failure")

type reportWriteCloser struct {
	bytes.Buffer
	failAfter *int
}

func (writer *reportWriteCloser) Write(data []byte) (int, error) {
	if writer.failAfter == nil {
		return writer.Buffer.Write(data)
	}
	remaining := *writer.failAfter - writer.Buffer.Len()
	if remaining <= 0 {
		return 0, errReportWriter
	}
	if len(data) <= remaining {
		return writer.Buffer.Write(data)
	}
	written, _ := writer.Buffer.Write(data[:remaining])
	return written, errReportWriter
}

func (writer *reportWriteCloser) Close() error { return nil }

func safeRunReport(req reportRequest) (result reportResponse) {
	result = reportResponse{
		ProtocolVersion: reportProtocolVersion, OracleMode: "report", ID: req.ID,
		BehaviorIDs: cloneStrings(req.BehaviorIDs), TestCaseIDs: cloneStrings(req.TestCaseIDs),
		UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Format: req.Format, FindingCount: len(req.Findings), RedactedFindings: []directFinding{},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	if req.ProtocolVersion != reportProtocolVersion {
		result.Error = &oracleError{Class: "protocol", Message: fmt.Sprintf("expected report protocol %d", reportProtocolVersion)}
		return finishReportResponse(result, nil)
	}
	if req.FailAfterBytes != nil && *req.FailAfterBytes < 0 {
		result.Error = &oracleError{Class: "request", Message: "fail_after_bytes must be nonnegative"}
		return finishReportResponse(result, nil)
	}

	findings := make([]report.Finding, 0, len(req.Findings))
	for index, input := range req.Findings {
		finding, err := decodeReportFinding(input)
		if err != nil {
			result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("finding %d: %v", index, err)}
			return finishReportResponse(result, nil)
		}
		if req.RedactPercent != nil {
			finding.Redact(*req.RedactPercent)
		}
		findings = append(findings, finding)
		result.RedactedFindings = append(result.RedactedFindings, canonicalDirectFinding(finding))
	}

	writer := &reportWriteCloser{failAfter: req.FailAfterBytes}
	var reporter report.Reporter
	var temporary string
	switch req.Format {
	case "json":
		reporter = &report.JsonReporter{}
	case "csv":
		reporter = &report.CsvReporter{}
	case "junit":
		reporter = &report.JunitReporter{}
	case "sarif":
		rules := make([]config.Rule, 0, len(req.OrderedRules))
		for index, input := range req.OrderedRules {
			id, err := decodeReportBase64(input.IDBase64, "rule id")
			if err != nil {
				result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("ordered rule %d: %v", index, err)}
				return finishReportResponse(result, writer)
			}
			description, err := decodeReportBase64(input.DescriptionBase64, "rule description")
			if err != nil {
				result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("ordered rule %d: %v", index, err)}
				return finishReportResponse(result, writer)
			}
			rules = append(rules, config.Rule{RuleID: id, Description: description})
		}
		reporter = &report.SarifReporter{OrderedRules: rules}
	case "template":
		var path string
		switch req.TemplateMode {
		case "empty-path":
			path = ""
		case "missing":
			var err error
			temporary, err = os.MkdirTemp("", "rustleaks-report-template-")
			if err != nil {
				result.Error = &oracleError{Class: "io", Message: err.Error()}
				return finishReportResponse(result, writer)
			}
			defer os.RemoveAll(temporary)
			path = filepath.Join(temporary, "missing.tmpl")
		case "", "execute", "validate":
			templateBytes, err := base64.StdEncoding.DecodeString(req.TemplateBase64)
			if err != nil {
				result.Error = &oracleError{Class: "request", Message: "invalid template_base64"}
				return finishReportResponse(result, writer)
			}
			temporary, err = os.MkdirTemp("", "rustleaks-report-template-")
			if err != nil {
				result.Error = &oracleError{Class: "io", Message: err.Error()}
				return finishReportResponse(result, writer)
			}
			defer os.RemoveAll(temporary)
			path = filepath.Join(temporary, "custom.tmpl")
			if err := os.WriteFile(path, templateBytes, 0o600); err != nil {
				result.Error = &oracleError{Class: "io", Message: err.Error()}
				return finishReportResponse(result, writer)
			}
		default:
			result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown template mode %q", req.TemplateMode)}
			return finishReportResponse(result, writer)
		}
		templateReporter, err := report.NewTemplateReporter(path)
		if err != nil {
			class := "template-read"
			if req.TemplateMode == "empty-path" {
				class = "template-path"
			} else if strings.Contains(err.Error(), "error parsing file") {
				class = "template-parse"
			}
			message := err.Error()
			if temporary != "" {
				message = strings.ReplaceAll(message, temporary, "<template-root>")
			}
			result.Error = &oracleError{Class: class, Message: message}
			return finishReportResponse(result, writer)
		}
		if req.TemplateMode == "validate" {
			return finishReportResponse(result, writer)
		}
		reporter = templateReporter
	default:
		result.Error = &oracleError{Class: "format", Message: fmt.Sprintf("unknown report format %q", req.Format)}
		return finishReportResponse(result, writer)
	}

	if err := reporter.Write(writer, findings); err != nil {
		class := "writer"
		if req.Format == "template" && !errors.Is(err, errReportWriter) {
			class = "template-execute"
		}
		result.Error = &oracleError{Class: class, Message: err.Error()}
	}
	return finishReportResponse(result, writer)
}

func finishReportResponse(result reportResponse, writer *reportWriteCloser) reportResponse {
	var output []byte
	if writer != nil {
		output = writer.Bytes()
	}
	digest := sha256.Sum256(output)
	result.OutputBase64 = base64.StdEncoding.EncodeToString(output)
	result.OutputBytes = len(output)
	result.OutputSHA256 = hex.EncodeToString(digest[:])
	return result
}

func decodeReportFinding(input reportFindingInput) (report.Finding, error) {
	decode := func(value, field string) (string, error) { return decodeReportBase64(value, field) }
	values := make([]string, 0, 14)
	for _, item := range []struct{ value, field string }{
		{input.RuleIDBase64, "rule_id"}, {input.DescriptionBase64, "description"},
		{input.LineBase64, "line"}, {input.MatchBase64, "match"}, {input.SecretBase64, "secret"},
		{input.FileBase64, "file"}, {input.SymlinkFileBase64, "symlink_file"},
		{input.CommitBase64, "commit"}, {input.LinkBase64, "link"}, {input.AuthorBase64, "author"},
		{input.EmailBase64, "email"}, {input.DateBase64, "date"}, {input.MessageBase64, "message"},
		{input.FingerprintBase64, "fingerprint"},
	} {
		value, err := decode(item.value, item.field)
		if err != nil {
			return report.Finding{}, err
		}
		values = append(values, value)
	}
	var tags []string
	if !input.TagsNil {
		tags = make([]string, 0, len(input.TagsBase64))
		for index, encoded := range input.TagsBase64 {
			tag, err := decode(encoded, "tag")
			if err != nil {
				return report.Finding{}, fmt.Errorf("tag %d: %w", index, err)
			}
			tags = append(tags, tag)
		}
	}
	return report.Finding{
		RuleID: values[0], Description: values[1], StartLine: input.StartLine, EndLine: input.EndLine,
		StartColumn: input.StartColumn, EndColumn: input.EndColumn, Line: values[2], Match: values[3], Secret: values[4],
		File: values[5], SymlinkFile: values[6], Commit: values[7], Link: values[8], Entropy: math.Float32frombits(input.EntropyBits),
		Author: values[9], Email: values[10], Date: values[11], Message: values[12], Tags: tags, Fingerprint: values[13],
	}, nil
}

func decodeReportBase64(value, field string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("invalid %s base64", field)
	}
	return string(decoded), nil
}

func runGitRequest(req gitRequest, result gitResponse) gitResponse {
	// Spaces and non-ASCII in the private root make accidental shell parsing or
	// lossy path conversion observable in every real-Git corpus case.
	temporary, err := os.MkdirTemp("", "gitleaks git Ω oracle-")
	if err != nil {
		result.Error = &oracleError{Class: "io", Message: err.Error()}
		return result
	}
	defer os.RemoveAll(temporary)
	globalConfig := filepath.Join(temporary, "empty-gitconfig")
	if err := os.WriteFile(globalConfig, nil, 0o600); err != nil {
		result.Error = &oracleError{Class: "io", Message: err.Error()}
		return result
	}

	repository := filepath.Join(temporary, "repository")
	if err := os.Mkdir(repository, 0o755); err != nil {
		result.Error = &oracleError{Class: "io", Message: err.Error()}
		return result
	}
	if req.Repository != "empty" {
		fixture, fixtureErr := gitFixturePath(req.Repository)
		if fixtureErr != nil {
			result.Error = &oracleError{Class: "request", Message: fixtureErr.Error()}
			return result
		}
		if copyErr := copySourceFixture(fixture, repository); copyErr != nil {
			result.Error = &oracleError{Class: "io", Message: copyErr.Error()}
			return result
		}
		dotGit := filepath.Join(repository, "dotGit")
		gitDir := filepath.Join(repository, ".git")
		if _, statErr := os.Lstat(gitDir); !errors.Is(statErr, os.ErrNotExist) {
			result.Error = &oracleError{Class: "fixture", Message: "copied fixture unexpectedly contains .git"}
			return result
		}
		if renameErr := os.Rename(dotGit, gitDir); renameErr != nil {
			result.Error = &oracleError{Class: "fixture", Message: renameErr.Error()}
			return result
		}
	}
	if err := applyGitMutation(repository, req.Mutation, globalConfig); err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	if req.RemoteURL != "" {
		if err := setGitRemote(repository, req.RemoteURL, globalConfig); err != nil {
			result.Error = &oracleError{Class: "fixture", Message: err.Error()}
			return result
		}
	}

	restoreEnvironment, err := isolateGitEnvironment(globalConfig)
	if err != nil {
		result.Error = &oracleError{Class: "io", Message: err.Error()}
		return result
	}
	defer restoreEnvironment()
	versionCommand := exec.Command("git", "--version")
	versionCommand.Env = isolatedCommandEnvironment(globalConfig)
	versionOutput, err := versionCommand.Output()
	if err != nil {
		result.Error = &oracleError{Class: "git", Message: err.Error()}
		return result
	}
	result.GitVersionBase64 = b64(string(bytes.TrimSpace(versionOutput)))

	platform, err := scm.PlatformFromString(req.Platform)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remote := sources.NewRemoteInfoContext(ctx, platform, repository)
	result.Remote = canonicalGitRemote(remote)
	if req.Operation == "remote" {
		return result
	}
	cfg, _, err := loadAllowlistDetectorConfig(allowlistRequest{
		UseDefault: req.ConfigFixture == "", ConfigFixture: req.ConfigFixture,
	})
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	if len(req.AllowCommits) != 0 {
		allowlist := &config.Allowlist{Commits: cloneStrings(req.AllowCommits)}
		if err := allowlist.Validate(); err != nil {
			result.Error = &oracleError{Class: "config", Message: err.Error()}
			return result
		}
		cfg.Allowlists = append(cfg.Allowlists, allowlist)
	}
	var detector *detect.Detector
	if req.Detect {
		detector = detect.NewDetectorContext(ctx, cfg)
		if req.LoadIgnore {
			if err := detector.AddGitleaksIgnore(filepath.Join(repository, ".gitleaksignore")); err != nil {
				result.Error = &oracleError{Class: "ignore", Message: err.Error()}
				return result
			}
		}
	}

	var command *sources.GitCmd
	switch req.Operation {
	case "log":
		command, err = sources.NewGitLogCmdContext(ctx, repository, req.LogOptions)
		result.ArgumentsBase64 = b64Slice(gitLogArguments(req.LogOptions))
	case "diff":
		command, err = sources.NewGitDiffCmdContext(ctx, repository, req.Staged)
		result.ArgumentsBase64 = b64Slice(gitDiffArguments(req.Staged))
	default:
		result.Error = &oracleError{Class: "request", Message: fmt.Sprintf("unknown Git operation %q", req.Operation)}
		return result
	}
	if err != nil {
		result.Error = &oracleError{Class: classifyGitError(err), Message: normalizeGitText(err.Error(), repository)}
		return result
	}
	result.CommandBase64 = b64(normalizeGitText(command.String(), repository))
	if req.CancelAfterStart {
		cancel()
	}

	sema := semgroup.NewGroup(ctx, 1)
	source := &sources.Git{Cmd: command, Config: &cfg, Remote: remote, Sema: sema, MaxArchiveDepth: req.MaxArchiveDepth}
	var lock sync.Mutex
	err = source.Fragments(ctx, func(fragment sources.Fragment, issue error) error {
		projected := canonicalGitFragment(fragment)
		lock.Lock()
		result.Fragments = append(result.Fragments, projected)
		if issue != nil {
			result.Issues = append(result.Issues, gitIssue{
				Fragment: projected, Class: classifyGitError(issue),
				Message: normalizeGitText(issue.Error(), repository),
			})
		}
		lock.Unlock()
		if issue == nil && detector != nil {
			for _, finding := range detector.Detect(detect.Fragment(fragment)) {
				detector.AddFinding(finding)
			}
		}
		return nil
	})
	if err != nil {
		result.Error = &oracleError{Class: classifyGitError(err), Message: normalizeGitText(err.Error(), repository)}
	}
	if detector != nil {
		for _, finding := range detector.Findings() {
			result.Findings = append(result.Findings, canonicalDirectFinding(finding))
		}
	}
	canonicalizeGitResult(&result)
	return result
}

func gitFixturePath(repository string) (string, error) {
	if repository != "small" && repository != "staged" && repository != "archives" {
		return "", fmt.Errorf("unknown Git fixture %q", repository)
	}
	return sourceFixturePath(filepath.Join("testdata", "repos", repository))
}

func applyGitMutation(repository, mutation, globalConfig string) error {
	switch mutation {
	case "":
		return nil
	case "working-additions":
		return os.WriteFile(filepath.Join(repository, "main.go"), []byte("this line is added\nand another one"), 0o644)
	case "delete-main":
		return os.Remove(filepath.Join(repository, "main.go"))
	case "binary-main":
		return os.WriteFile(filepath.Join(repository, "main.go"), []byte{'b', 'i', 'n', 0, 'a', 'r', 'y'}, 0o644)
	case "staged-rename":
		command := exec.Command("git", "-C", repository, "mv", "main.go", "renamed.go")
		command.Env = isolatedCommandEnvironment(globalConfig)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("stage rename: %w: %s", err, bytes.TrimSpace(output))
		}
		return nil
	case "staged-bad-archive":
		if err := os.Rename(filepath.Join(repository, "main.go"), filepath.Join(repository, "broken.zip")); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(repository, "broken.zip"), []byte{'P', 'K', 3, 4, 0, 'x'}, 0o644); err != nil {
			return err
		}
		command := exec.Command("git", "-C", repository, "add", "-A", "--", "main.go", "broken.zip")
		command.Env = isolatedCommandEnvironment(globalConfig)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("stage malformed archive: %w: %s", err, bytes.TrimSpace(output))
		}
		return nil
	case "binary-archive-worktree":
		return os.WriteFile(filepath.Join(repository, "main.go.zst"), []byte{'b', 'a', 'd', 0, 'z', 's', 't'}, 0o644)
	default:
		return fmt.Errorf("unknown Git mutation %q", mutation)
	}
}

func setGitRemote(repository, remote, globalConfig string) error {
	command := exec.Command("git", "-C", repository, "remote", "set-url", "origin", remote)
	command.Env = isolatedCommandEnvironment(globalConfig)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("set remote: %w: %s", err, bytes.TrimSpace(output))
	}
	return nil
}

func isolatedCommandEnvironment(globalConfig string) []string {
	environment := os.Environ()
	environment = append(environment, "GIT_CONFIG_GLOBAL="+globalConfig, "GIT_CONFIG_NOSYSTEM=1", "LC_ALL=C", "TZ=UTC")
	return environment
}

func isolateGitEnvironment(globalConfig string) (func(), error) {
	keys := []string{"GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "LC_ALL", "TZ"}
	values := []string{globalConfig, "1", "C", "UTC"}
	previous := make([]string, len(keys))
	present := make([]bool, len(keys))
	for index, key := range keys {
		previous[index], present[index] = os.LookupEnv(key)
		if err := os.Setenv(key, values[index]); err != nil {
			return nil, err
		}
	}
	return func() {
		for index, key := range keys {
			if present[index] {
				_ = os.Setenv(key, previous[index])
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}, nil
}

func gitLogArguments(logOptions string) []string {
	arguments := []string{"git", "-C", "<repo>", "log", "-p", "-U0"}
	if logOptions == "" {
		return append(arguments, "--full-history", "--all", "--diff-filter=tuxdb")
	}
	return append(arguments, strings.Split(logOptions, " ")...)
}

func gitDiffArguments(staged bool) []string {
	arguments := []string{"git", "-C", "<repo>", "diff", "-U0", "--no-ext-diff"}
	if staged {
		arguments = append(arguments, "--staged")
	}
	return append(arguments, ".")
}

func canonicalGitFragment(fragment sources.Fragment) gitFragment {
	result := gitFragment{
		RawBase64: b64(fragment.Raw), BytesBase64: base64.StdEncoding.EncodeToString(fragment.Bytes), BytesNil: fragment.Bytes == nil,
		FileBase64: b64(fragment.FilePath), WindowsFileBase64: b64(fragment.WindowsFilePath),
		SymlinkFileBase64: b64(fragment.SymlinkFile), CommitBase64: b64(fragment.CommitSHA),
		StartLine: fragment.StartLine, Inherited: fragment.InheritedFromFinding,
	}
	if fragment.CommitInfo != nil {
		result.CommitInfo = &gitCommitInfo{
			AuthorNameBase64: b64(fragment.CommitInfo.AuthorName), AuthorEmailBase64: b64(fragment.CommitInfo.AuthorEmail),
			DateBase64: b64(fragment.CommitInfo.Date), MessageBase64: b64(fragment.CommitInfo.Message),
			SHABase64: b64(fragment.CommitInfo.SHA), Remote: canonicalGitRemote(fragment.CommitInfo.Remote),
		}
	}
	return result
}

func canonicalGitRemote(remote *sources.RemoteInfo) *gitRemote {
	if remote == nil {
		return nil
	}
	return &gitRemote{Platform: remote.Platform.String(), URLBase64: b64(remote.Url)}
}

func canonicalizeGitResult(result *gitResponse) {
	result.CanonicalFragments = append(result.CanonicalFragments[:0], result.Fragments...)
	sort.SliceStable(result.CanonicalFragments, func(i, j int) bool {
		a, _ := json.Marshal(result.CanonicalFragments[i])
		b, _ := json.Marshal(result.CanonicalFragments[j])
		return bytes.Compare(a, b) < 0
	})
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, _ := json.Marshal(result.Findings[i])
		b, _ := json.Marshal(result.Findings[j])
		return bytes.Compare(a, b) < 0
	})
}

func normalizeGitText(value, repository string) string {
	if executable, err := exec.LookPath("git"); err == nil {
		value = strings.Replace(value, executable, "git", 1)
	}
	value = strings.ReplaceAll(value, filepath.ToSlash(repository), "<repo>")
	return strings.ReplaceAll(value, repository, "<repo>")
}

func classifyGitError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if err != nil && err.Error() == "stderr is not empty" {
		return "stderr"
	}
	return "git"
}

func runSourceBoundary(req sourceRequest, result sourceResponse) sourceResponse {
	data, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil || req.BufferSize < 0 || req.MaxPeekSize < 0 {
		result.Error = &oracleError{Class: "request", Message: "invalid boundary request"}
		return result
	}
	buffer := make([]byte, req.BufferSize)
	reader := bufio.NewReader(bytes.NewReader(data))
	startLine := 1
	for {
		n, readErr := reader.Read(buffer)
		result.ReadCalls++
		if readErr != nil && readErr != io.EOF {
			result.Error = &oracleError{Class: "read", Message: readErr.Error()}
			return result
		}
		if n == 0 && len(buffer) != 0 {
			return result
		}
		peek := bytes.NewBuffer(buffer[:n])
		if err := sourceReadUntilSafeBoundary(reader, n, req.MaxPeekSize, peek); err != nil {
			result.Error = &oracleError{Class: "read", Message: err.Error()}
			return result
		}
		fragment := sourceFragment{RawBase64: b64(peek.String()), BytesBase64: b64(peek.String()), FileBase64: b64(""),
			WindowsFileBase64: b64(""), SymlinkFileBase64: b64(""), CommitBase64: b64(""), StartLine: startLine}
		result.Fragments = append(result.Fragments, fragment)
		result.CanonicalFragments = append(result.CanonicalFragments, fragment)
		if len(buffer) == 0 || readErr == io.EOF {
			return result
		}
		startLine += bytes.Count(peek.Bytes(), []byte{'\n'})
	}
}

// This is a protocol exposure of pinned sources.readUntilSafeBoundary. Its
// source hash is checked by the corpus generator, and the focused upstream test
// is run separately, so changes cannot silently diverge from the private Go
// helper merely because it is not importable from another package.
func sourceReadUntilSafeBoundary(r *bufio.Reader, n, maxPeekSize int, peek *bytes.Buffer) error {
	if peek.Len() == 0 {
		return nil
	}
	whitespace := func(value byte) bool { return value == ' ' || value == '\t' || value == '\n' || value == '\r' }
	data := peek.Bytes()
	last := data[len(data)-1]
	newlines := 0
	if whitespace(last) {
		for index := len(data) - 1; index >= 0; index-- {
			last = data[index]
			if last == '\n' {
				newlines++
				if newlines >= 2 {
					return nil
				}
			} else if !whitespace(last) {
				break
			}
		}
	}
	newlines = 0
	for {
		data = peek.Bytes()
		last = data[len(data)-1]
		if last == '\n' {
			newlines++
			if newlines >= 2 {
				break
			}
		} else if !whitespace(last) {
			newlines = 0
		}
		if peek.Len()-n >= maxPeekSize {
			break
		}
		value, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		peek.WriteByte(value)
	}
	return nil
}

func runSourceFile(req sourceRequest, result sourceResponse) sourceResponse {
	reader, scheduled, err := sourceReader(req)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	path, err := decodeSourcePath(req.PathBase64, req.LogicalPath)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	cfg, err := sourceConfig(req.ConfigFixture, req.SkipPathsBase64)
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if req.CancelBefore {
		cancel()
	}
	file := &sources.File{Content: reader, Path: path, MaxArchiveDepth: req.MaxArchiveDepth, Config: cfg}
	if req.BufferSize > 0 {
		file.Buffer = make([]byte, req.BufferSize)
	}
	result = collectSourceFragments(ctx, file, req, result, "")
	if scheduled != nil {
		result.ReadCalls = scheduled.calls
	}
	return result
}

func runSourceFiles(req sourceRequest, result sourceResponse) sourceResponse {
	temporary, err := os.MkdirTemp("", "rustleaks-source-oracle-")
	if err != nil {
		result.Error = &oracleError{Class: "io", Message: err.Error()}
		return result
	}
	defer os.RemoveAll(temporary)
	root := filepath.Join(temporary, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		result.Error = &oracleError{Class: "io", Message: err.Error()}
		return result
	}
	if req.FixturePath != "" {
		fixture, fixtureErr := sourceFixturePath(req.FixturePath)
		if fixtureErr != nil {
			result.Error = &oracleError{Class: "request", Message: fixtureErr.Error()}
			return result
		}
		if fixtureErr := copySourceFixture(fixture, root); fixtureErr != nil {
			result.Error = &oracleError{Class: "io", Message: fixtureErr.Error()}
			return result
		}
	}
	if err := materializeSourceEntries(root, req.Entries); err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	normalizationRoot := root
	if req.RootSubpath != "" {
		clean := filepath.Clean(req.RootSubpath)
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			result.Error = &oracleError{Class: "request", Message: "root_subpath escapes root"}
			return result
		}
		root = filepath.Join(root, clean)
	}
	cfg, err := sourceConfig(req.ConfigFixture, req.SkipPathsBase64)
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if req.CancelBefore {
		cancel()
	}
	if req.MissingRoot {
		if err := os.Remove(root); err != nil {
			result.Error = &oracleError{Class: "io", Message: err.Error()}
			return result
		}
	}
	workerLimit := req.WorkerLimit
	if workerLimit <= 0 {
		workerLimit = 2
	}
	sema := semgroup.NewGroup(context.Background(), int64(workerLimit))
	files := &sources.Files{Path: root, Config: cfg, FollowSymlinks: req.FollowSymlinks,
		MaxFileSize: req.MaxFileSize, MaxArchiveDepth: req.MaxArchiveDepth, Sema: sema}
	logical := req.LogicalPath
	if logical == "" {
		logical = "<root>"
	}
	normalizationLogical := logical
	if req.RootSubpath != "" {
		suffix := "/" + filepath.ToSlash(filepath.Clean(req.RootSubpath))
		if strings.HasSuffix(filepath.ToSlash(normalizationLogical), suffix) {
			normalizationLogical = strings.TrimSuffix(filepath.ToSlash(normalizationLogical), suffix)
		}
	}
	physicalRoot, resolveErr := filepath.EvalSymlinks(root)
	if resolveErr != nil {
		physicalRoot = root
	}
	physicalNormalizationRoot, resolveErr := filepath.EvalSymlinks(normalizationRoot)
	if resolveErr != nil {
		physicalNormalizationRoot = normalizationRoot
	}
	files.Path = physicalRoot
	return collectSourceFragments(ctx, files, req, result, physicalNormalizationRoot+"\x00"+normalizationLogical)
}

func runSourceReader(req sourceRequest, result sourceResponse) sourceResponse {
	reader, scheduled, err := sourceReader(req)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	cfg, _, err := loadAllowlistDetectorConfig(allowlistRequest{UseDefault: req.ConfigFixture == "", ConfigFixture: req.ConfigFixture})
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	detector := detect.NewDetector(cfg)
	bufferKB := req.BufferSize
	if bufferKB <= 0 {
		bufferKB = 10
	}
	if req.Stream {
		findings, final := detector.StreamDetectReader(reader, bufferKB)
		for finding := range findings {
			result.Findings = append(result.Findings, canonicalDirectFinding(finding))
		}
		if finalErr := <-final; finalErr != nil {
			result.Issues = append(result.Issues, sourceIssue{Fragment: emptySourceFragment(), Class: "read", Message: finalErr.Error()})
		}
	} else {
		findings, finalErr := detector.DetectReader(reader, bufferKB)
		for _, finding := range findings {
			result.Findings = append(result.Findings, canonicalDirectFinding(finding))
		}
		if finalErr != nil {
			result.Issues = append(result.Issues, sourceIssue{Fragment: emptySourceFragment(), Class: "read", Message: finalErr.Error()})
		}
	}
	if scheduled != nil {
		result.ReadCalls = scheduled.calls
	}
	canonicalizeSourceResult(&result)
	return result
}

func collectSourceFragments(ctx context.Context, source sources.Source, req sourceRequest, result sourceResponse, normalization string) sourceResponse {
	var lock sync.Mutex
	var active int32
	var maximum int32
	emitted := 0
	var detector *detect.Detector
	if req.Detect {
		cfg, _, err := loadAllowlistDetectorConfig(allowlistRequest{UseDefault: req.ConfigFixture == "", ConfigFixture: req.ConfigFixture})
		if err != nil {
			result.Error = &oracleError{Class: "config", Message: err.Error()}
			return result
		}
		detector = detect.NewDetector(cfg)
		if req.IgnoreFixture != "" {
			path, pathErr := sourceFixturePath(req.IgnoreFixture)
			if pathErr != nil {
				result.Error = &oracleError{Class: "request", Message: pathErr.Error()}
				return result
			}
			if ignoreErr := detector.AddGitleaksIgnore(path); ignoreErr != nil {
				result.Error = &oracleError{Class: "ignore", Message: ignoreErr.Error()}
				return result
			}
		}
	}
	err := source.Fragments(ctx, func(fragment sources.Fragment, issue error) error {
		current := atomic.AddInt32(&active, 1)
		defer atomic.AddInt32(&active, -1)
		for {
			prior := atomic.LoadInt32(&maximum)
			if current <= prior || atomic.CompareAndSwapInt32(&maximum, prior, current) {
				break
			}
		}
		projected := canonicalSourceFragment(fragment)
		if normalization != "" {
			parts := strings.SplitN(normalization, "\x00", 2)
			projected = normalizeSourceFragment(projected, parts[0], parts[1])
		}
		lock.Lock()
		emitted++
		result.Fragments = append(result.Fragments, projected)
		if issue != nil {
			result.Issues = append(result.Issues, sourceIssue{Fragment: projected, Class: "read", Message: normalizeSourceMessage(issue.Error(), normalization)})
		}
		position := emitted
		lock.Unlock()
		if issue == nil && detector != nil {
			detectFragment := fragment
			if normalization != "" {
				parts := strings.SplitN(normalization, "\x00", 2)
				detectFragment.FilePath = normalizeSourcePathText(detectFragment.FilePath, parts[0], parts[1])
				detectFragment.WindowsFilePath = normalizeSourcePathText(detectFragment.WindowsFilePath, parts[0], parts[1])
				detectFragment.SymlinkFile = normalizeSourcePathText(detectFragment.SymlinkFile, parts[0], parts[1])
			}
			for _, finding := range detector.DetectContext(ctx, detect.Fragment(detectFragment)) {
				detector.AddFinding(finding)
			}
		}
		if req.YieldErrorAfter > 0 && position >= req.YieldErrorAfter {
			return errors.New("scheduled yield error")
		}
		return nil
	})
	result.ConcurrentCallbacks = maximum
	if err != nil {
		class := "source"
		if errors.Is(err, context.Canceled) {
			class = "canceled"
		} else if err.Error() == "scheduled yield error" {
			class = "yield"
		}
		result.Error = &oracleError{Class: class, Message: normalizeSourceMessage(err.Error(), normalization)}
	}
	if detector != nil {
		for _, finding := range detector.Findings() {
			canonical := canonicalDirectFinding(finding)
			if normalization != "" {
				parts := strings.SplitN(normalization, "\x00", 2)
				canonical = normalizeDirectFinding(canonical, parts[0], parts[1])
			}
			result.Findings = append(result.Findings, canonical)
		}
	}
	canonicalizeSourceResult(&result)
	return result
}

func canonicalSourceFragment(fragment sources.Fragment) sourceFragment {
	return sourceFragment{
		RawBase64: b64(fragment.Raw), BytesBase64: base64.StdEncoding.EncodeToString(fragment.Bytes), BytesNil: fragment.Bytes == nil,
		FileBase64: b64(fragment.FilePath), WindowsFileBase64: b64(fragment.WindowsFilePath),
		SymlinkFileBase64: b64(fragment.SymlinkFile), CommitBase64: b64(fragment.CommitSHA),
		StartLine: fragment.StartLine, Inherited: fragment.InheritedFromFinding,
	}
}

func emptySourceFragment() sourceFragment {
	return sourceFragment{RawBase64: b64(""), BytesBase64: b64(""), BytesNil: true, FileBase64: b64(""),
		WindowsFileBase64: b64(""), SymlinkFileBase64: b64(""), CommitBase64: b64("")}
}

func canonicalizeSourceResult(result *sourceResponse) {
	result.CanonicalFragments = append(result.CanonicalFragments[:0], result.Fragments...)
	sort.SliceStable(result.CanonicalFragments, func(i, j int) bool {
		a, _ := json.Marshal(result.CanonicalFragments[i])
		b, _ := json.Marshal(result.CanonicalFragments[j])
		return bytes.Compare(a, b) < 0
	})
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, _ := json.Marshal(result.Findings[i])
		b, _ := json.Marshal(result.Findings[j])
		return bytes.Compare(a, b) < 0
	})
}

func normalizeSourceFragment(fragment sourceFragment, physical, logical string) sourceFragment {
	fragment.FileBase64 = normalizeBase64Path(fragment.FileBase64, physical, logical)
	fragment.WindowsFileBase64 = normalizeBase64Path(fragment.WindowsFileBase64, physical, logical)
	fragment.SymlinkFileBase64 = normalizeBase64Path(fragment.SymlinkFileBase64, physical, logical)
	return fragment
}

func normalizeDirectFinding(finding directFinding, physical, logical string) directFinding {
	finding.FileBase64 = normalizeBase64Path(finding.FileBase64, physical, logical)
	finding.SymlinkFileBase64 = normalizeBase64Path(finding.SymlinkFileBase64, physical, logical)
	finding.FingerprintBase64 = normalizeBase64Path(finding.FingerprintBase64, physical, logical)
	return finding
}

func normalizeBase64Path(encoded, physical, logical string) string {
	value, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	normalized := strings.ReplaceAll(string(value), filepath.ToSlash(physical), filepath.ToSlash(logical))
	normalized = strings.ReplaceAll(normalized, physical, logical)
	return b64(normalized)
}

func normalizeSourcePathText(value, physical, logical string) string {
	value = strings.ReplaceAll(value, filepath.ToSlash(physical), filepath.ToSlash(logical))
	return strings.ReplaceAll(value, physical, logical)
}

func normalizeSourceMessage(message, normalization string) string {
	if normalization == "" {
		return message
	}
	parts := strings.SplitN(normalization, "\x00", 2)
	message = strings.ReplaceAll(message, filepath.ToSlash(parts[0]), filepath.ToSlash(parts[1]))
	return strings.ReplaceAll(message, parts[0], parts[1])
}

func sourceReader(req sourceRequest) (io.Reader, *scheduledSourceReader, error) {
	if len(req.ReaderSchedule) != 0 {
		reader := &scheduledSourceReader{steps: req.ReaderSchedule}
		return reader, reader, nil
	}
	if req.FixturePath != "" {
		path, err := sourceFixturePath(req.FixturePath)
		if err != nil {
			return nil, nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		return bytes.NewReader(data), nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil {
		return nil, nil, errors.New("invalid content base64")
	}
	return bytes.NewReader(data), nil, nil
}

func decodeSourcePath(encoded, logical string) (string, error) {
	if encoded != "" {
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", errors.New("invalid path base64")
		}
		return string(value), nil
	}
	return logical, nil
}

func sourceFixturePath(relative string) (string, error) {
	clean := filepath.Clean(relative)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
		!(clean == "testdata" || strings.HasPrefix(clean, "testdata"+string(filepath.Separator))) {
		return "", errors.New("fixture_path must stay within compat/fixtures/upstream/testdata")
	}
	root, err := filepath.Abs("../../../compat/fixtures/upstream")
	if err != nil {
		return "", err
	}
	return filepath.Join(root, clean), nil
}

func sourceConfig(fixture string, skipPaths []string) (*config.Config, error) {
	if fixture == "" && len(skipPaths) == 0 {
		return nil, nil
	}
	var cfg config.Config
	if fixture != "" {
		loaded, _, err := loadAllowlistDetectorConfig(allowlistRequest{ConfigFixture: fixture})
		if err != nil {
			return nil, err
		}
		cfg = loaded
	}
	if len(skipPaths) != 0 {
		allowlist := &config.Allowlist{}
		for index, encoded := range skipPaths {
			pattern, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("invalid skip_paths_base64[%d]", index)
			}
			compiled, err := regexp.Compile(string(pattern))
			if err != nil {
				return nil, fmt.Errorf("invalid skip path pattern: %w", err)
			}
			allowlist.Paths = append(allowlist.Paths, compiled)
		}
		if err := allowlist.Validate(); err != nil {
			return nil, err
		}
		cfg.Allowlists = append(cfg.Allowlists, allowlist)
	}
	return &cfg, nil
}

func copySourceFixture(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destination, filepath.Base(source)), data, info.Mode().Perm())
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

func materializeSourceEntries(root string, entries []sourceEntry) error {
	for _, entry := range entries {
		clean := filepath.Clean(entry.Path)
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("entry path %q escapes root", entry.Path)
		}
		path := filepath.Join(root, clean)
		switch entry.Kind {
		case "dir":
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case "file":
			data, err := base64.StdEncoding.DecodeString(entry.ContentBase64)
			if err != nil {
				return fmt.Errorf("invalid content base64 for %q", entry.Path)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				return err
			}
			if entry.Mode != nil {
				if err := os.Chmod(path, os.FileMode(*entry.Mode)); err != nil {
					return err
				}
			}
		case "symlink":
			if filepath.IsAbs(entry.Target) {
				return fmt.Errorf("absolute symlink target for %q", entry.Path)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(entry.Target, path); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown entry kind %q", entry.Kind)
		}
	}
	return nil
}

func runSessionRequest(req sessionRequest, result sessionResponse) sessionResponse {
	temporary, err := os.MkdirTemp("", "gitleaks-session-oracle-")
	if err != nil {
		result.Error = &oracleError{Class: "io", Message: err.Error()}
		return result
	}
	defer os.RemoveAll(temporary)

	cfg := config.Config{Rules: map[string]config.Rule{}, Keywords: map[string]struct{}{}, OrderedRules: []string{}}
	detector := detect.NewDetector(cfg)
	detector.Redact = req.RedactPercent

	ignoreKeys := map[string]struct{}{}
	if req.IgnoreFile != nil {
		result.Ignore.Configured = true
		logicalName := req.IgnoreFile.Name
		if logicalName == "" {
			logicalName = ".gitleaksignore"
		}
		ignorePath := filepath.Join(temporary, ".gitleaksignore")
		if !req.IgnoreFile.Missing {
			content, decodeErr := base64.StdEncoding.DecodeString(req.IgnoreFile.ContentBase64)
			if decodeErr != nil {
				result.Error = &oracleError{Class: "request", Message: "invalid ignore file base64"}
				return result
			}
			if writeErr := os.WriteFile(ignorePath, content, 0o600); writeErr != nil {
				result.Error = &oracleError{Class: "io", Message: writeErr.Error()}
				return result
			}
		}
		if loadErr := detector.AddGitleaksIgnore(ignorePath); loadErr != nil {
			result.Error = &oracleError{Class: "ignore-open", Message: "could not open " + logicalName}
			return result
		}
		result.Ignore.Loaded = true
		ignoreMap := reflect.ValueOf(detector).Elem().FieldByName("gitleaksIgnore")
		keys := make([]string, 0, ignoreMap.Len())
		for _, key := range ignoreMap.MapKeys() {
			keys = append(keys, key.String())
		}
		sort.Strings(keys)
		result.Ignore.EntriesBase64 = b64Slice(keys)
		result.Ignore.UniqueCount = len(keys)
		for _, key := range keys {
			ignoreKeys[key] = struct{}{}
		}
	}

	var baseline []report.Finding
	if req.BaselineFile != nil {
		result.Baseline.Configured = true
		logicalName := req.BaselineFile.Name
		if logicalName == "" {
			logicalName = "baseline.json"
		}
		baselinePath := filepath.Join(temporary, "baseline.json")
		if !req.BaselineFile.Missing {
			content, decodeErr := base64.StdEncoding.DecodeString(req.BaselineFile.ContentBase64)
			if decodeErr != nil {
				result.Error = &oracleError{Class: "request", Message: "invalid baseline file base64"}
				return result
			}
			if writeErr := os.WriteFile(baselinePath, content, 0o600); writeErr != nil {
				result.Error = &oracleError{Class: "io", Message: writeErr.Error()}
				return result
			}
		}
		baseline, err = detect.LoadBaseline(baselinePath)
		if err != nil {
			message := strings.ReplaceAll(err.Error(), baselinePath, logicalName)
			class := "baseline"
			if strings.HasPrefix(err.Error(), "could not open ") {
				class = "baseline-open"
			} else if strings.HasPrefix(err.Error(), "the format of the file ") {
				class = "baseline-format"
			}
			result.Error = &oracleError{Class: class, Message: message}
			return result
		}
		if err := detector.AddBaseline(baselinePath, temporary); err != nil {
			result.Error = &oracleError{Class: "baseline", Message: strings.ReplaceAll(err.Error(), baselinePath, logicalName)}
			return result
		}
		result.Baseline.Loaded = true
		for _, finding := range baseline {
			result.Baseline.Findings = append(result.Baseline.Findings, canonicalDirectFinding(finding))
		}
	}

	for index, input := range req.Findings {
		finding, _, decodeErr := input.decode()
		if decodeErr != nil {
			result.Error = &oracleError{Class: "request", Message: decodeErr.Error()}
			return result
		}
		result.InputFindings = append(result.InputFindings, canonicalDirectFinding(finding))
		globalFingerprint := fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
		qualifiedFingerprint := globalFingerprint
		if finding.Commit != "" {
			qualifiedFingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
		}
		_, ignoredGlobal := ignoreKeys[globalFingerprint]
		_, ignoredCommit := ignoreKeys[qualifiedFingerprint]
		if finding.Commit == "" {
			ignoredCommit = false
		}
		baselineIsNew := detect.IsNew(finding, req.RedactPercent, baseline)
		disposition := "accepted"
		switch {
		case ignoredGlobal:
			disposition = "ignored-global"
		case ignoredCommit:
			disposition = "ignored-commit"
		case !baselineIsNew:
			disposition = "ignored-baseline"
		}
		before := len(detector.Findings())
		detector.AddFinding(finding)
		after := len(detector.Findings())
		if (after == before+1) != (disposition == "accepted") {
			result.Error = &oracleError{Class: "adapter", Message: fmt.Sprintf("decision mismatch at finding %d", index)}
			return result
		}
		result.Decisions = append(result.Decisions, sessionDecision{
			Index: index, GlobalFingerprintBase64: b64(globalFingerprint),
			QualifiedFingerprintBase64: b64(qualifiedFingerprint), AssignedFingerprintBase64: b64(qualifiedFingerprint),
			IgnoredByGlobal: ignoredGlobal, IgnoredByCommit: ignoredCommit,
			BaselineIsNew: baselineIsNew, Disposition: disposition,
		})
	}
	for _, finding := range detector.Findings() {
		result.CollectedFindings = append(result.CollectedFindings, canonicalDirectFinding(finding))
	}
	result.CanonicalFindings = append(result.CanonicalFindings, result.CollectedFindings...)
	sort.SliceStable(result.CanonicalFindings, func(i, j int) bool {
		a, _ := json.Marshal(result.CanonicalFindings[i])
		b, _ := json.Marshal(result.CanonicalFindings[j])
		return bytes.Compare(a, b) < 0
	})
	return result
}

func runCompositeMissingRequiredProbe(req compositeRequest, result compositeResponse) compositeResponse {
	fragment, err := req.Fragment.decode()
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	primary := gitleaksregexp.MustCompile(`PRIMARY=[A-Z]+`)
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(fragment.Raw)))
	result.ConfigSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("programmatic:missing-required:v1")))
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"primary": {RuleID: "primary", Description: "Programmatic missing required probe", Regex: primary,
				RequiredRules: []*config.Required{{RuleID: "not-present"}}},
		},
		Keywords: map[string]struct{}{}, OrderedRules: []string{"primary"},
	}
	detector := detect.NewDetector(cfg)
	for _, finding := range detector.Detect(fragment) {
		result.Findings = append(result.Findings, canonicalDirectFinding(finding))
	}
	return result
}

func runCompositeDetect(req compositeRequest, result compositeResponse) compositeResponse {
	fragment, err := req.Fragment.decode()
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	inputBytes := []byte(fragment.Raw)
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(inputBytes))
	cfg, rawConfig, err := loadAllowlistDetectorConfig(allowlistRequest{
		UseDefault: req.UseDefault, ConfigBase64: req.ConfigBase64, ConfigFixture: req.ConfigFixture,
		ConfigEntry: req.ConfigEntry, ConfigFiles: req.ConfigFiles, ConfigWorkdir: req.ConfigWorkdir,
	})
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	result.ConfigSHA256 = fmt.Sprintf("%x", sha256.Sum256(rawConfig))
	detector := detect.NewDetector(cfg)
	detector.MaxDecodeDepth = req.Options.MaxDecodeDepth
	detector.MaxTargetMegaBytes = req.Options.MaxTargetMB
	detector.Redact = req.Options.RedactPercent
	detector.IgnoreGitleaksAllow = req.Options.IgnoreAllowMarker
	for _, finding := range detector.Detect(fragment) {
		result.Findings = append(result.Findings, canonicalDirectFinding(finding))
	}
	// Config.Rules is a Go map, so cross-process detector emission order is not
	// stable. Canonicalize only the outer finding set. RequiredFindings remains
	// in the exact primary -> required specification -> auxiliary match order.
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, _ := json.Marshal(result.Findings[i])
		b, _ := json.Marshal(result.Findings[j])
		return bytes.Compare(a, b) < 0
	})
	return result
}

func runCompositeRedact(req compositeRequest, result compositeResponse) compositeResponse {
	finding, raw, err := req.Redaction.decode()
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	original := canonicalDirectFinding(finding)
	result.Original = &original
	finding.Redact(req.RedactPercent)
	redacted := canonicalDirectFinding(finding)
	result.Redacted = &redacted
	return result
}

func (input compositeFindingInput) decode() (report.Finding, []byte, error) {
	decode := func(name, value string) (string, error) {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("invalid %s base64", name)
		}
		return string(raw), nil
	}
	values := []struct {
		name  string
		value string
	}{
		{"description", input.DescriptionBase64}, {"line", input.LineBase64}, {"match", input.MatchBase64},
		{"secret", input.SecretBase64}, {"file", input.FileBase64}, {"symlink_file", input.SymlinkFileBase64},
		{"commit", input.CommitBase64}, {"link", input.LinkBase64}, {"author", input.AuthorBase64},
		{"email", input.EmailBase64}, {"date", input.DateBase64}, {"message", input.MessageBase64},
		{"fingerprint", input.FingerprintBase64},
	}
	decoded := make([]string, len(values))
	for index, value := range values {
		text, err := decode(value.name, value.value)
		if err != nil {
			return report.Finding{}, nil, err
		}
		decoded[index] = text
	}
	tags := make([]string, 0, len(input.TagsBase64))
	for index, encoded := range input.TagsBase64 {
		tag, err := decode(fmt.Sprintf("tags[%d]", index), encoded)
		if err != nil {
			return report.Finding{}, nil, err
		}
		tags = append(tags, tag)
	}
	finding := report.Finding{
		RuleID: input.RuleID, Description: decoded[0], StartLine: input.StartLine, EndLine: input.EndLine,
		StartColumn: input.StartColumn, EndColumn: input.EndColumn, Line: decoded[1], Match: decoded[2],
		Secret: decoded[3], File: decoded[4], SymlinkFile: decoded[5], Commit: decoded[6], Link: decoded[7],
		Entropy: math.Float32frombits(input.EntropyBits), Author: decoded[8], Email: decoded[9], Date: decoded[10],
		Message: decoded[11], Tags: tags, Fingerprint: decoded[12],
	}
	if input.Fragment != nil {
		fragmentValues := []struct {
			name, value string
		}{
			{"fragment.raw", input.Fragment.RawBase64}, {"fragment.bytes", input.Fragment.BytesBase64},
			{"fragment.file", input.Fragment.FileBase64}, {"fragment.windows_file", input.Fragment.WindowsFileBase64},
			{"fragment.symlink_file", input.Fragment.SymlinkFileBase64}, {"fragment.commit", input.Fragment.CommitBase64},
		}
		fragmentDecoded := make([]string, len(fragmentValues))
		for index, value := range fragmentValues {
			text, err := decode(value.name, value.value)
			if err != nil {
				return report.Finding{}, nil, err
			}
			fragmentDecoded[index] = text
		}
		finding.Fragment = &sources.Fragment{
			Raw: fragmentDecoded[0], Bytes: []byte(fragmentDecoded[1]), FilePath: fragmentDecoded[2],
			WindowsFilePath: fragmentDecoded[3], SymlinkFile: fragmentDecoded[4], CommitSHA: fragmentDecoded[5],
			StartLine: input.Fragment.StartLine, InheritedFromFinding: input.Fragment.Inherited,
		}
	}
	for index, required := range input.RequiredFindings {
		line, err := decode(fmt.Sprintf("required_findings[%d].line", index), required.LineBase64)
		if err != nil {
			return report.Finding{}, nil, err
		}
		match, err := decode(fmt.Sprintf("required_findings[%d].match", index), required.MatchBase64)
		if err != nil {
			return report.Finding{}, nil, err
		}
		secret, err := decode(fmt.Sprintf("required_findings[%d].secret", index), required.SecretBase64)
		if err != nil {
			return report.Finding{}, nil, err
		}
		finding.AddRequiredFindings([]*report.RequiredFinding{{
			RuleID: required.RuleID, StartLine: required.StartLine, EndLine: required.EndLine,
			StartColumn: required.StartColumn, EndColumn: required.EndColumn,
			Line: line, Match: match, Secret: secret,
		}})
	}
	canonicalInput, err := json.Marshal(input)
	if err != nil {
		return report.Finding{}, nil, err
	}
	return finding, canonicalInput, nil
}

func safeRunDetect(req detectRequest) (result detectResponse) {
	result = newDetectResponse(req)
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Findings = []directFinding{}
			result.Error = &oracleError{Class: "panic", Message: fmt.Sprint(recovered)}
		}
	}()
	return runDetectRequest(req, result)
}

func newDetectResponse(req detectRequest) detectResponse {
	return detectResponse{
		ProtocolVersion:     detectProtocolVersion,
		OracleMode:          "detect",
		ID:                  req.ID,
		BehaviorIDs:         cloneStrings(req.BehaviorIDs),
		TestCaseIDs:         cloneStrings(req.TestCaseIDs),
		AssertionIDs:        cloneStrings(req.AssertionIDs),
		UpstreamRevision:    upstreamRevision,
		DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion:           runtime.Version(),
		Findings:            []directFinding{},
	}
}

func runDetectRequest(req detectRequest, result detectResponse) detectResponse {
	if req.ProtocolVersion != detectProtocolVersion {
		result.Error = &oracleError{
			Class: "protocol", Message: fmt.Sprintf("expected detector protocol %d", detectProtocolVersion),
		}
		return result
	}
	fragment, err := req.Fragment.decode()
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	inputBytes := []byte(fragment.Raw)
	result.InputSHA256 = fmt.Sprintf("%x", sha256.Sum256(inputBytes))

	rawConfig, err := detectorConfigBytes(req)
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	result.ConfigSHA256 = fmt.Sprintf("%x", sha256.Sum256(rawConfig))
	cfg, err := loadConfig(request{UseDefault: req.UseDefault, ConfigBase64: req.ConfigBase64})
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}

	detector := detect.NewDetector(cfg)
	detector.MaxDecodeDepth = req.Options.MaxDecodeDepth
	detector.MaxTargetMegaBytes = req.Options.MaxTargetMB
	detector.Redact = req.Options.RedactPercent
	detector.IgnoreGitleaksAllow = req.Options.IgnoreAllowMarker
	for _, finding := range detector.Detect(fragment) {
		result.Findings = append(result.Findings, canonicalDirectFinding(finding))
	}
	result.TotalBytes = detector.TotalBytes.Load()
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, _ := json.Marshal(result.Findings[i])
		b, _ := json.Marshal(result.Findings[j])
		return bytes.Compare(a, b) < 0
	})
	return result
}

func detectorConfigBytes(req detectRequest) ([]byte, error) {
	if req.UseDefault {
		return []byte(config.DefaultConfig), nil
	}
	raw, err := base64.StdEncoding.DecodeString(req.ConfigBase64)
	if err != nil {
		return nil, errors.New("invalid config base64")
	}
	return raw, nil
}

func canonicalDirectFinding(finding report.Finding) directFinding {
	result := directFinding{
		RuleID: finding.RuleID, DescriptionBase64: b64(finding.Description),
		StartLine: finding.StartLine, EndLine: finding.EndLine,
		StartColumn: finding.StartColumn, EndColumn: finding.EndColumn,
		LineBase64: b64(finding.Line), MatchBase64: b64(finding.Match), SecretBase64: b64(finding.Secret),
		FileBase64: b64(finding.File), SymlinkFileBase64: b64(finding.SymlinkFile),
		CommitBase64: b64(finding.Commit), LinkBase64: b64(finding.Link),
		EntropyBits: math.Float32bits(finding.Entropy), AuthorBase64: b64(finding.Author),
		EmailBase64: b64(finding.Email), DateBase64: b64(finding.Date), MessageBase64: b64(finding.Message),
		TagsBase64: b64Slice(finding.Tags), FingerprintBase64: b64(finding.Fingerprint),
		RequiredFindings: []directRequiredFinding{},
	}
	if finding.Fragment != nil {
		result.Fragment = &directFragmentSnapshot{
			RawBase64: b64(finding.Fragment.Raw), BytesBase64: base64.StdEncoding.EncodeToString(finding.Fragment.Bytes),
			FileBase64: b64(finding.Fragment.FilePath), WindowsFileBase64: b64(finding.Fragment.WindowsFilePath),
			SymlinkFileBase64: b64(finding.Fragment.SymlinkFile), CommitBase64: b64(finding.Fragment.CommitSHA),
			StartLine: finding.Fragment.StartLine, Inherited: finding.Fragment.InheritedFromFinding,
		}
	}
	// The pinned Go API intentionally keeps this slice private while exposing it
	// through terminal presentation. Reflection is limited to read-only scalar
	// access so the oracle can freeze the complete semantic result without an
	// unsafe pointer or a forked upstream package.
	field := reflect.ValueOf(&finding).Elem().FieldByName("requiredFindings")
	for index := 0; index < field.Len(); index++ {
		entry := field.Index(index)
		if entry.IsNil() {
			continue
		}
		entry = entry.Elem()
		result.RequiredFindings = append(result.RequiredFindings, directRequiredFinding{
			RuleID:    entry.FieldByName("RuleID").String(),
			StartLine: int(entry.FieldByName("StartLine").Int()), EndLine: int(entry.FieldByName("EndLine").Int()),
			StartColumn: int(entry.FieldByName("StartColumn").Int()), EndColumn: int(entry.FieldByName("EndColumn").Int()),
			LineBase64: b64(entry.FieldByName("Line").String()), MatchBase64: b64(entry.FieldByName("Match").String()),
			SecretBase64: b64(entry.FieldByName("Secret").String()),
		})
	}
	return result
}

func run(req request) response {
	result := response{
		ProtocolVersion: protocolVersion, ID: req.ID,
		UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion: runtime.Version(),
		Findings:  []oracleFinding{},
	}
	if req.ProtocolVersion != protocolVersion {
		result.Error = &oracleError{Class: "protocol", Message: fmt.Sprintf("expected protocol %d", protocolVersion)}
		return result
	}
	fragment, err := req.Fragment.decode()
	if err != nil {
		result.Error = &oracleError{Class: "request", Message: err.Error()}
		return result
	}
	cfg, err := loadConfig(req)
	if err != nil {
		result.Error = &oracleError{Class: "config", Message: err.Error()}
		return result
	}
	detector := detect.NewDetector(cfg)
	detector.MaxDecodeDepth = req.Options.MaxDecodeDepth
	detector.MaxTargetMegaBytes = req.Options.MaxTargetMB
	detector.Redact = req.Options.RedactPercent
	detector.IgnoreGitleaksAllow = req.Options.IgnoreAllowMarker
	for _, finding := range detector.Detect(fragment) {
		result.Findings = append(result.Findings, oracleFinding{
			RuleID: finding.RuleID, DescriptionB64: b64(finding.Description),
			StartLine: finding.StartLine, EndLine: finding.EndLine,
			StartColumn: finding.StartColumn, EndColumn: finding.EndColumn,
			LineB64: b64(finding.Line), MatchB64: b64(finding.Match), SecretB64: b64(finding.Secret),
			FileB64: b64(finding.File), SymlinkFileB64: b64(finding.SymlinkFile),
			CommitB64: b64(finding.Commit), LinkB64: b64(finding.Link), EntropyBits: math.Float32bits(finding.Entropy),
			AuthorB64: b64(finding.Author), EmailB64: b64(finding.Email), DateB64: b64(finding.Date),
			MessageB64: b64(finding.Message), TagsB64: b64Slice(finding.Tags), FingerprintB64: b64(finding.Fingerprint),
		})
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, _ := json.Marshal(result.Findings[i])
		b, _ := json.Marshal(result.Findings[j])
		return bytes.Compare(a, b) < 0
	})
	return result
}

func safeRun(req request) (result response) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = response{
				ProtocolVersion: protocolVersion, ID: req.ID,
				UpstreamRevision: upstreamRevision, DefaultConfigSHA256: defaultConfigSHA256,
				GoVersion: runtime.Version(), Findings: []oracleFinding{},
				Error: &oracleError{Class: "panic", Message: fmt.Sprint(recovered)},
			}
		}
	}()
	return run(req)
}

func loadConfig(req request) (config.Config, error) {
	var raw string
	if req.UseDefault {
		raw = config.DefaultConfig
	} else {
		decoded, err := base64.StdEncoding.DecodeString(req.ConfigBase64)
		if err != nil {
			return config.Config{}, errors.New("invalid config base64")
		}
		raw = string(decoded)
	}
	viper.Reset()
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(raw)); err != nil {
		return config.Config{}, err
	}
	var parsed config.ViperConfig
	if err := viper.Unmarshal(&parsed); err != nil {
		return config.Config{}, err
	}
	return parsed.Translate()
}

func safeRunConfig(req configRequest) (result configResponse) {
	result = newConfigResponse(req)
	var logBuffer bytes.Buffer
	logging.Logger = logging.Logger.Output(&logBuffer).Level(-1)
	defer func() {
		result.Diagnostics = canonicalDiagnostics(logBuffer.Bytes())
		if recovered := recover(); recovered != nil {
			result.Effective = nil
			result.Error = &configError{
				Class: "panic", Stage: "translate", Message: fmt.Sprint(recovered),
				CauseChain: []string{fmt.Sprint(recovered)},
			}
		}
	}()

	if req.ProtocolVersion != protocolVersion {
		result.Error = &configError{
			Class: "protocol", Stage: "request",
			Message:    fmt.Sprintf("expected protocol %d", protocolVersion),
			CauseChain: []string{fmt.Sprintf("expected protocol %d", protocolVersion)},
		}
		return result
	}

	raw, stage, err := configSourceBytes(req.Source)
	result.ConfigSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	if err != nil {
		result.Error = makeConfigError(stage, err)
		return result
	}
	cfg, stage, err := loadCanonicalConfig(req.Source, raw)
	if err != nil {
		result.Error = makeConfigError(stage, err)
		return result
	}
	canonical := canonicalizeConfig(cfg)
	result.Effective = &canonical
	return result
}

func newConfigResponse(req configRequest) configResponse {
	return configResponse{
		ProtocolVersion:     protocolVersion,
		OracleMode:          "config",
		ID:                  req.ID,
		UpstreamRevision:    upstreamRevision,
		DefaultConfigSHA256: defaultConfigSHA256,
		GoVersion:           runtime.Version(),
		Source: configSourceResult{
			Kind: req.Source.Kind, Path: req.Source.Path, Origin: req.Source.Origin,
		},
		Diagnostics: []configDiagnostic{},
	}
}

func configSourceBytes(source configSource) ([]byte, string, error) {
	var raw []byte
	var err error
	switch source.Kind {
	case "default":
		raw = []byte(config.DefaultConfig)
	case "inline", "origin":
		raw, err = base64.StdEncoding.DecodeString(source.ConfigBase64)
		if err != nil {
			return nil, "request", errors.New("invalid config base64")
		}
	case "path":
		if source.Path == "" {
			return nil, "request", errors.New("path source requires path")
		}
		raw, err = os.ReadFile(source.Path)
		if err != nil {
			return nil, "read", err
		}
	default:
		return nil, "request", fmt.Errorf("unknown config source kind %q", source.Kind)
	}
	return raw, "", nil
}

func loadCanonicalConfig(source configSource, raw []byte) (config.Config, string, error) {
	viper.Reset()
	viper.SetConfigType("toml")
	var err error
	switch source.Kind {
	case "default", "inline":
		err = viper.ReadConfig(bytes.NewReader(raw))
	case "origin":
		if source.Origin == "" {
			return config.Config{}, "request", errors.New("origin source requires origin")
		}
		viper.SetConfigFile(source.Origin)
		err = viper.ReadConfig(bytes.NewReader(raw))
	case "path":
		viper.SetConfigFile(source.Path)
		err = viper.ReadInConfig()
	}
	if err != nil {
		return config.Config{}, "parse", err
	}
	var parsed config.ViperConfig
	if err := viper.Unmarshal(&parsed); err != nil {
		return config.Config{}, "unmarshal", err
	}
	compiled, err := parsed.Translate()
	if err != nil {
		return config.Config{}, "translate", err
	}
	return compiled, "", nil
}

func makeConfigError(stage string, err error) *configError {
	class := "config"
	message := err.Error()
	switch stage {
	case "request", "read", "parse", "unmarshal":
		class = stage
	case "translate":
		switch {
		case strings.Contains(message, "extended config"), strings.Contains(message, "extend.path"):
			class = "extension"
		case strings.Contains(message, "required"):
			class = "required-rule"
		case strings.Contains(message, "allowlist") || strings.Contains(message, "allowlists"):
			class = "allowlist"
		case strings.Contains(message, "minVersion"):
			class = "min-version"
		case strings.Contains(message, "rule") || strings.Contains(message, "regex") || strings.Contains(message, "|id|"):
			class = "rule"
		default:
			class = "translate"
		}
	}
	chain := []string{}
	for current := err; current != nil; current = errors.Unwrap(current) {
		chain = append(chain, current.Error())
	}
	return &configError{Class: class, Stage: stage, Message: message, CauseChain: chain}
}

func canonicalizeConfig(cfg config.Config) canonicalConfig {
	ordered := append([]string{}, cfg.OrderedRules...)
	positions := make(map[string][]int)
	for index, id := range ordered {
		positions[id] = append(positions[id], index)
	}
	duplicates := []duplicateRule{}
	for id, indexes := range positions {
		if len(indexes) > 1 {
			duplicates = append(duplicates, duplicateRule{ID: id, Count: len(indexes), Positions: indexes})
		}
	}
	sort.Slice(duplicates, func(i, j int) bool { return duplicates[i].ID < duplicates[j].ID })

	ruleIDs := make([]string, 0, len(cfg.Rules))
	for id := range cfg.Rules {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]canonicalRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rule := cfg.Rules[id]
		var pathPattern, regexPattern *string
		if rule.Path != nil {
			value := rule.Path.String()
			pathPattern = &value
		}
		if rule.Regex != nil {
			value := rule.Regex.String()
			regexPattern = &value
		}
		required := make([]canonicalRequired, 0, len(rule.RequiredRules))
		for _, item := range rule.RequiredRules {
			if item == nil {
				continue
			}
			required = append(required, canonicalRequired{
				ID: item.RuleID, WithinLines: item.WithinLines, WithinColumns: item.WithinColumns,
			})
		}
		rules = append(rules, canonicalRule{
			ID: id, Description: rule.Description,
			Path: pathPattern, Regex: regexPattern,
			SecretGroup: rule.SecretGroup, Entropy: canonicalFloat64(rule.Entropy), EntropyBits: math.Float64bits(rule.Entropy),
			Keywords: cloneStrings(rule.Keywords), Tags: cloneStrings(rule.Tags),
			Required: required, Allowlists: canonicalizeAllowlists(rule.Allowlists), SkipReport: rule.SkipReport,
		})
	}

	keywords := make([]string, 0, len(cfg.Keywords))
	for keyword := range cfg.Keywords {
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	return canonicalConfig{
		Title: cfg.Title, Description: cfg.Description, Path: cfg.Path, MinVersion: cfg.MinVersion,
		Extend: canonicalExtend{
			Path: cfg.Extend.Path, URL: cfg.Extend.URL, UseDefault: cfg.Extend.UseDefault,
			DisabledRules: cloneStrings(cfg.Extend.DisabledRules),
		},
		OrderedRuleIDs: ordered, DuplicateRuleIDs: duplicates, Rules: rules,
		GlobalAllowlists: canonicalizeAllowlists(cfg.Allowlists), NormalizedKeys: keywords,
	}
}

func canonicalFloat64(value float64) any {
	switch {
	case math.IsNaN(value):
		return "NaN"
	case math.IsInf(value, 1):
		return "+Inf"
	case math.IsInf(value, -1):
		return "-Inf"
	default:
		return value
	}
}

func canonicalizeAllowlists(allowlists []*config.Allowlist) []canonicalAllowlist {
	result := make([]canonicalAllowlist, 0, len(allowlists))
	for _, allowlist := range allowlists {
		if allowlist == nil {
			continue
		}
		commits := cloneStrings(allowlist.Commits)
		stopWords := cloneStrings(allowlist.StopWords)
		// Validate rebuilds precisely these two fields from Go maps. They are
		// semantic sets; sorting removes only that proven map nondeterminism.
		sort.Strings(commits)
		sort.Strings(stopWords)
		paths := make([]string, 0, len(allowlist.Paths))
		for _, pattern := range allowlist.Paths {
			if pattern != nil {
				paths = append(paths, pattern.String())
			}
		}
		regexes := make([]string, 0, len(allowlist.Regexes))
		for _, pattern := range allowlist.Regexes {
			if pattern != nil {
				regexes = append(regexes, pattern.String())
			}
		}
		result = append(result, canonicalAllowlist{
			Description: allowlist.Description, Condition: allowlist.MatchCondition.String(),
			Commits: commits, Paths: paths, RegexTarget: allowlist.RegexTarget,
			Regexes: regexes, StopWords: stopWords,
		})
	}
	return result
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string{}, values...)
}

func canonicalDiagnostics(raw []byte) []configDiagnostic {
	result := []configDiagnostic{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			result = append(result, configDiagnostic{
				Level: "unparsed", Message: string(line), Fields: map[string]any{},
			})
			continue
		}
		level, _ := event["level"].(string)
		message, _ := event["message"].(string)
		delete(event, "level")
		delete(event, "message")
		// The upstream logger includes a wall-clock timestamp in its context.
		// Time is presentation state, not configuration behavior.
		delete(event, "time")
		result = append(result, configDiagnostic{Level: level, Message: message, Fields: event})
	}
	return result
}

func (fragment requestFragment) decode() (detect.Fragment, error) {
	decode := func(value, field string) (string, error) {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("invalid %s base64", field)
		}
		return string(decoded), nil
	}

	content, err := decode(fragment.ContentBase64, "content")
	if err != nil {
		return detect.Fragment{}, err
	}
	file, err := decode(fragment.FileBase64, "file")
	if err != nil {
		return detect.Fragment{}, err
	}
	windowsFile, err := decode(fragment.WindowsFileBase64, "windows_file")
	if err != nil {
		return detect.Fragment{}, err
	}
	symlinkFile, err := decode(fragment.SymlinkFileBase64, "symlink_file")
	if err != nil {
		return detect.Fragment{}, err
	}
	commit, err := decode(fragment.CommitBase64, "commit")
	if err != nil {
		return detect.Fragment{}, err
	}
	author, err := decode(fragment.AuthorBase64, "author")
	if err != nil {
		return detect.Fragment{}, err
	}
	email, err := decode(fragment.EmailBase64, "email")
	if err != nil {
		return detect.Fragment{}, err
	}
	date, err := decode(fragment.DateBase64, "date")
	if err != nil {
		return detect.Fragment{}, err
	}
	message, err := decode(fragment.MessageBase64, "message")
	if err != nil {
		return detect.Fragment{}, err
	}
	remoteURL, err := decode(fragment.RemoteURLBase64, "remote_url")
	if err != nil {
		return detect.Fragment{}, err
	}

	decoded := detect.Fragment{
		Raw: content, FilePath: file, WindowsFilePath: windowsFile,
		SymlinkFile: symlinkFile, CommitSHA: commit, StartLine: fragment.StartLine,
		InheritedFromFinding: fragment.Inherited,
	}
	if author != "" || email != "" || date != "" || message != "" || remoteURL != "" || fragment.RemotePlatform != "" {
		platform, err := scm.PlatformFromString(fragment.RemotePlatform)
		if err != nil {
			return detect.Fragment{}, err
		}
		commitInfo := &sources.CommitInfo{
			AuthorName: author, AuthorEmail: email, Date: date, Message: message, SHA: commit,
		}
		if remoteURL != "" || fragment.RemotePlatform != "" {
			commitInfo.Remote = &sources.RemoteInfo{Platform: platform, Url: remoteURL}
		}
		decoded.CommitInfo = commitInfo
	}
	return decoded, nil
}

func b64(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func b64Slice(values []string) []string {
	encoded := make([]string, 0, len(values))
	for _, value := range values {
		encoded = append(encoded, b64(value))
	}
	return encoded
}

func firstDifference(expected, actual []byte) error {
	expectedLines := bytes.Split(expected, []byte{'\n'})
	actualLines := bytes.Split(actual, []byte{'\n'})
	limit := min(len(expectedLines), len(actualLines))
	for index := 0; index < limit; index++ {
		if !bytes.Equal(expectedLines[index], actualLines[index]) {
			return fmt.Errorf("oracle output differs at line %d\nexpected: %s\nactual:   %s", index+1, expectedLines[index], actualLines[index])
		}
	}
	return fmt.Errorf("oracle output line count differs: expected %d, actual %d", len(expectedLines), len(actualLines))
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "oracle:", err)
		os.Exit(1)
	}
}
