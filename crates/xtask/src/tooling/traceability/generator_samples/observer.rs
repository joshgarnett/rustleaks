//! Temporary Go observer and narrowly checked source instrumentation.

use std::{fs, path::Path};

pub(super) const VALIDATE_GO: &str = r#"// Generated only inside a temporary git archive by Rust traceability tooling.
package utils

import (
    "encoding/base64"
    "encoding/json"
    "os"
    "runtime"
    "sort"
    "strings"

    "github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
    "github.com/zricethezav/gitleaks/v8/config"
    "github.com/zricethezav/gitleaks/v8/detect"
    "github.com/zricethezav/gitleaks/v8/logging"
    "github.com/zricethezav/gitleaks/v8/report"
)

type sampleOrigin struct { TemplateKey string; SourceFile string; SourceLine int }
type loggedFinding struct {
    MatchBase64 string `json:"match_base64"`
    SecretBase64 string `json:"secret_base64"`
}
type loggedDependencies struct {
    Entropy float64 `json:"entropy"`
    KeywordBase64 []string `json:"keyword_base64"`
    RuleAllowlistCount int `json:"rule_allowlist_count"`
    HasPath bool `json:"has_path"`
    SecretGroup int `json:"secret_group"`
    GlobalAllowlist bool `json:"global_allowlist"`
}
type loggedRecord struct {
    Constructor string `json:"constructor"`
    RuleID string `json:"rule_id"`
    Helper string `json:"helper"`
    Polarity string `json:"polarity"`
    Ordinal int `json:"ordinal"`
    Contract string `json:"contract"`
    HelperSource string `json:"helper_source_file"`
    HelperLine int `json:"helper_line"`
    OriginKind string `json:"origin_kind"`
    OriginSource string `json:"origin_source_file"`
    OriginLine int `json:"origin_line"`
    TemplateKey *string `json:"template_key"`
    InputBase64 string `json:"input_base64"`
    PathPresent bool `json:"path_present"`
    PathBase64 *string `json:"path_base64"`
    Findings []loggedFinding `json:"findings"`
    Dependencies loggedDependencies `json:"dependencies"`
}

var sampleOrigins = map[string][]sampleOrigin{}
var observationFile *os.File

func relativeSource(path string) string {
    marker := "/cmd/generate/"
    if index := strings.Index(path, marker); index >= 0 { return path[index+1:] }
    return path
}
func registerSampleOrigin(value string, templateKey string, sourceFile string, sourceLine int) {
    sampleOrigins[value] = append(sampleOrigins[value], sampleOrigin{templateKey, relativeSource(sourceFile), sourceLine})
}
func consumeSampleOrigin(value string) (sampleOrigin, bool) {
    origins := sampleOrigins[value]
    if len(origins) == 0 { return sampleOrigin{}, false }
    origin := origins[0]
    if len(origins) == 1 { delete(sampleOrigins, value) } else { sampleOrigins[value] = origins[1:] }
    return origin, true
}
func caller() (string, string, int) {
    pc, file, line, ok := runtime.Caller(3)
    if !ok { return "unknown", "unknown", 0 }
    name := runtime.FuncForPC(pc).Name()
    if index := strings.LastIndex(name, "."); index >= 0 { name = name[index+1:] }
    return name, relativeSource(file), line
}
func encode(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
func dependencies(rule *config.Rule) loggedDependencies {
    keywords := make([]string, len(rule.Keywords))
    for index, keyword := range rule.Keywords { keywords[index] = encode(keyword) }
    return loggedDependencies{rule.Entropy, keywords, len(rule.Allowlists), rule.Path != nil, rule.SecretGroup, true}
}
func writeObservation(record loggedRecord) {
    if observationFile == nil {
        path := os.Getenv("RUSTLEAKS_GENERATOR_SAMPLE_LOG")
        if path == "" { panic("RUSTLEAKS_GENERATOR_SAMPLE_LOG is unset") }
        file, err := os.Create(path); if err != nil { panic(err) }; observationFile = file
    }
    if err := json.NewEncoder(observationFile).Encode(record); err != nil { panic(err) }
}
func logCase(rule *config.Rule, helper string, polarity string, ordinal int, contract string, input string, path *string, findings []report.Finding) {
    constructor, helperSource, helperLine := caller()
    origin, generated := consumeSampleOrigin(input)
    originKind, originSource, originLine := "direct", helperSource, helperLine
    var templateKey *string
    if generated { originKind, originSource, originLine = "generated_template", origin.SourceFile, origin.SourceLine; key := origin.TemplateKey; templateKey = &key }
    loggedFindings := make([]loggedFinding, 0, len(findings))
    for _, finding := range findings { loggedFindings = append(loggedFindings, loggedFinding{encode(finding.Match), encode(finding.Secret)}) }
    var pathBase64 *string
    if path != nil { encoded := encode(*path); pathBase64 = &encoded }
    writeObservation(loggedRecord{constructor, rule.RuleID, helper, polarity, ordinal, contract,
        helperSource, helperLine, originKind, originSource, originLine, templateKey, encode(input),
        path != nil, pathBase64, loggedFindings, dependencies(rule)})
}
func Validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {
    r := &rule; d := createSingleRuleDetector(r)
    for ordinal, tp := range truePositives {
        findings := d.DetectString(tp); logCase(r, "validate", "ordinary_true", ordinal, "at_least_one", tp, nil, findings)
        if len(findings) < 1 { logging.Fatal().Str("rule", r.RuleID).Str("value", tp).Str("regex", r.Regex.String()).Msg("Failed to Validate. True positive was not detected by regex.") }
    }
    for ordinal, fp := range falsePositives {
        findings := d.DetectString(fp); logCase(r, "validate", "ordinary_false", ordinal, "zero", fp, nil, findings)
        if len(findings) != 0 { logging.Fatal().Str("rule", r.RuleID).Str("value", fp).Str("regex", r.Regex.String()).Msg("Failed to Validate. False positive was detected by regex.") }
    }
    return r
}
func sortedPaths(samples map[string]string) []string {
    paths := make([]string, 0, len(samples)); for path := range samples { paths = append(paths, path) }; sort.Strings(paths); return paths
}
func ValidateWithPaths(rule config.Rule, truePositives map[string]string, falsePositives map[string]string) *config.Rule {
    r := &rule; d := createSingleRuleDetector(r)
    for ordinal, path := range sortedPaths(truePositives) {
        tp := truePositives[path]; fragment := detect.Fragment{Raw: tp, FilePath: path}; findings := d.Detect(fragment)
        logCase(r, "validate_with_paths", "path_true", ordinal, "exactly_one", tp, &path, findings)
        if len(findings) != 1 { logging.Fatal().Str("rule", r.RuleID).Str("value", tp).Str("regex", r.Regex.String()).Str("path", r.Path.String()).Msg("Failed to Validate. True positive was not detected by regex and/or path.") }
    }
    for ordinal, path := range sortedPaths(falsePositives) {
        fp := falsePositives[path]; fragment := detect.Fragment{Raw: fp, FilePath: path}; findings := d.Detect(fragment)
        logCase(r, "validate_with_paths", "path_false", ordinal, "zero", fp, &path, findings)
        if len(findings) != 0 { logging.Fatal().Str("rule", r.RuleID).Str("value", fp).Str("regex", r.Regex.String()).Str("path", r.Path.String()).Msg("Failed to Validate. False positive was detected by regex and/or path.") }
    }
    return r
}
func createSingleRuleDetector(r *config.Rule) *detect.Detector {
    uniqueKeywords := make(map[string]struct{}); var keywords []string
    for _, keyword := range r.Keywords { normalized := strings.ToLower(keyword); if _, ok := uniqueKeywords[normalized]; ok { continue }; keywords = append(keywords, normalized); uniqueKeywords[normalized] = struct{}{} }
    r.Keywords = keywords; rules := map[string]config.Rule{r.RuleID: *r}; cfg := base.CreateGlobalConfig(); cfg.Rules = rules; cfg.Keywords = uniqueKeywords
    for _, allowlist := range cfg.Allowlists { if err := allowlist.Validate(); err != nil { logging.Fatal().Err(err).Msg("invalid global allowlist") } }
    return detect.NewDetector(cfg)
}
"#;

pub(super) fn instrument_helpers(path: &Path) -> Result<(), String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let source = replace_once(
        source,
        "\t\"fmt\"\n\t\"strings\"\n",
        "\t\"fmt\"\n\t\"runtime\"\n\t\"sort\"\n\t\"strings\"\n",
        "generate.go imports",
    )?;
    let start = source
        .find("func GenerateSampleSecret(identifier string, secret string) string {")
        .ok_or("failed to instrument GenerateSampleSecret")?;
    let end = function_end(&source, start)?;
    let replacement = r#"func GenerateSampleSecret(identifier string, secret string) string {
	sample := fmt.Sprintf("%s_api_token = \"%s\"", identifier, secret)
	_, file, line, _ := runtime.Caller(1)
	registerSampleOrigin(sample, "single - api token assignment", file, line)
	return sample
}"#;
    let mut source = format!("{}{}{}", &source[..start], replacement, &source[end..]);
    let old = "\tcases := make([]string, 0, len(samples))\n\tfor _, v := range samples {\n\t\tcases = append(cases, replacer.Replace(v))\n\t}\n\treturn cases";
    let new = "\tkeys := make([]string, 0, len(samples))\n\tfor key := range samples {\n\t\tkeys = append(keys, key)\n\t}\n\tsort.Strings(keys)\n\t_, file, line, _ := runtime.Caller(1)\n\tcases := make([]string, 0, len(samples))\n\tfor _, key := range keys {\n\t\tsample := replacer.Replace(samples[key])\n\t\tregisterSampleOrigin(sample, key, file, line)\n\t\tcases = append(cases, sample)\n\t}\n\treturn cases";
    source = replace_once(source, old, new, "GenerateSampleSecrets")?;
    fs::write(path, source).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

pub(super) fn instrument_secret(path: &Path) -> Result<(), String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let start = source
        .find("func NewSecret(regex string) string {")
        .ok_or("failed to instrument deterministic secret generation")?;
    let end = function_end(&source, start)?;
    let replacement = r#"func deterministicSeed(regex string) int64 {
	hash := uint64(14695981039346656037)
	for index := 0; index < len(regex); index++ { hash ^= uint64(regex[index]); hash *= 1099511628211 }
	return int64(hash)
}
func concentrationScore(value string) int {
	counts := [256]int{}; for index := 0; index < len(value); index++ { counts[value[index]]++ }
	score := 0; for _, count := range counts { score += count * count }; return score
}
func NewSecret(regex string) string {
	g, err := reggen.NewGenerator(regex); if err != nil { panic(err) }
	baseSeed := deterministicSeed(regex); best := ""; bestScore := 0
	for offset := int64(0); offset < 128; offset++ {
		g.SetSeed(baseSeed + offset); candidate := g.Generate(1); score := concentrationScore(candidate)
		if offset == 0 || score < bestScore || (score == bestScore && candidate < best) { best = candidate; bestScore = score }
	}
	return best
}"#;
    fs::write(
        path,
        format!("{}{}{}", &source[..start], replacement, &source[end..]),
    )
    .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn function_end(source: &str, start: usize) -> Result<usize, String> {
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .ok_or("function lacks body")?;
    let mut depth = 0;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(open + offset + 1);
                }
            }
            _ => {}
        }
    }
    Err("unterminated function body".into())
}

fn replace_once(mut source: String, old: &str, new: &str, label: &str) -> Result<String, String> {
    let start = source
        .find(old)
        .ok_or_else(|| format!("failed to instrument {label}"))?;
    if source[start + old.len()..].contains(old) {
        return Err(format!("ambiguous instrumentation target: {label}"));
    }
    source.replace_range(start..start + old.len(), new);
    Ok(source)
}
