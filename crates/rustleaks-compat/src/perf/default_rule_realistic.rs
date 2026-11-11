//! Synthetic realistic formats and a long-lived engine cycling diverse inputs.
//!
//! Every planted secret comes from the fixture's deterministic generator. Any
//! line without a plant contains no `generic-api-key` keyword next to an
//! assignment, or a value too short for the rule, so plants are the candidates.

use rustleaks_core::model::Fragment;
use serde_json::{Value, json};

use super::{
    Context, Expected, Fallible, Forbidden, GENERIC_RULE, GITHUB_PAT_RULE, KIB, Killer, Lcg, Plan,
    Plant, Scan, Script, TOKEN_ALPHABET, VALUE_ALPHABET, admission, all_admitted, ascii_scan,
    census, ensure, filler, generic_value, ghp_token, go_entropy, groupless_private_key,
    groupless_tokens, keyword_run_blob, keyword_run_repeat, multibyte, near_miss, prefix_storm,
    prose, single, thrash_generic,
};

const REALISTIC_SIZE: usize = 256 * KIB;
const LONG_LIVED_FAMILY_SIZE: usize = 8 * KIB;
/// At least 10,000 scans per operation, cycling all 20 input families.
const LONG_LIVED_SCANS: usize = 10_000;
/// Digest characters that spell no default keyword.
const DIGEST_ALPHABET: &[u8] = b"0123456789GHJMNPQRTUVWXZ+/";

pub(super) fn build(id: &str, mut ctx: Context<'_>) -> Fallible<Plan> {
    if id == "core-long-lived-diverse" {
        return long_lived(ctx);
    }
    let (scan, counts) = match id {
        "core-realistic-lockfile-allowlisted-path-256-kib" => {
            lockfile(&ctx, REALISTIC_SIZE, "web/package-lock.json", true)?
        }
        "core-realistic-lockfile-other-path-256-kib" => {
            lockfile(&ctx, REALISTIC_SIZE, "web/deps-snapshot.json", false)?
        }
        "core-realistic-env-256-kib" => env_file(&mut ctx, REALISTIC_SIZE)?,
        "core-realistic-k8s-yaml-256-kib" => k8s_yaml(&mut ctx, REALISTIC_SIZE)?,
        "core-realistic-jwt-log-256-kib" => jwt_log(&mut ctx, REALISTIC_SIZE)?,
        "core-realistic-multi-language-256-kib" => multi_language(&mut ctx, REALISTIC_SIZE)?,
        "core-realistic-binary-256-kib" => binary(&mut ctx, REALISTIC_SIZE)?,
        "core-realistic-utf16-256-kib" => utf16(&ctx, REALISTIC_SIZE)?,
        _ => return Err(format!("unbuilt realistic workload {id}").into()),
    };
    Ok(single(ctx, scan, counts))
}

fn path_scan(
    ctx: &Context<'_>,
    raw: Vec<u8>,
    path: &str,
    plants: Vec<Plant>,
    candidates: usize,
) -> Fallible<Scan> {
    let expected = ctx.expected(&raw, plants, candidates)?;
    Ok(Scan {
        fragment: Fragment::builder(raw).file_path(path).build(),
        expected,
    })
}

/// npm-style entries with `integrity sha512-` digests. Names and digests avoid
/// every default keyword, which the census below proves for this exact input.
/// `package-lock.json` is on the default global path allowlist, so that variant
/// returns at the path gate having charged no work unit at all.
pub(super) fn lockfile(
    ctx: &Context<'_>,
    size: usize,
    path: &str,
    allowed: bool,
) -> Fallible<(Scan, Value)> {
    let mut raw =
        b"{\n  \"name\": \"demo-workspace\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n"
            .to_vec();
    let mut rng = Lcg::new(0x6c6f_636b);
    let mut entries = 0;
    while raw.len() < size {
        let digest = String::from_utf8(rng.string(DIGEST_ALPHABET, 86))?;
        raw.extend_from_slice(
            format!(
                "    \"node_modules/pkg{entries:05}\": {{\n      \"version\": \"{}.{}.{}\",\n      \"resolved\": \"https://registry.example.test/pkg{entries:05}/-/pkg{entries:05}.tgz\",\n      \"integrity\": \"sha512-{digest}==\"\n    }},\n",
                entries % 9,
                entries % 31,
                entries % 97,
            )
            .as_bytes(),
        );
        entries += 1;
    }
    raw.truncate(size);
    let literal = census(ctx.config, &raw);
    ensure(
        literal.occurrences == 0,
        "lockfile fixture spelled a default keyword",
    )?;
    let mut scan = path_scan(ctx, raw, path, Vec::new(), 0)?;
    if allowed {
        // The fragment's path is allowlisted, so the scan exits before any
        // checkpoint: no pass, keyword, rule or candidate work is charged.
        scan.expected = Expected {
            work: Some(0),
            findings: Vec::new(),
        };
    }
    Ok((scan, json!({"packages": entries, "path": path})))
}

/// `.env` assignments. Plants carry generic keywords in the assignment name and
/// a clean value; other lines hold no keyword at all.
pub(super) fn env_file(ctx: &mut Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const NAMES: [&str; 4] = ["API_KEY", "AUTH_TOKEN", "DB_PASSWORD", "CLIENT_SECRET"];
    let rule = ctx.rule_index(GENERIC_RULE)?;
    let forbidden = Forbidden::new(ctx.config, &[VALUE_ALPHABET])?;
    let mut rng = Lcg::new(0x656e_7631);
    let mut raw = Vec::with_capacity(size);
    let mut plants = Vec::new();
    let mut line = 0;
    while raw.len() + 128 < size {
        if line % 32 == 7 {
            let start = raw.len();
            let name = NAMES[plants.len() % NAMES.len()];
            raw.extend_from_slice(format!("{name}_{line:05}=").as_bytes());
            let secret = raw.len();
            raw.extend_from_slice(&generic_value(&mut rng, &forbidden, 32)?);
            plants.push(Plant {
                rule,
                matched: (start, raw.len()),
                secret: (secret, raw.len()),
            });
            raw.push(b'\n');
        } else {
            raw.extend_from_slice(format!("CONFIG_{line:05}_FLAG=enabled\n").as_bytes());
        }
        line += 1;
    }
    raw.resize(size, b'\n');
    let candidates = plants.len();
    let scan = path_scan(ctx, raw, "deploy/.env", plants, candidates)?;
    Ok((scan, json!({"lines": line, "planted_findings": candidates})))
}

/// Kubernetes Secrets with base64-like values and no file path. The path-gated
/// `kubernetes-secret-yaml` rule therefore stops before its regex, and only the
/// `password:` and `api-token:` values reach `generic-api-key`. The `apiVersion`
/// value is too short, `kind: Secret` has no operator after it, and `username`
/// holds no generic keyword.
pub(super) fn k8s_yaml(ctx: &mut Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    let rule = ctx.rule_index(GENERIC_RULE)?;
    let forbidden = Forbidden::new(ctx.config, &[VALUE_ALPHABET])?;
    let mut rng = Lcg::new(0x6b38_7331);
    let mut raw = Vec::with_capacity(size);
    let mut plants = Vec::new();
    let mut manifests = 0;
    while raw.len() + 512 < size {
        raw.extend_from_slice(
            format!(
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: demo-config-{manifests:05}\ntype: Opaque\ndata:\n  username: dmFsdWU\n"
            )
            .as_bytes(),
        );
        for name in ["password", "api-token"] {
            raw.extend_from_slice(b"  ");
            let start = raw.len();
            raw.extend_from_slice(format!("{name}: ").as_bytes());
            let secret = raw.len();
            raw.extend_from_slice(&generic_value(&mut rng, &forbidden, 44)?);
            plants.push(Plant {
                rule,
                matched: (start, raw.len()),
                secret: (secret, raw.len()),
            });
            raw.push(b'\n');
        }
        raw.extend_from_slice(b"---\n");
        manifests += 1;
    }
    raw.resize(size, b'\n');
    let candidates = plants.len();
    let scan = ascii_scan(ctx, raw, plants, candidates)?;
    Ok((
        scan,
        json!({"manifests": manifests, "planted_findings": candidates}),
    ))
}

/// An unsigned synthetic token in JWT shape, for the `jwt` rule. The header is
/// the base64url form of `{"alg":"HS256"}`; payload and signature are random.
fn synthetic_jwt(rng: &mut Lcg) -> Vec<u8> {
    let mut alphabet = TOKEN_ALPHABET.to_vec();
    alphabet.extend_from_slice(b"-_");
    let mut token = b"eyJhbGciOiJIUzI1NiJ9.eyJ".to_vec();
    token.extend_from_slice(&rng.string(&alphabet, 45));
    token.push(b'.');
    token.extend_from_slice(&rng.string(&alphabet, 43));
    token
}

/// Access-log lines with no generic keyword and occasional synthetic JWTs. The
/// `jwt` rule's group is the token and its terminator is the following space,
/// which stays in the match because only newlines are trimmed.
pub(super) fn jwt_log(ctx: &mut Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    let rule = ctx.rule_index("jwt")?;
    let mut rng = Lcg::new(0x6a77_746c);
    let mut raw = Vec::with_capacity(size);
    let mut plants = Vec::new();
    let mut line = 0_usize;
    while raw.len() + 512 < size {
        let stamp = format!(
            "2026-03-14T12:{:02}:{:02}Z INFO gateway ",
            line / 60 % 60,
            line % 60
        );
        raw.extend_from_slice(stamp.as_bytes());
        if line % 8 == 3 {
            raw.extend_from_slice(b"bearer ");
            let start = raw.len();
            let token = synthetic_jwt(&mut rng);
            ensure(
                go_entropy(&token)? > 3.0,
                "synthetic JWT must exceed the jwt entropy threshold",
            )?;
            raw.extend_from_slice(&token);
            let secret_end = raw.len();
            raw.push(b' ');
            plants.push(Plant {
                rule,
                matched: (start, raw.len()),
                secret: (start, secret_end),
            });
            raw.extend_from_slice(b"accepted\n");
        } else {
            raw.extend_from_slice(format!("request {line} completed status 200\n").as_bytes());
        }
        line += 1;
    }
    raw.resize(size, b'\n');
    let candidates = plants.len();
    let scan = ascii_scan(ctx, raw, plants, candidates)?;
    Ok((scan, json!({"lines": line, "planted_findings": candidates})))
}

/// Source lines from five languages. Only the plant lines use a generic
/// keyword; each `(prefix, keyword-and-assign, suffix)` splits around the
/// value, and the closing quote is the regex terminator kept in the match.
pub(super) fn multi_language(ctx: &mut Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const NEUTRAL: [&str; 8] = [
        "def parse_line(value):\n",
        "    return value.strip()\n",
        "func add(a int, b int) int { return a + b }\n",
        "fn add(a: i32, b: i32) -> i32 { a + b }\n",
        "public int add(int a, int b) { return a + b; }\n",
        "function add(a, b) { return a + b; }\n",
        "const LIMIT = 42;\n",
        "let total = 0;\n",
    ];
    // (text before the match, match text before the value, text after the value)
    const PLANTS: [(&str, &str, &str); 5] = [
        ("", "API_KEY = \"", "\"\n"),
        ("const ", "authToken = \"", "\";\n"),
        ("\t", "secretKey := \"", "\"\n"),
        ("let ", "password = \"", "\";\n"),
        ("String ", "token = \"", "\";\n"),
    ];
    let rule = ctx.rule_index(GENERIC_RULE)?;
    let forbidden = Forbidden::new(ctx.config, &[VALUE_ALPHABET])?;
    let mut rng = Lcg::new(0x6c61_6e67);
    let mut raw = Vec::with_capacity(size);
    let mut plants = Vec::new();
    let mut line = 0;
    while raw.len() + 256 < size {
        if line % 64 == 13 {
            let (lead, assign, tail) = PLANTS[plants.len() % PLANTS.len()];
            raw.extend_from_slice(lead.as_bytes());
            let start = raw.len();
            raw.extend_from_slice(assign.as_bytes());
            let secret = raw.len();
            raw.extend_from_slice(&generic_value(&mut rng, &forbidden, 32)?);
            let secret_end = raw.len();
            raw.extend_from_slice(tail.as_bytes());
            plants.push(Plant {
                rule,
                // The closing quote is consumed as the regex terminator.
                matched: (start, secret_end + 1),
                secret: (secret, secret_end),
            });
        } else {
            raw.extend_from_slice(NEUTRAL[line % NEUTRAL.len()].as_bytes());
        }
        line += 1;
    }
    raw.resize(size, b'\n');
    let candidates = plants.len();
    let scan = ascii_scan(ctx, raw, plants, candidates)?;
    Ok((scan, json!({"lines": line, "planted_findings": candidates})))
}

/// Invalid UTF-8 made of NUL and high bytes, holding three synthetic tokens.
/// No byte is LF, so upstream's one virtual newline places each finding on line
/// zero and its line is the whole fragment.
pub(super) fn binary(ctx: &mut Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    let rule = ctx.rule_index(GITHUB_PAT_RULE)?;
    let mut rng = Lcg::new(0x6269_6e31);
    let mut raw = (0..size)
        .map(|_| {
            // Zero stays NUL; the rest map onto 0x80..=0xFF.
            let value = rng.below(129);
            if value == 0 {
                0
            } else {
                u8::try_from(0x7F + value).expect("value is at most 0xFF")
            }
        })
        .collect::<Vec<_>>();
    let mut plants = Vec::new();
    for quarter in 1..=3 {
        let start = size * quarter / 4;
        let token = ghp_token(&mut rng);
        raw[start - 1] = 0;
        raw[start + token.len()] = 0;
        raw[start..start + token.len()].copy_from_slice(&token);
        plants.push(Plant {
            rule,
            matched: (start, start + token.len()),
            secret: (start, start + token.len()),
        });
    }
    let candidates = plants.len();
    let scan = ascii_scan(ctx, raw, plants, candidates)?;
    Ok((
        scan,
        json!({"planted_findings": candidates, "valid_utf8": false}),
    ))
}

/// UTF-16LE source text with a byte-order mark. Core sees raw bytes, in which
/// every letter is separated by NUL, so no keyword occurs literally: the text
/// admits only the keywordless path rule and yields no finding by design.
pub(super) fn utf16(ctx: &Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const TEXT: &str = "const token = \"synthetic-value-not-matched\";\nlet total = 0;\n";
    let mut raw = vec![0xFF, 0xFE];
    while raw.len() < size {
        for unit in TEXT.encode_utf16() {
            raw.extend_from_slice(&unit.to_le_bytes());
        }
    }
    raw.truncate(size);
    let occurrences = census(ctx.config, &raw).occurrences;
    ensure(occurrences == 0, "UTF-16 bytes spelled a default keyword")?;
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((scan, json!({"encoding": "utf-16le"})))
}

/// Twenty input families at one size. Together they exercise keyword, regex,
/// filter and finding paths so that lazy-DFA state and other caches stay in
/// flux across scans, on one engine kept for the whole process. Retained
/// memory is observed through the representative collector's fresh-process
/// peak RSS for this child process.
fn long_lived(mut ctx: Context<'_>) -> Fallible<Plan> {
    let size = LONG_LIVED_FAMILY_SIZE;
    let families = vec![
        admission(&mut ctx, 16, size)?.0,
        prose(&ctx, size)?.0,
        near_miss(&ctx, Killer::Entropy, size / 64)?.0,
        near_miss(&ctx, Killer::Stopword, size / 64)?.0,
        near_miss(&ctx, Killer::RuleAllowlist, size / 64)?.0,
        near_miss(&ctx, Killer::GlobalAllowlist, size / 64)?.0,
        all_admitted(&ctx, size)?.0,
        keyword_run_repeat(&ctx, size)?.0,
        keyword_run_blob(&ctx, size)?.0,
        prefix_storm(&ctx, size)?.0,
        thrash_generic(&ctx, size)?.0,
        multibyte(&mut ctx, Script::Cjk, size, 4)?.0,
        multibyte(&mut ctx, Script::Cyrillic, size, 4)?.0,
        groupless_private_key(&mut ctx, size)?.0,
        groupless_tokens(&mut ctx, 128)?.0,
        env_file(&mut ctx, size)?.0,
        k8s_yaml(&mut ctx, size)?.0,
        jwt_log(&mut ctx, size)?.0,
        multi_language(&mut ctx, size)?.0,
        binary(&mut ctx, size)?.0,
    ];
    ensure(families.len() == 20, "long-lived fixture needs 20 families")?;
    ensure(
        filler(1).len() == 1,
        "filler helper must honor its requested size",
    )?;
    Ok(Plan {
        rules: ctx.rules,
        scans: families,
        scans_per_operation: LONG_LIVED_SCANS,
        counts: json!({
            "families": 20,
            "family_bytes": size,
            "scans_per_operation": LONG_LIVED_SCANS,
            "retained_engines": 1,
            "retained_behavior": "fresh-process peak RSS from the representative collector",
        }),
    })
}
