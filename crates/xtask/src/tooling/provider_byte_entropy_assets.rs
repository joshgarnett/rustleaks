//! Fixed source and native contracts for six byte-entropy provider rules.

const REVIEWED: &str = r#"{
  "selection": {
    "source_revision": "8f376ff9c31ed5309ac448fe601c5dd21b376155",
    "source_sha256": "7c305ade42d5dbad4650b97cca0299f9c16d152ec555ae47bd6f321f049f82e5",
    "kingfisher_revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
    "generated_filter_ast_sha256": "0c8e0b2668188945b99d20414d387d51add97b7492a6e7b19e2dfcf600427dbd",
    "global_secret_regexes": [
      "(?i)^true|false|null$",
      "^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$",
      "^\\$(?:\\d+|{\\d+})$",
      "^\\$(?:[A-Z_]+|[a-z_]+)$",
      "^\\${(?:[A-Z_]+|[a-z_]+)}$",
      "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$",
      "^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$",
      "^%(?:[A-Z_]+|[a-z_]+)%$",
      "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$",
      "^\\{\\d{0,2}}$",
      "^@(?:[A-Z_]+|[a-z_]+)@$",
      "^/Users/(?i)[a-z0-9]+/[\\w .-/]+$",
      "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$"
    ],
    "global_secret_stopwords": [
      "abcdefghijklmnopqrstuvwxyz",
      "014df517-39d1-4453-b7b3-9930c563627c"
    ],
    "global_scope": "Preserve reviewed global secret exclusions through the unchanged native base. Retain native source-path policy, including office/PDF/binary and .git exclusions; source also excludes Bun lockfiles. No source-policy equivalence claim.",
    "predicate_contract": {
      "algorithm": "byte-shannon-f64-v1",
      "reject": "lt",
      "threshold": 3.5
    },
    "arithmetic_scope": "Ascending 256-byte histogram, per-count binary64 division by byte length, and accumulation in byte order. ASCII rule languages; no arbitrary-platform libm-bit or invalid-UTF-8 source-string equivalence claim.",
    "native_secret_regexes": [
      "(?:(?i)^true|false|null$)",
      "(?:^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$)",
      "(?:^\\$(?:\\d+|{\\d+})$)",
      "(?:^\\$(?:[A-Z_]+|[a-z_]+)$)",
      "(?:^\\${(?:[A-Z_]+|[a-z_]+)}$)",
      "(?:^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$)",
      "(?:^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$)",
      "(?:^%(?:[A-Z_]+|[a-z_]+)%$)",
      "(?:^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$)",
      "(?:^\\{\\d{0,2}}$)",
      "(?:^@(?:[A-Z_]+|[a-z_]+)@$)",
      "(?:^/Users/(?i)[a-z0-9]+/[\\w .-/]+$)",
      "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)"
    ],
    "predicate_scope": "Wrap each of the 13 source regexes in its own noncapturing group before native allowlist joining. Preserve all internal flags and alternatives; do not translate predicate whitespace. Retain both case-insensitive secret stopwords.",
    "inherited_global_reachability": "For these six fixed lowercase prefixes, source regex 1 is the only reachable global regex. Regex 2 requires an entire repeated-letter, star or dot value; regexes 3 through 13 require leading $, {, %, @ or /. None of those forms intersects a captured provider token. Consequently inherited legacy cross-alternative flags cannot change this six-rule domain. Native local copies retain independent source scopes explicitly."
  },
  "rules": [
    {
      "origin": {
        "id": "rustleaks.dockerhub-personal-access-token",
        "upstream_id": "dockerhub-personal-access-token",
        "source_line": 3003,
        "source_pattern": "\\b(dckr_pat_[A-Za-z0-9_-]{27})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) < 3.5\n",
        "source_filter_ast_sha256": "0c8e0b2668188945b99d20414d387d51add97b7492a6e7b19e2dfcf600427dbd",
        "source_keywords": [
          "dckr_pat_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "\\b(dckr_pat_[A-Za-z0-9_-]{27})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "transformations": [
          "Namespace identifier, preserve case-sensitive prefix, body bounds and alphabet, ASCII word boundaries, capture 1 and delimiter ownership.",
          "Spell byte whitespace as ASCII 09 through 0d and 20. Apify uses only terminal word boundary and consumes no delimiter.",
          "Preserve the source strict-less-than rejection with explicit native byte-shannon-f64-v1 algorithm and threshold 3.5; retain the original thirty rules and their entropy contracts unchanged.",
          "Preserve the complete generated global secret regex/stopword rejection through native base composition. No component, tokenizer, path-local or precedence predicate is omitted; source path policy remains a declared native difference.",
          "Retain explicit rule-local copies of all 13 source secret regexes with independent noncapturing scope and both source stopwords. Preserve predicate whitespace literally; inherited legacy flag leakage is unreachable for these six captured prefix languages."
        ]
      },
      "native": {
        "id": "rustleaks.dockerhub-personal-access-token",
        "description": "Docker Hub personal access token",
        "regex": "\\b(dckr_pat_[A-Za-z0-9_-]{27})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secretGroup": 1,
        "keywords": [
          "dckr_pat_"
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "allowlists": [
          {
            "description": "Independently scoped source global secret exclusions",
            "regexTarget": "secret",
            "regexes": [
              "(?:(?i)^true|false|null$)",
              "(?:^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$)",
              "(?:^\\$(?:\\d+|{\\d+})$)",
              "(?:^\\$(?:[A-Z_]+|[a-z_]+)$)",
              "(?:^\\${(?:[A-Z_]+|[a-z_]+)}$)",
              "(?:^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$)",
              "(?:^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$)",
              "(?:^%(?:[A-Z_]+|[a-z_]+)%$)",
              "(?:^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$)",
              "(?:^\\{\\d{0,2}}$)",
              "(?:^@(?:[A-Z_]+|[a-z_]+)@$)",
              "(?:^/Users/(?i)[a-z0-9]+/[\\w .-/]+$)",
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)"
            ],
            "stopwords": [
              "abcdefghijklmnopqrstuvwxyz",
              "014df517-39d1-4453-b7b3-9930c563627c"
            ]
          }
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.dockerhub-organization-access-token",
        "upstream_id": "dockerhub-organization-access-token",
        "source_line": 2990,
        "source_pattern": "\\b(dckr_oat_[A-Za-z0-9_-]{32})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) < 3.5\n",
        "source_filter_ast_sha256": "0c8e0b2668188945b99d20414d387d51add97b7492a6e7b19e2dfcf600427dbd",
        "source_keywords": [
          "dckr_oat_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "\\b(dckr_oat_[A-Za-z0-9_-]{32})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "transformations": [
          "Namespace identifier, preserve case-sensitive prefix, body bounds and alphabet, ASCII word boundaries, capture 1 and delimiter ownership.",
          "Spell byte whitespace as ASCII 09 through 0d and 20. Apify uses only terminal word boundary and consumes no delimiter.",
          "Preserve the source strict-less-than rejection with explicit native byte-shannon-f64-v1 algorithm and threshold 3.5; retain the original thirty rules and their entropy contracts unchanged.",
          "Preserve the complete generated global secret regex/stopword rejection through native base composition. No component, tokenizer, path-local or precedence predicate is omitted; source path policy remains a declared native difference.",
          "Retain explicit rule-local copies of all 13 source secret regexes with independent noncapturing scope and both source stopwords. Preserve predicate whitespace literally; inherited legacy flag leakage is unreachable for these six captured prefix languages."
        ]
      },
      "native": {
        "id": "rustleaks.dockerhub-organization-access-token",
        "description": "Docker Hub organization access token",
        "regex": "\\b(dckr_oat_[A-Za-z0-9_-]{32})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secretGroup": 1,
        "keywords": [
          "dckr_oat_"
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "allowlists": [
          {
            "description": "Independently scoped source global secret exclusions",
            "regexTarget": "secret",
            "regexes": [
              "(?:(?i)^true|false|null$)",
              "(?:^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$)",
              "(?:^\\$(?:\\d+|{\\d+})$)",
              "(?:^\\$(?:[A-Z_]+|[a-z_]+)$)",
              "(?:^\\${(?:[A-Z_]+|[a-z_]+)}$)",
              "(?:^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$)",
              "(?:^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$)",
              "(?:^%(?:[A-Z_]+|[a-z_]+)%$)",
              "(?:^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$)",
              "(?:^\\{\\d{0,2}}$)",
              "(?:^@(?:[A-Z_]+|[a-z_]+)@$)",
              "(?:^/Users/(?i)[a-z0-9]+/[\\w .-/]+$)",
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)"
            ],
            "stopwords": [
              "abcdefghijklmnopqrstuvwxyz",
              "014df517-39d1-4453-b7b3-9930c563627c"
            ]
          }
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.neon-api-key",
        "upstream_id": "neon-api-key",
        "source_line": 8744,
        "source_pattern": "\\b(napi_[A-Za-z0-9]{64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) < 3.5\n",
        "source_filter_ast_sha256": "0c8e0b2668188945b99d20414d387d51add97b7492a6e7b19e2dfcf600427dbd",
        "source_keywords": [
          "napi_"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "native_pattern": "\\b(napi_[A-Za-z0-9]{64})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "transformations": [
          "Namespace identifier, preserve case-sensitive prefix, body bounds and alphabet, ASCII word boundaries, capture 1 and delimiter ownership.",
          "Spell byte whitespace as ASCII 09 through 0d and 20. Apify uses only terminal word boundary and consumes no delimiter.",
          "Preserve the source strict-less-than rejection with explicit native byte-shannon-f64-v1 algorithm and threshold 3.5; retain the original thirty rules and their entropy contracts unchanged.",
          "Preserve the complete generated global secret regex/stopword rejection through native base composition. No component, tokenizer, path-local or precedence predicate is omitted; source path policy remains a declared native difference.",
          "Retain explicit rule-local copies of all 13 source secret regexes with independent noncapturing scope and both source stopwords. Preserve predicate whitespace literally; inherited legacy flag leakage is unreachable for these six captured prefix languages."
        ]
      },
      "native": {
        "id": "rustleaks.neon-api-key",
        "description": "Neon API key",
        "regex": "\\b(napi_[A-Za-z0-9]{64})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secretGroup": 1,
        "keywords": [
          "napi_"
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "allowlists": [
          {
            "description": "Independently scoped source global secret exclusions",
            "regexTarget": "secret",
            "regexes": [
              "(?:(?i)^true|false|null$)",
              "(?:^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$)",
              "(?:^\\$(?:\\d+|{\\d+})$)",
              "(?:^\\$(?:[A-Z_]+|[a-z_]+)$)",
              "(?:^\\${(?:[A-Z_]+|[a-z_]+)}$)",
              "(?:^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$)",
              "(?:^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$)",
              "(?:^%(?:[A-Z_]+|[a-z_]+)%$)",
              "(?:^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$)",
              "(?:^\\{\\d{0,2}}$)",
              "(?:^@(?:[A-Z_]+|[a-z_]+)@$)",
              "(?:^/Users/(?i)[a-z0-9]+/[\\w .-/]+$)",
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)"
            ],
            "stopwords": [
              "abcdefghijklmnopqrstuvwxyz",
              "014df517-39d1-4453-b7b3-9930c563627c"
            ]
          }
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.render-api-key",
        "upstream_id": "render-api-key",
        "source_line": 10217,
        "source_pattern": "\\b(rnd_[A-Za-z0-9]{28})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) < 3.5\n",
        "source_filter_ast_sha256": "0c8e0b2668188945b99d20414d387d51add97b7492a6e7b19e2dfcf600427dbd",
        "source_keywords": [
          "rnd_"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "native_pattern": "\\b(rnd_[A-Za-z0-9]{28})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "transformations": [
          "Namespace identifier, preserve case-sensitive prefix, body bounds and alphabet, ASCII word boundaries, capture 1 and delimiter ownership.",
          "Spell byte whitespace as ASCII 09 through 0d and 20. Apify uses only terminal word boundary and consumes no delimiter.",
          "Preserve the source strict-less-than rejection with explicit native byte-shannon-f64-v1 algorithm and threshold 3.5; retain the original thirty rules and their entropy contracts unchanged.",
          "Preserve the complete generated global secret regex/stopword rejection through native base composition. No component, tokenizer, path-local or precedence predicate is omitted; source path policy remains a declared native difference.",
          "Retain explicit rule-local copies of all 13 source secret regexes with independent noncapturing scope and both source stopwords. Preserve predicate whitespace literally; inherited legacy flag leakage is unreachable for these six captured prefix languages."
        ]
      },
      "native": {
        "id": "rustleaks.render-api-key",
        "description": "Render API key",
        "regex": "\\b(rnd_[A-Za-z0-9]{28})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secretGroup": 1,
        "keywords": [
          "rnd_"
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "allowlists": [
          {
            "description": "Independently scoped source global secret exclusions",
            "regexTarget": "secret",
            "regexes": [
              "(?:(?i)^true|false|null$)",
              "(?:^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$)",
              "(?:^\\$(?:\\d+|{\\d+})$)",
              "(?:^\\$(?:[A-Z_]+|[a-z_]+)$)",
              "(?:^\\${(?:[A-Z_]+|[a-z_]+)}$)",
              "(?:^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$)",
              "(?:^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$)",
              "(?:^%(?:[A-Z_]+|[a-z_]+)%$)",
              "(?:^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$)",
              "(?:^\\{\\d{0,2}}$)",
              "(?:^@(?:[A-Z_]+|[a-z_]+)@$)",
              "(?:^/Users/(?i)[a-z0-9]+/[\\w .-/]+$)",
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)"
            ],
            "stopwords": [
              "abcdefghijklmnopqrstuvwxyz",
              "014df517-39d1-4453-b7b3-9930c563627c"
            ]
          }
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.deno-account-token",
        "upstream_id": "deno-account-token",
        "source_line": 2690,
        "source_pattern": "\\b(ddp_[A-Za-z0-9]{36})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) < 3.5\n",
        "source_filter_ast_sha256": "0c8e0b2668188945b99d20414d387d51add97b7492a6e7b19e2dfcf600427dbd",
        "source_keywords": [
          "ddp_"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "native_pattern": "\\b(ddp_[A-Za-z0-9]{36})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "transformations": [
          "Namespace identifier, preserve case-sensitive prefix, body bounds and alphabet, ASCII word boundaries, capture 1 and delimiter ownership.",
          "Spell byte whitespace as ASCII 09 through 0d and 20. Apify uses only terminal word boundary and consumes no delimiter.",
          "Preserve the source strict-less-than rejection with explicit native byte-shannon-f64-v1 algorithm and threshold 3.5; retain the original thirty rules and their entropy contracts unchanged.",
          "Preserve the complete generated global secret regex/stopword rejection through native base composition. No component, tokenizer, path-local or precedence predicate is omitted; source path policy remains a declared native difference.",
          "Retain explicit rule-local copies of all 13 source secret regexes with independent noncapturing scope and both source stopwords. Preserve predicate whitespace literally; inherited legacy flag leakage is unreachable for these six captured prefix languages."
        ]
      },
      "native": {
        "id": "rustleaks.deno-account-token",
        "description": "Deno account token",
        "regex": "\\b(ddp_[A-Za-z0-9]{36})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secretGroup": 1,
        "keywords": [
          "ddp_"
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "allowlists": [
          {
            "description": "Independently scoped source global secret exclusions",
            "regexTarget": "secret",
            "regexes": [
              "(?:(?i)^true|false|null$)",
              "(?:^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$)",
              "(?:^\\$(?:\\d+|{\\d+})$)",
              "(?:^\\$(?:[A-Z_]+|[a-z_]+)$)",
              "(?:^\\${(?:[A-Z_]+|[a-z_]+)}$)",
              "(?:^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$)",
              "(?:^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$)",
              "(?:^%(?:[A-Z_]+|[a-z_]+)%$)",
              "(?:^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$)",
              "(?:^\\{\\d{0,2}}$)",
              "(?:^@(?:[A-Z_]+|[a-z_]+)@$)",
              "(?:^/Users/(?i)[a-z0-9]+/[\\w .-/]+$)",
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)"
            ],
            "stopwords": [
              "abcdefghijklmnopqrstuvwxyz",
              "014df517-39d1-4453-b7b3-9930c563627c"
            ]
          }
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.apify-api-token",
        "upstream_id": "apify-api-token",
        "source_line": 631,
        "source_pattern": "\\b(apify_api_[A-Za-z0-9]{34,38})\\b",
        "source_filter": "entropy(finding[\"secret\"]) < 3.5\n",
        "source_filter_ast_sha256": "0c8e0b2668188945b99d20414d387d51add97b7492a6e7b19e2dfcf600427dbd",
        "source_keywords": [
          "apify_api_"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "present; not imported",
        "native_pattern": "\\b(apify_api_[A-Za-z0-9]{34,38})\\b",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "transformations": [
          "Namespace identifier, preserve case-sensitive prefix, body bounds and alphabet, ASCII word boundaries, capture 1 and delimiter ownership.",
          "Spell byte whitespace as ASCII 09 through 0d and 20. Apify uses only terminal word boundary and consumes no delimiter.",
          "Preserve the source strict-less-than rejection with explicit native byte-shannon-f64-v1 algorithm and threshold 3.5; retain the original thirty rules and their entropy contracts unchanged.",
          "Preserve the complete generated global secret regex/stopword rejection through native base composition. No component, tokenizer, path-local or precedence predicate is omitted; source path policy remains a declared native difference.",
          "Retain explicit rule-local copies of all 13 source secret regexes with independent noncapturing scope and both source stopwords. Preserve predicate whitespace literally; inherited legacy flag leakage is unreachable for these six captured prefix languages."
        ]
      },
      "native": {
        "id": "rustleaks.apify-api-token",
        "description": "Apify API token",
        "regex": "\\b(apify_api_[A-Za-z0-9]{34,38})\\b",
        "secretGroup": 1,
        "keywords": [
          "apify_api_"
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "lt",
          "threshold": 3.5
        },
        "allowlists": [
          {
            "description": "Independently scoped source global secret exclusions",
            "regexTarget": "secret",
            "regexes": [
              "(?:(?i)^true|false|null$)",
              "(?:^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$)",
              "(?:^\\$(?:\\d+|{\\d+})$)",
              "(?:^\\$(?:[A-Z_]+|[a-z_]+)$)",
              "(?:^\\${(?:[A-Z_]+|[a-z_]+)}$)",
              "(?:^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$)",
              "(?:^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$)",
              "(?:^%(?:[A-Z_]+|[a-z_]+)%$)",
              "(?:^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$)",
              "(?:^\\{\\d{0,2}}$)",
              "(?:^@(?:[A-Z_]+|[a-z_]+)@$)",
              "(?:^/Users/(?i)[a-z0-9]+/[\\w .-/]+$)",
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)"
            ],
            "stopwords": [
              "abcdefghijklmnopqrstuvwxyz",
              "014df517-39d1-4453-b7b3-9930c563627c"
            ]
          }
        ]
      }
    }
  ]
}"#;

pub(super) fn validate(
    provenance: &serde_json::Value,
    native_rules: &[toml::Value],
) -> Result<(), String> {
    let reviewed: serde_json::Value = serde_json::from_str(REVIEWED)
        .map_err(|error| format!("invalid byte-entropy provider inventory: {error}"))?;
    if provenance["native_byte_entropy_selection"] != reviewed["selection"] {
        return Err("native byte-entropy source selection differs".into());
    }
    let origins = provenance["rules"]
        .as_array()
        .ok_or("provider origins missing")?;
    let expected = reviewed["rules"]
        .as_array()
        .ok_or("reviewed byte providers missing")?;
    if expected.len() != 6 || native_rules.len() != 303 || origins.len() != 303 {
        return Err("native byte-entropy provider inventory differs".into());
    }
    for ((native, origin), expected) in native_rules[30..36]
        .iter()
        .zip(&origins[30..36])
        .zip(expected)
    {
        let native = serde_json::to_value(native)
            .map_err(|error| format!("cannot inspect native byte provider: {error}"))?;
        if *origin != expected["origin"] || native != expected["native"] {
            return Err(format!(
                "native byte provider source or predicate differs: {}",
                expected["origin"]["id"]
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_changed_and_scalar_substituted_byte_predicates() {
        let root = crate::workspace_root().unwrap();
        let directory = root.join("crates/rustleaks-core/default");
        let provenance: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(directory.join("rustleaks-providers-v1.provenance.json"))
                .unwrap(),
        )
        .unwrap();
        let pack: toml::Value = toml::from_str(
            &std::fs::read_to_string(directory.join("rustleaks-providers-v1.toml")).unwrap(),
        )
        .unwrap();
        let rules = pack["rules"].as_array().unwrap();
        assert!(validate(&provenance, rules).is_ok());
        for index in 30..36 {
            for field in ["entropy", "regex", "secretGroup", "keywords", "allowlists"] {
                let mut changed = rules.clone();
                changed[index].as_table_mut().unwrap().remove(field);
                assert!(validate(&provenance, &changed).is_err());
            }
            let mut changed = rules.clone();
            changed[index]["entropy"] = toml::Value::Float(3.5);
            assert!(validate(&provenance, &changed).is_err());
            let mut changed = rules.clone();
            changed[index]["entropy"]["reject"] = toml::Value::String("le".into());
            assert!(validate(&provenance, &changed).is_err());
            let mut changed = provenance.clone();
            changed["rules"][index]["source_filter"] = serde_json::json!(null);
            assert!(validate(&changed, rules).is_err());
        }
        let mut changed = provenance.clone();
        changed["native_byte_entropy_selection"]["global_secret_regexes"] = serde_json::json!([]);
        assert!(validate(&changed, rules).is_err());
    }
}
