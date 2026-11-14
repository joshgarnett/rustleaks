//! Fixed source and native contracts for shared-prefix delimiter increments.

const REVIEWED: &str = r#"{
  "selection": {
    "source_url": "https://raw.githubusercontent.com/betterleaks/betterleaks/8f376ff9c31ed5309ac448fe601c5dd21b376155/config/betterleaks.toml",
    "source_sha256": "7c305ade42d5dbad4650b97cca0299f9c16d152ec555ae47bd6f321f049f82e5",
    "kingfisher_revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
    "rule_count": 24,
    "native_rule_slice": [
      36,
      60
    ],
    "global_secret_atoms": [
      [
        "matchesAny",
        "(?i)^true|false|null$"
      ],
      [
        "matchesAny",
        "^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$"
      ],
      [
        "matchesAny",
        "^\\$(?:\\d+|{\\d+})$"
      ],
      [
        "matchesAny",
        "^\\$(?:[A-Z_]+|[a-z_]+)$"
      ],
      [
        "matchesAny",
        "^\\${(?:[A-Z_]+|[a-z_]+)}$"
      ],
      [
        "matchesAny",
        "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$"
      ],
      [
        "matchesAny",
        "^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$"
      ],
      [
        "matchesAny",
        "^%(?:[A-Z_]+|[a-z_]+)%$"
      ],
      [
        "matchesAny",
        "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$"
      ],
      [
        "matchesAny",
        "^\\{\\d{0,2}}$"
      ],
      [
        "matchesAny",
        "^@(?:[A-Z_]+|[a-z_]+)@$"
      ],
      [
        "matchesAny",
        "^/Users/(?i)[a-z0-9]+/[\\w .-/]+$"
      ],
      [
        "matchesAny",
        "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$"
      ],
      [
        "containsAny",
        "abcdefghijklmnopqrstuvwxyz"
      ],
      [
        "containsAny",
        "014df517-39d1-4453-b7b3-9930c563627c"
      ]
    ],
    "scope": "Opt-in raw-byte delimiter increments. No ordinary-delimiter aliases, contextual-preamble changes, online validation, catalog completeness or source-path equivalence.",
    "arithmetic": "Ascending byte histogram, per-count binary64 division and accumulation; reject H <= threshold. No cross-platform libm-bit equality claim."
  },
  "rules": [
    {
      "origin": {
        "id": "rustleaks.aws-amazon-bedrock-api-key-long-lived-delimiter",
        "upstream_id": "aws-amazon-bedrock-api-key-long-lived",
        "source_line": 980,
        "source_pattern": "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "absk"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.aws-amazon-bedrock-api-key-long-lived-delimiter",
        "description": "aws amazon bedrock api key long lived before an escaped quote or vertical tab",
        "regex": "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "absk"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.digitalocean-access-token-delimiter",
        "upstream_id": "digitalocean-access-token",
        "source_line": 2866,
        "source_pattern": "\\b(doo_v1_[a-f0-9]{64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "doo_v1_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "present; not imported",
          "repository": "https://github.com/mongodb/kingfisher",
          "revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
          "path": "crates/kingfisher-rules/data/imported-rules-capabilities.yml",
          "sha256": "67e89f3c5f94bfd23446cc1d49d3a5aa8191381a687bc4939745d3f211152c61",
          "entry": "betterleaks.digitalocean-access-token",
          "line": 443,
          "entry_sha256": "bdacd758c6adc276ab3bb7b70e19291300de2e7baafd53d98e1cb3b55da0fdb5"
        },
        "native_pattern": "\\b(doo_v1_[a-f0-9]{64})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.digitalocean-access-token-delimiter",
        "description": "digitalocean access token before an escaped quote or vertical tab",
        "regex": "\\b(doo_v1_[a-f0-9]{64})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "doo_v1_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.gcp-api-key-delimiter",
        "upstream_id": "gcp-api-key",
        "source_line": 3737,
        "source_pattern": "\\b(AIza[\\w-]{35})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 4.0\n|| matchesAny(finding[\"secret\"], [\n  `AIzaSyabcdefghijklmnopqrstuvwxyz1234567`,\n  `AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`,\n  `AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`,\n  `AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`,\n  `AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`,\n  `AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`,\n  `AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`,\n  `AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`,\n  `AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`,\n  `AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`,\n  `AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`,\n  `AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`,\n  `AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`,\n  `AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`,\n  `AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`,\n  `AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`\n])\n",
        "source_filter_ast_sha256": "d56a4b27e94cb198d89cf7055b5e9c85b8ca81815f76d485ef63f1a4c7416d16",
        "source_keywords": [
          "aiza"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "present; not imported",
          "repository": "https://github.com/mongodb/kingfisher",
          "revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
          "path": "crates/kingfisher-rules/data/imported-rules-capabilities.yml",
          "sha256": "67e89f3c5f94bfd23446cc1d49d3a5aa8191381a687bc4939745d3f211152c61",
          "entry": "betterleaks.gcp-api-key",
          "line": 89,
          "entry_sha256": "2c11def852fc22f2b138f0d5a9abcdc6befabcf3e3cb3952ff1d27b4c916f8dc"
        },
        "native_pattern": "\\b(AIza[A-Za-z0-9_-]{35})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "local_secret_exclusions": [
          "AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
          "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
          "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
          "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
          "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
          "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
          "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
          "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
          "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
          "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
          "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
          "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
          "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
          "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
          "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
          "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"
        ],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.gcp-api-key-delimiter",
        "description": "gcp api key before an escaped quote or vertical tab",
        "regex": "\\b(AIza[A-Za-z0-9_-]{35})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "keywords": [
          "aiza"
        ],
        "allowlists": [
          {
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
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)",
              "(?:AIzaSyabcdefghijklmnopqrstuvwxyz1234567)",
              "(?:AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs)",
              "(?:AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM)",
              "(?:AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU)",
              "(?:AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0)",
              "(?:AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A)",
              "(?:AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c)",
              "(?:AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4)",
              "(?:AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY)",
              "(?:AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM)",
              "(?:AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ)",
              "(?:AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g)",
              "(?:AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU)",
              "(?:AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw)",
              "(?:AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE)",
              "(?:AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY)"
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
        "id": "rustleaks.huggingface-access-token-delimiter",
        "upstream_id": "huggingface-access-token",
        "source_line": 7074,
        "source_pattern": "\\b(hf_(?i:[a-z]{34}))(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "hf_"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "present; not imported",
        "source_revocation": "present; not imported",
        "kingfisher_revocation_overlay": {
          "status": "present; not imported",
          "repository": "https://github.com/mongodb/kingfisher",
          "revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
          "path": "crates/kingfisher-rules/data/imported-rules-capabilities.yml",
          "sha256": "67e89f3c5f94bfd23446cc1d49d3a5aa8191381a687bc4939745d3f211152c61",
          "entry": "betterleaks.huggingface-access-token",
          "line": 197,
          "entry_sha256": "ea66ec4f6cc029e36347b34dcabf3c9f9ab8dcd55da5d1f1c96818536b512b70"
        },
        "native_pattern": "\\b(hf_[A-Za-z]{34})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.huggingface-access-token-delimiter",
        "description": "huggingface access token before an escaped quote or vertical tab",
        "regex": "\\b(hf_[A-Za-z]{34})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "hf_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.huggingface-organization-api-token-delimiter",
        "upstream_id": "huggingface-organization-api-token",
        "source_line": 7163,
        "source_pattern": "\\b(api_org_(?i:[a-z]{34}))(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "api_org_"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "present; not imported",
        "source_revocation": "present; not imported",
        "kingfisher_revocation_overlay": {
          "status": "present; not imported",
          "repository": "https://github.com/mongodb/kingfisher",
          "revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
          "path": "crates/kingfisher-rules/data/imported-rules-capabilities.yml",
          "sha256": "67e89f3c5f94bfd23446cc1d49d3a5aa8191381a687bc4939745d3f211152c61",
          "entry": "betterleaks.huggingface-organization-api-token",
          "line": 212,
          "entry_sha256": "49b3c70965079b8f1cfcbebed601ec2869b9cf01e161303b748320a6e602593e",
          "alias": "huggingface_revoke",
          "anchor_line": 199
        },
        "native_pattern": "\\b(api_org_[A-Za-z]{34})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.huggingface-organization-api-token-delimiter",
        "description": "huggingface organization api token before an escaped quote or vertical tab",
        "regex": "\\b(api_org_[A-Za-z]{34})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "api_org_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.infracost-api-token-delimiter",
        "upstream_id": "infracost-api-token",
        "source_line": 7362,
        "source_pattern": "\\b(ico-[a-zA-Z0-9]{32})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "ico-"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(ico-[a-zA-Z0-9]{32})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.infracost-api-token-delimiter",
        "description": "infracost api token before an escaped quote or vertical tab",
        "regex": "\\b(ico-[a-zA-Z0-9]{32})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "ico-"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.intra42-client-secret-delimiter",
        "upstream_id": "intra42-client-secret",
        "source_line": 7415,
        "source_pattern": "\\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "intra",
          "s-s4t2ud-",
          "s-s4t2af-"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(s-s4t2(?:ud|af)-[a-fA-F0-9]{64})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.intra42-client-secret-delimiter",
        "description": "intra42 client secret before an escaped quote or vertical tab",
        "regex": "\\b(s-s4t2(?:ud|af)-[a-fA-F0-9]{64})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "intra",
          "s-s4t2ud-",
          "s-s4t2af-"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.maxmind-license-key-delimiter",
        "upstream_id": "maxmind-license-key",
        "source_line": 8294,
        "source_pattern": "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 4.0\n",
        "source_filter_ast_sha256": "21bbfd3cb4b2b3e779f3b108d70e3397b8bcd2e893f681faf1eeb5b6492aeed6",
        "source_keywords": [
          "_mmk"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.maxmind-license-key-delimiter",
        "description": "maxmind license key before an escaped quote or vertical tab",
        "regex": "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "keywords": [
          "_mmk"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.notion-api-token-delimiter",
        "upstream_id": "notion-api-token",
        "source_line": 8866,
        "source_pattern": "\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 4.0\n",
        "source_filter_ast_sha256": "21bbfd3cb4b2b3e779f3b108d70e3397b8bcd2e893f681faf1eeb5b6492aeed6",
        "source_keywords": [
          "ntn_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "present; not imported",
          "repository": "https://github.com/mongodb/kingfisher",
          "revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
          "path": "crates/kingfisher-rules/data/imported-rules-capabilities.yml",
          "sha256": "67e89f3c5f94bfd23446cc1d49d3a5aa8191381a687bc4939745d3f211152c61",
          "entry": "betterleaks.notion-api-token",
          "line": 257,
          "entry_sha256": "ae850a3dccc2e81d00408da3d2e4ece6b8498f41d1f7d42640b2948ea2042c47"
        },
        "native_pattern": "\\b(ntn_[0-9]{11}[A-Za-z0-9]{35})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.notion-api-token-delimiter",
        "description": "notion api token before an escaped quote or vertical tab",
        "regex": "\\b(ntn_[0-9]{11}[A-Za-z0-9]{35})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "keywords": [
          "ntn_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.octopus-deploy-api-key-delimiter",
        "upstream_id": "octopus-deploy-api-key",
        "source_line": 8995,
        "source_pattern": "\\b(API-[A-Z0-9]{26})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "api-"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(API-[A-Z0-9]{26})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.octopus-deploy-api-key-delimiter",
        "description": "octopus deploy api key before an escaped quote or vertical tab",
        "regex": "\\b(API-[A-Z0-9]{26})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "api-"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.planetscale-oauth-token-delimiter",
        "upstream_id": "planetscale-oauth-token",
        "source_line": 9637,
        "source_pattern": "\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "pscale_oauth_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(pscale_oauth_[A-Za-z0-9_=.-]{32,64})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.planetscale-oauth-token-delimiter",
        "description": "planetscale oauth token before an escaped quote or vertical tab",
        "regex": "\\b(pscale_oauth_[A-Za-z0-9_=.-]{32,64})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "pscale_oauth_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.planetscale-password-delimiter",
        "upstream_id": "planetscale-password",
        "source_line": 9650,
        "source_pattern": "(?i)\\b(pscale_pw_(?i)[\\w=\\.-]{32,64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "pscale_pw_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b([pP][sS][cC][aA][lL][eE]_[pP][wW]_[A-Za-z0-9_=.-]{32,64})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.planetscale-password-delimiter",
        "description": "planetscale password before an escaped quote or vertical tab",
        "regex": "\\b([pP][sS][cC][aA][lL][eE]_[pP][wW]_[A-Za-z0-9_=.-]{32,64})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "pscale_pw_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.prefect-api-token-delimiter",
        "upstream_id": "prefect-api-token",
        "source_line": 9957,
        "source_pattern": "\\b(pnu_[a-zA-Z0-9]{36})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "pnu_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(pnu_[a-zA-Z0-9]{36})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.prefect-api-token-delimiter",
        "description": "prefect api token before an escaped quote or vertical tab",
        "regex": "\\b(pnu_[a-zA-Z0-9]{36})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "pnu_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.pulumi-api-token-delimiter",
        "upstream_id": "pulumi-api-token",
        "source_line": 10023,
        "source_pattern": "\\b(pul-[a-f0-9]{40})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "pul-"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(pul-[a-f0-9]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.pulumi-api-token-delimiter",
        "description": "pulumi api token before an escaped quote or vertical tab",
        "regex": "\\b(pul-[a-f0-9]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "pul-"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.readme-api-token-delimiter",
        "upstream_id": "readme-api-token",
        "source_line": 10180,
        "source_pattern": "\\b(rdme_[a-z0-9]{70})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "rdme_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(rdme_[a-z0-9]{70})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.readme-api-token-delimiter",
        "description": "readme api token before an escaped quote or vertical tab",
        "regex": "\\b(rdme_[a-z0-9]{70})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "rdme_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.rubygems-api-token-delimiter",
        "upstream_id": "rubygems-api-token",
        "source_line": 10362,
        "source_pattern": "\\b(rubygems_[a-f0-9]{48})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "rubygems_"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(rubygems_[a-f0-9]{48})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.rubygems-api-token-delimiter",
        "description": "rubygems api token before an escaped quote or vertical tab",
        "regex": "\\b(rubygems_[a-f0-9]{48})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "rubygems_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.scalingo-api-token-delimiter",
        "upstream_id": "scalingo-api-token",
        "source_line": 10514,
        "source_pattern": "\\b(tk-us-[\\w-]{48})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "tk-us-"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(tk-us-[A-Za-z0-9_-]{48})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.scalingo-api-token-delimiter",
        "description": "scalingo api token before an escaped quote or vertical tab",
        "regex": "\\b(tk-us-[A-Za-z0-9_-]{48})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "tk-us-"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.settlemint-application-access-token-delimiter",
        "upstream_id": "settlemint-application-access-token",
        "source_line": 10727,
        "source_pattern": "\\b(sm_aat_[a-zA-Z0-9]{16})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "sm_aat"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(sm_aat_[a-zA-Z0-9]{16})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.settlemint-application-access-token-delimiter",
        "description": "settlemint application access token before an escaped quote or vertical tab",
        "regex": "\\b(sm_aat_[a-zA-Z0-9]{16})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "sm_aat"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.settlemint-personal-access-token-delimiter",
        "upstream_id": "settlemint-personal-access-token",
        "source_line": 10740,
        "source_pattern": "\\b(sm_pat_[a-zA-Z0-9]{16})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "sm_pat"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(sm_pat_[a-zA-Z0-9]{16})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.settlemint-personal-access-token-delimiter",
        "description": "settlemint personal access token before an escaped quote or vertical tab",
        "regex": "\\b(sm_pat_[a-zA-Z0-9]{16})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "sm_pat"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.settlemint-service-access-token-delimiter",
        "upstream_id": "settlemint-service-access-token",
        "source_line": 10753,
        "source_pattern": "\\b(sm_sat_[a-zA-Z0-9]{16})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "sm_sat"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(sm_sat_[a-zA-Z0-9]{16})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.settlemint-service-access-token-delimiter",
        "description": "settlemint service access token before an escaped quote or vertical tab",
        "regex": "\\b(sm_sat_[a-zA-Z0-9]{16})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "keywords": [
          "sm_sat"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.shippo-api-token-delimiter",
        "upstream_id": "shippo-api-token",
        "source_line": 10766,
        "source_pattern": "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "shippo_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.shippo-api-token-delimiter",
        "description": "shippo api token before an escaped quote or vertical tab",
        "regex": "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "shippo_"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.square-access-token-delimiter",
        "upstream_id": "square-access-token",
        "source_line": 11281,
        "source_pattern": "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "sq0atp-",
          "eaaa"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b((?:EAAA|sq0atp-)[A-Za-z0-9_-]{22,60})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.square-access-token-delimiter",
        "description": "square access token before an escaped quote or vertical tab",
        "regex": "\\b((?:EAAA|sq0atp-)[A-Za-z0-9_-]{22,60})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "keywords": [
          "sq0atp-",
          "eaaa"
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.vault-batch-token-delimiter",
        "upstream_id": "vault-batch-token",
        "source_line": 12214,
        "source_pattern": "\\b(hvb\\.[\\w-]{138,300})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 4.0\n",
        "source_filter_ast_sha256": "21bbfd3cb4b2b3e779f3b108d70e3397b8bcd2e893f681faf1eeb5b6492aeed6",
        "source_keywords": [
          "hvb."
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(hvb\\.[A-Za-z0-9_-]{138,300})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "local_secret_exclusions": [],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.vault-batch-token-delimiter",
        "description": "vault batch token before an escaped quote or vertical tab",
        "regex": "\\b(hvb\\.[A-Za-z0-9_-]{138,300})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "keywords": [
          "hvb."
        ],
        "allowlists": [
          {
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
        "id": "rustleaks.vault-service-token-delimiter",
        "upstream_id": "vault-service-token",
        "source_line": 12227,
        "source_pattern": "\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?i:[a-z0-9]{24})))(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n|| matchesAny(finding[\"secret\"], [`s\\.[A-Za-z]{24}`])\n",
        "source_filter_ast_sha256": "406c1c3ff0e7f463828c7789d93495385580a7c552f464f1978ba793b1644e21",
        "source_keywords": [
          "hvs.",
          "vault"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b((?:hvs\\.[A-Za-z0-9_-]{90,120}|s\\.[A-Za-z0-9]{24}))(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.5
        },
        "local_secret_exclusions": [
          "s\\.[A-Za-z]{24}"
        ],
        "transformations": [
          "Select only literal backslash followed by a single quote, double quote or backtick, or one vertical-tab byte. Keep ordinary delimiters and EOF with the unchanged default.",
          "Keep source prefix roles, alphabet, bounds, alternatives, ASCII word boundary and secret capture. Expand case-insensitive ASCII and word classes explicitly; reject non-ASCII folds.",
          "Use byte-shannon-f64-v1 with reject=le and the source threshold. Copy all generated global and local secret predicates into the rule, scope every regex independently, and preserve stopwords. The unchanged native global exclusions additionally apply; their case-flag leakage is unreachable in these fixed-prefix token languages. Retain native path policy.",
          "Retain source keywords, including vault context for the legacy s. form. Do not widen it to the default s. keyword."
        ]
      },
      "native": {
        "id": "rustleaks.vault-service-token-delimiter",
        "description": "vault service token before an escaped quote or vertical tab",
        "regex": "\\b((?:hvs\\.[A-Za-z0-9_-]{90,120}|s\\.[A-Za-z0-9]{24}))(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.5
        },
        "keywords": [
          "hvs.",
          "vault"
        ],
        "allowlists": [
          {
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
              "(?:^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$)",
              "(?:s\\.[A-Za-z]{24})"
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
        .map_err(|error| format!("invalid delimiter provider inventory: {error}"))?;
    if provenance["shared_delimiter_selection"] != reviewed["selection"] {
        return Err("shared delimiter source selection differs".into());
    }
    let origins = provenance["rules"]
        .as_array()
        .ok_or("provider origins missing")?;
    let expected = reviewed["rules"]
        .as_array()
        .ok_or("reviewed delimiter providers missing")?;
    if expected.len() != 24 || native_rules.len() != 104 || origins.len() != 104 {
        return Err("shared delimiter provider inventory differs".into());
    }
    for ((native, origin), expected) in native_rules[36..60]
        .iter()
        .zip(&origins[36..60])
        .zip(expected)
    {
        let native = serde_json::to_value(native)
            .map_err(|error| format!("cannot inspect delimiter provider: {error}"))?;
        if *origin != expected["origin"] || native != expected["native"] {
            return Err(format!(
                "delimiter source or predicate differs: {}",
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
    fn rejects_changed_delimiters_captures_predicates_and_source_keywords() {
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
        for index in 36..60 {
            for field in ["entropy", "regex", "secretGroup", "keywords", "allowlists"] {
                let mut changed = rules.clone();
                changed[index].as_table_mut().unwrap().remove(field);
                assert!(validate(&provenance, &changed).is_err());
            }
            let mut changed = rules.clone();
            changed[index]["entropy"]["reject"] = toml::Value::String("lt".into());
            assert!(validate(&provenance, &changed).is_err());
            let mut changed = rules.clone();
            changed[index]["allowlists"][0]["regexes"]
                .as_array_mut()
                .unwrap()
                .remove(0);
            assert!(validate(&provenance, &changed).is_err());
            let mut changed = provenance.clone();
            changed["rules"][index]["source_filter"] = serde_json::json!(null);
            assert!(validate(&changed, rules).is_err());
        }
    }
}
