//! Fixed source and native contracts for contextual delimiter companions.
const REVIEWED: &str = r#"{
  "selection": {
    "source_url": "https://raw.githubusercontent.com/betterleaks/betterleaks/8f376ff9c31ed5309ac448fe601c5dd21b376155/config/betterleaks.toml",
    "source_sha256": "7c305ade42d5dbad4650b97cca0299f9c16d152ec555ae47bd6f321f049f82e5",
    "kingfisher_revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
    "rule_count": 44,
    "native_rule_slice": [
      60,
      104
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
    "scope": "Twenty context-sensitive families with disjoint terminal/context-VT companions, three VT-only residuals, and old OpenAI segment-pair endings. Excludes public Lob and Mailgun rows.",
    "global_flag_scope_proof": "Captured domains cannot start $, {, %, @ or slash, which are required by flag-sensitive inherited global expressions 3..13. Expression 2 retains its own case scope; expression 1 keeps its source alternation. Sonar bare letters and quoted Terraform values retain all source exclusions.",
    "enumeration": "First-VT alternations are disjoint for a particular source assignment. Distinct assignments or repeated context labels may still produce overlapping occurrences under existing native enumeration; no cross-engine enumeration equivalence claim."
  },
  "rules": [
    {
      "origin": {
        "id": "rustleaks.beamer-api-token-delimiter",
        "upstream_id": "beamer-api-token",
        "source_line": 1199,
        "source_pattern": "(?i)(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "beamer"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[bB][eE][aA][mM][eE][rR])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([bB]_[A-Za-z0-9=_\\-]{44})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.beamer-api-token-delimiter",
        "description": "beamer api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[bB][eE][aA][mM][eE][rR])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([bB]_[A-Za-z0-9=_\\-]{44})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "beamer"
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
        "id": "rustleaks.beamer-api-token-context-vt",
        "upstream_id": "beamer-api-token",
        "source_line": 1199,
        "source_pattern": "(?i)(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "beamer"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[bB][eE][aA][mM][eE][rR])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([bB]_[A-Za-z0-9=_\\-]{44})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.beamer-api-token-context-vt",
        "description": "beamer api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[bB][eE][aA][mM][eE][rR])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([bB]_[A-Za-z0-9=_\\-]{44})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "beamer"
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
        "id": "rustleaks.defined-networking-api-token-delimiter",
        "upstream_id": "defined-networking-api-token",
        "source_line": 2680,
        "source_pattern": "(?i)(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "dnkey"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[dD][nN][kK][eE][yY])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([dD][nN][kK][eE][yY]-[A-Za-z0-9=_\\-]{26}-[A-Za-z0-9=_\\-]{52})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.defined-networking-api-token-delimiter",
        "description": "defined networking api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[dD][nN][kK][eE][yY])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([dD][nN][kK][eE][yY]-[A-Za-z0-9=_\\-]{26}-[A-Za-z0-9=_\\-]{52})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "dnkey"
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
        "id": "rustleaks.defined-networking-api-token-context-vt",
        "upstream_id": "defined-networking-api-token",
        "source_line": 2680,
        "source_pattern": "(?i)(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "dnkey"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[dD][nN][kK][eE][yY])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([dD][nN][kK][eE][yY]-[A-Za-z0-9=_\\-]{26}-[A-Za-z0-9=_\\-]{52})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.defined-networking-api-token-context-vt",
        "description": "defined networking api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[dD][nN][kK][eE][yY])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([dD][nN][kK][eE][yY]-[A-Za-z0-9=_\\-]{26}-[A-Za-z0-9=_\\-]{52})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "dnkey"
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
        "id": "rustleaks.hashicorp-tf-password-delimiter",
        "upstream_id": "hashicorp-tf-password",
        "source_line": 6940,
        "source_pattern": "(?i)(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(\"[a-z0-9=_\\-]{8,20}\")(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "administrator_login_password",
          "password"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:(?:[aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR]_[lL][oO][gG][iI][nN]_[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][oO][rR][dD]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}(\"[A-Za-z0-9=_\\-]{8,20}\")(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": "\\.(?:[tT][fF]|[hH][cC][lL])$",
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.hashicorp-tf-password-delimiter",
        "description": "hashicorp tf password before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:(?:[aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR]_[lL][oO][gG][iI][nN]_[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][oO][rR][dD]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}(\"[A-Za-z0-9=_\\-]{8,20}\")(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "administrator_login_password",
          "password"
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
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "path": "\\.(?:[tT][fF]|[hH][cC][lL])$"
      }
    },
    {
      "origin": {
        "id": "rustleaks.hashicorp-tf-password-context-vt",
        "upstream_id": "hashicorp-tf-password",
        "source_line": 6940,
        "source_pattern": "(?i)(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(\"[a-z0-9=_\\-]{8,20}\")(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 2.0\n",
        "source_filter_ast_sha256": "ca9ac50298397c9a8c135aa6521b577892eea05ca43782cada9f05e65a9a9710",
        "source_keywords": [
          "administrator_login_password",
          "password"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:(?:[aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR]_[lL][oO][gG][iI][nN]_[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][oO][rR][dD]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))(\"[A-Za-z0-9=_\\-]{8,20}\")(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": "\\.(?:[tT][fF]|[hH][cC][lL])$",
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.hashicorp-tf-password-context-vt",
        "description": "hashicorp tf password with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:(?:[aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR]_[lL][oO][gG][iI][nN]_[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][oO][rR][dD]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))(\"[A-Za-z0-9=_\\-]{8,20}\")(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "administrator_login_password",
          "password"
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
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 2.0
        },
        "path": "\\.(?:[tT][fF]|[hH][cC][lL])$"
      }
    },
    {
      "origin": {
        "id": "rustleaks.heroku-api-key-delimiter",
        "upstream_id": "heroku-api-key",
        "source_line": 6957,
        "source_pattern": "(?i)(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "heroku"
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
          "entry": "betterleaks.heroku-api-key",
          "line": 458,
          "entry_sha256": "b7f31e66031086cfa62e115583f6191f8a1764fdc59eee197250fc4a9c5f247c"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[hH][eE][rR][oO][kK][uU])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.heroku-api-key-delimiter",
        "description": "heroku api key before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[hH][eE][rR][oO][kK][uU])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "heroku"
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
        "id": "rustleaks.heroku-api-key-context-vt",
        "upstream_id": "heroku-api-key",
        "source_line": 6957,
        "source_pattern": "(?i)(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "heroku"
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
          "entry": "betterleaks.heroku-api-key",
          "line": 458,
          "entry_sha256": "b7f31e66031086cfa62e115583f6191f8a1764fdc59eee197250fc4a9c5f247c"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[hH][eE][rR][oO][kK][uU])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.heroku-api-key-context-vt",
        "description": "heroku api key with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[hH][eE][rR][oO][kK][uU])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "heroku"
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
        "id": "rustleaks.hubspot-api-key-delimiter",
        "upstream_id": "hubspot-api-key",
        "source_line": 7064,
        "source_pattern": "(?i)(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "hubspot"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[hH][uU][bB][sS][pP][oO][tT])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.hubspot-api-key-delimiter",
        "description": "hubspot api key before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[hH][uU][bB][sS][pP][oO][tT])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "hubspot"
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
        "id": "rustleaks.hubspot-api-key-context-vt",
        "upstream_id": "hubspot-api-key",
        "source_line": 7064,
        "source_pattern": "(?i)(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "hubspot"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[hH][uU][bB][sS][pP][oO][tT])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.hubspot-api-key-context-vt",
        "description": "hubspot api key with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[hH][uU][bB][sS][pP][oO][tT])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "hubspot"
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
        "id": "rustleaks.lob-api-key-delimiter",
        "upstream_id": "lob-api-key",
        "source_line": 8002,
        "source_pattern": "(?i)(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "test_",
          "live_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[lL][oO][bB])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}(([lL][iI][vV][eE]|[tT][eE][sS][tT])_[a-fA-F0-9]{35})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.lob-api-key-delimiter",
        "description": "lob api key before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[lL][oO][bB])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}(([lL][iI][vV][eE]|[tT][eE][sS][tT])_[a-fA-F0-9]{35})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "test_",
          "live_"
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
        "id": "rustleaks.lob-api-key-context-vt",
        "upstream_id": "lob-api-key",
        "source_line": 8002,
        "source_pattern": "(?i)(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "test_",
          "live_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[lL][oO][bB])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))(([lL][iI][vV][eE]|[tT][eE][sS][tT])_[a-fA-F0-9]{35})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.lob-api-key-context-vt",
        "description": "lob api key with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[lL][oO][bB])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))(([lL][iI][vV][eE]|[tT][eE][sS][tT])_[a-fA-F0-9]{35})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "test_",
          "live_"
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
        "id": "rustleaks.mailchimp-api-key-delimiter",
        "upstream_id": "mailchimp-api-key",
        "source_line": 8054,
        "source_pattern": "(?i)(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "mailchimp"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "present; not imported",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:(?:[mM][aA][iI][lL][cC][hH][iI][mM][pP][sS][dD][kK].[iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([a-fA-F0-9]{32}-[uU][sS][0-9]{2})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.mailchimp-api-key-delimiter",
        "description": "mailchimp api key before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:(?:[mM][aA][iI][lL][cC][hH][iI][mM][pP][sS][dD][kK].[iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([a-fA-F0-9]{32}-[uU][sS][0-9]{2})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "mailchimp"
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
        "id": "rustleaks.mailchimp-api-key-context-vt",
        "upstream_id": "mailchimp-api-key",
        "source_line": 8054,
        "source_pattern": "(?i)(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "mailchimp"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "present; not imported",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:(?:[mM][aA][iI][lL][cC][hH][iI][mM][pP][sS][dD][kK].[iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([a-fA-F0-9]{32}-[uU][sS][0-9]{2})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.mailchimp-api-key-context-vt",
        "description": "mailchimp api key with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:(?:[mM][aA][iI][lL][cC][hH][iI][mM][pP][sS][dD][kK].[iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([a-fA-F0-9]{32}-[uU][sS][0-9]{2})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "mailchimp"
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
        "id": "rustleaks.mailgun-private-api-token-delimiter",
        "upstream_id": "mailgun-private-api-token",
        "source_line": 8120,
        "source_pattern": "(?i)(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "mailgun"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([kK][eE][yY]-[a-fA-F0-9]{32})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.mailgun-private-api-token-delimiter",
        "description": "mailgun private api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([kK][eE][yY]-[a-fA-F0-9]{32})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "mailgun"
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
        "id": "rustleaks.mailgun-private-api-token-context-vt",
        "upstream_id": "mailgun-private-api-token",
        "source_line": 8120,
        "source_pattern": "(?i)(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "mailgun"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([kK][eE][yY]-[a-fA-F0-9]{32})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.mailgun-private-api-token-context-vt",
        "description": "mailgun private api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([kK][eE][yY]-[a-fA-F0-9]{32})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "mailgun"
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
        "id": "rustleaks.mailgun-signing-key-delimiter",
        "upstream_id": "mailgun-signing-key",
        "source_line": 8151,
        "source_pattern": "(?i)(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "mailgun"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([a-hA-H0-9]{32}-[a-hA-H0-9]{8}-[a-hA-H0-9]{8})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.mailgun-signing-key-delimiter",
        "description": "mailgun signing key before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([a-hA-H0-9]{32}-[a-hA-H0-9]{8}-[a-hA-H0-9]{8})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "mailgun"
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
        "id": "rustleaks.mailgun-signing-key-context-vt",
        "upstream_id": "mailgun-signing-key",
        "source_line": 8151,
        "source_pattern": "(?i)(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "mailgun"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([a-hA-H0-9]{32}-[a-hA-H0-9]{8}-[a-hA-H0-9]{8})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.mailgun-signing-key-context-vt",
        "description": "mailgun signing key with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([a-hA-H0-9]{32}-[a-hA-H0-9]{8}-[a-hA-H0-9]{8})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "mailgun"
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
        "id": "rustleaks.okta-access-token-delimiter",
        "upstream_id": "okta-access-token",
        "source_line": 9008,
        "source_pattern": "(?i:(?:(?-i:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(00[\\w=\\-]{40})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 4.0\n",
        "source_filter_ast_sha256": "21bbfd3cb4b2b3e779f3b108d70e3397b8bcd2e893f681faf1eeb5b6492aeed6",
        "source_keywords": [
          "okta"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?[A-Za-z0-9_.-]{0,50}?(?:(?:[Oo]kta|OKTA))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}(00[A-Za-z0-9_=\\-]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.okta-access-token-delimiter",
        "description": "okta access token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?[A-Za-z0-9_.-]{0,50}?(?:(?:[Oo]kta|OKTA))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}(00[A-Za-z0-9_=\\-]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "okta"
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
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        }
      }
    },
    {
      "origin": {
        "id": "rustleaks.okta-access-token-context-vt",
        "upstream_id": "okta-access-token",
        "source_line": 9008,
        "source_pattern": "(?i:(?:(?-i:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(00[\\w=\\-]{40})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 4.0\n",
        "source_filter_ast_sha256": "21bbfd3cb4b2b3e779f3b108d70e3397b8bcd2e893f681faf1eeb5b6492aeed6",
        "source_keywords": [
          "okta"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?[A-Za-z0-9_.-]{0,50}?(?:(?:[Oo]kta|OKTA))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))(00[A-Za-z0-9_=\\-]{40})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        },
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.okta-access-token-context-vt",
        "description": "okta access token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?[A-Za-z0-9_.-]{0,50}?(?:(?:[Oo]kta|OKTA))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))(00[A-Za-z0-9_=\\-]{40})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secretGroup": 1,
        "keywords": [
          "okta"
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
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 4.0
        }
      }
    },
    {
      "origin": {
        "id": "rustleaks.plaid-api-token-delimiter",
        "upstream_id": "plaid-api-token",
        "source_line": 9556,
        "source_pattern": "(?i)(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "plaid"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[pP][lL][aA][iI][dD])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([aA][cC][cC][eE][sS][sS]-(?:[sS][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.plaid-api-token-delimiter",
        "description": "plaid api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[pP][lL][aA][iI][dD])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([aA][cC][cC][eE][sS][sS]-(?:[sS][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "plaid"
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
        "id": "rustleaks.plaid-api-token-context-vt",
        "upstream_id": "plaid-api-token",
        "source_line": 9556,
        "source_pattern": "(?i)(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "plaid"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[pP][lL][aA][iI][dD])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([aA][cC][cC][eE][sS][sS]-(?:[sS][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.plaid-api-token-context-vt",
        "description": "plaid api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[pP][lL][aA][iI][dD])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([aA][cC][cC][eE][sS][sS]-(?:[sS][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "plaid"
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
        "id": "rustleaks.sidekiq-secret-delimiter",
        "upstream_id": "sidekiq-secret",
        "source_line": 10831,
        "source_pattern": "(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "bundle_enterprise__contribsys__com",
          "bundle_gems__contribsys__com"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:(?:[bB][uU][nN][dD][lL][eE]_[eE][nN][tT][eE][rR][pP][rR][iI][sS][eE]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]|[bB][uU][nN][dD][lL][eE]_[gG][eE][mM][sS]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([a-fA-F0-9]{8}:[a-fA-F0-9]{8})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.sidekiq-secret-delimiter",
        "description": "sidekiq secret before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:(?:[bB][uU][nN][dD][lL][eE]_[eE][nN][tT][eE][rR][pP][rR][iI][sS][eE]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]|[bB][uU][nN][dD][lL][eE]_[gG][eE][mM][sS]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([a-fA-F0-9]{8}:[a-fA-F0-9]{8})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "bundle_enterprise__contribsys__com",
          "bundle_gems__contribsys__com"
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
        "id": "rustleaks.sidekiq-secret-context-vt",
        "upstream_id": "sidekiq-secret",
        "source_line": 10831,
        "source_pattern": "(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "bundle_enterprise__contribsys__com",
          "bundle_gems__contribsys__com"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:(?:[bB][uU][nN][dD][lL][eE]_[eE][nN][tT][eE][rR][pP][rR][iI][sS][eE]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]|[bB][uU][nN][dD][lL][eE]_[gG][eE][mM][sS]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([a-fA-F0-9]{8}:[a-fA-F0-9]{8})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.sidekiq-secret-context-vt",
        "description": "sidekiq secret with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:(?:[bB][uU][nN][dD][lL][eE]_[eE][nN][tT][eE][rR][pP][rR][iI][sS][eE]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]|[bB][uU][nN][dD][lL][eE]_[gG][eE][mM][sS]__[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS]__[cC][oO][mM]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([a-fA-F0-9]{8}:[a-fA-F0-9]{8})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "bundle_enterprise__contribsys__com",
          "bundle_gems__contribsys__com"
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
        "id": "rustleaks.snyk-api-token-delimiter",
        "upstream_id": "snyk-api-token",
        "source_line": 11235,
        "source_pattern": "(?i)(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "snyk"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[sS][nN][yY][kK][_.-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.-]?)?(?:[kK][eE][yY]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.snyk-api-token-delimiter",
        "description": "snyk api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[sS][nN][yY][kK][_.-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.-]?)?(?:[kK][eE][yY]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "snyk"
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
        "id": "rustleaks.snyk-api-token-context-vt",
        "upstream_id": "snyk-api-token",
        "source_line": 11235,
        "source_pattern": "(?i)(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "snyk"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[sS][nN][yY][kK][_.-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.-]?)?(?:[kK][eE][yY]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.snyk-api-token-context-vt",
        "description": "snyk api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[sS][nN][yY][kK][_.-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.-]?)?(?:[kK][eE][yY]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "snyk"
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
        "id": "rustleaks.sonar-api-token-delimiter",
        "upstream_id": "sonar-api-token",
        "source_line": 11245,
        "source_pattern": "(?i)(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "sonar"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[sS][oO][nN][aA][rR][_.-]?([lL][oO][gG][iI][nN]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}((?:[sS][qQ][uUpPaA]_)?[A-Za-z0-9=_\\-]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 2,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.sonar-api-token-delimiter",
        "description": "sonar api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[sS][oO][nN][aA][rR][_.-]?([lL][oO][gG][iI][nN]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}((?:[sS][qQ][uUpPaA]_)?[A-Za-z0-9=_\\-]{40})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 2,
        "keywords": [
          "sonar"
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
        "id": "rustleaks.sonar-api-token-context-vt",
        "upstream_id": "sonar-api-token",
        "source_line": 11245,
        "source_pattern": "(?i)(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "sonar"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[sS][oO][nN][aA][rR][_.-]?([lL][oO][gG][iI][nN]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))((?:[sS][qQ][uUpPaA]_)?[A-Za-z0-9=_\\-]{40})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 2,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.sonar-api-token-context-vt",
        "description": "sonar api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[sS][oO][nN][aA][rR][_.-]?([lL][oO][gG][iI][nN]|[tT][oO][kK][eE][nN]))[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))((?:[sS][qQ][uUpPaA]_)?[A-Za-z0-9=_\\-]{40})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 2,
        "keywords": [
          "sonar"
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
        "id": "rustleaks.squarespace-access-token-delimiter",
        "upstream_id": "squarespace-access-token",
        "source_line": 11297,
        "source_pattern": "(?i)(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "squarespace"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[sS][qQ][uU][aA][rR][eE][sS][pP][aA][cC][eE])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.squarespace-access-token-delimiter",
        "description": "squarespace access token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[sS][qQ][uU][aA][rR][eE][sS][pP][aA][cC][eE])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "squarespace"
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
        "id": "rustleaks.squarespace-access-token-context-vt",
        "upstream_id": "squarespace-access-token",
        "source_line": 11297,
        "source_pattern": "(?i)(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "squarespace"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[sS][qQ][uU][aA][rR][eE][sS][pP][aA][cC][eE])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.squarespace-access-token-context-vt",
        "description": "squarespace access token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[sS][qQ][uU][aA][rR][eE][sS][pP][aA][cC][eE])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "squarespace"
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
        "id": "rustleaks.telegram-bot-api-token-delimiter",
        "upstream_id": "telegram-bot-api-token",
        "source_line": 11803,
        "source_pattern": "(?i)(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "telegr"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[tT][eE][lL][eE][gG][rR])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9]{5,16}:A[A-Za-z0-9_\\-]{34})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.telegram-bot-api-token-delimiter",
        "description": "telegram bot api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[tT][eE][lL][eE][gG][rR])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([0-9]{5,16}:A[A-Za-z0-9_\\-]{34})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "telegr"
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
        "id": "rustleaks.telegram-bot-api-token-context-vt",
        "upstream_id": "telegram-bot-api-token",
        "source_line": 11803,
        "source_pattern": "(?i)(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "telegr"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[tT][eE][lL][eE][gG][rR])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9]{5,16}:A[A-Za-z0-9_\\-]{34})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.telegram-bot-api-token-context-vt",
        "description": "telegram bot api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[tT][eE][lL][eE][gG][rR])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([0-9]{5,16}:A[A-Za-z0-9_\\-]{34})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "telegr"
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
        "id": "rustleaks.typeform-api-token-delimiter",
        "upstream_id": "typeform-api-token",
        "source_line": 12066,
        "source_pattern": "(?i)(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "tfp_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[tT][yY][pP][eE][fF][oO][rR][mM])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([tT][fF][pP]_[A-Za-z0-9\\-_\\.=]{59})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.typeform-api-token-delimiter",
        "description": "typeform api token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[tT][yY][pP][eE][fF][oO][rR][mM])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([tT][fF][pP]_[A-Za-z0-9\\-_\\.=]{59})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "tfp_"
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
        "id": "rustleaks.typeform-api-token-context-vt",
        "upstream_id": "typeform-api-token",
        "source_line": 12066,
        "source_pattern": "(?i)(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "tfp_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[tT][yY][pP][eE][fF][oO][rR][mM])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([tT][fF][pP]_[A-Za-z0-9\\-_\\.=]{59})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.typeform-api-token-context-vt",
        "description": "typeform api token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[tT][yY][pP][eE][fF][oO][rR][mM])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([tT][fF][pP]_[A-Za-z0-9\\-_\\.=]{59})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "tfp_"
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
        "id": "rustleaks.yandex-access-token-delimiter",
        "upstream_id": "yandex-access-token",
        "source_line": 12926,
        "source_pattern": "(?i)(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "yandex"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([tT]1\\.[A-Za-z0-9_-]+={0,2}\\.[A-Za-z0-9_-]{86}={0,2})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.yandex-access-token-delimiter",
        "description": "yandex access token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([tT]1\\.[A-Za-z0-9_-]+={0,2}\\.[A-Za-z0-9_-]{86}={0,2})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "yandex"
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
        "id": "rustleaks.yandex-access-token-context-vt",
        "upstream_id": "yandex-access-token",
        "source_line": 12926,
        "source_pattern": "(?i)(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "yandex"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([tT]1\\.[A-Za-z0-9_-]+={0,2}\\.[A-Za-z0-9_-]{86}={0,2})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.yandex-access-token-context-vt",
        "description": "yandex access token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([tT]1\\.[A-Za-z0-9_-]+={0,2}\\.[A-Za-z0-9_-]{86}={0,2})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "yandex"
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
        "id": "rustleaks.yandex-api-key-delimiter",
        "upstream_id": "yandex-api-key",
        "source_line": 12936,
        "source_pattern": "(?i)(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "yandex"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([aA][qQ][vV][nN][A-Za-z0-9_\\-]{35,38})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.yandex-api-key-delimiter",
        "description": "yandex api key before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([aA][qQ][vV][nN][A-Za-z0-9_\\-]{35,38})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "yandex"
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
        "id": "rustleaks.yandex-api-key-context-vt",
        "upstream_id": "yandex-api-key",
        "source_line": 12936,
        "source_pattern": "(?i)(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "yandex"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([aA][qQ][vV][nN][A-Za-z0-9_\\-]{35,38})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.yandex-api-key-context-vt",
        "description": "yandex api key with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([aA][qQ][vV][nN][A-Za-z0-9_\\-]{35,38})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "yandex"
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
        "id": "rustleaks.yandex-aws-access-token-delimiter",
        "upstream_id": "yandex-aws-access-token",
        "source_line": 12946,
        "source_pattern": "(?i)(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "yandex"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([yY][cC][A-Za-z0-9_\\-]{38})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before an escaped quote or vertical tab without context VT",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.yandex-aws-access-token-delimiter",
        "description": "yandex aws access token before an escaped quote or vertical tab without context VT",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0,5}([yY][cC][A-Za-z0-9_\\-]{38})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "yandex"
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
        "id": "rustleaks.yandex-aws-access-token-context-vt",
        "upstream_id": "yandex-aws-access-token",
        "source_line": 12946,
        "source_pattern": "(?i)(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "yandex"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([yY][cC][A-Za-z0-9_\\-]{38})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "with vertical tab in assignment whitespace",
        "transformations": [
          "Append a disjoint occurrence companion; preserve the previous sixty rule definitions and bytes.",
          "Preserve source context labels, token roles, alphabets, capture numbering, bounds and case resets. Use explicit ASCII folding; retain Mailchimp dot rune semantics and unbounded first Yandex segment.",
          "Preserve the native optional ASCII preamble for full-match geometry; its removal alone is not an occurrence increment. Okta retains both native optional preambles.",
          "Separate terminal gaps with no context VT from source VT in the 0..3 pre-separator or 0..5 post-separator regions. First-VT alternations preserve each total bound and do not expand the 0..20 label tail.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.yandex-aws-access-token-context-vt",
        "description": "yandex aws access token with vertical tab in assignment whitespace",
        "regex": "[A-Za-z0-9_.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])[ \\tA-Za-z0-9_.-]{0,20}(?:(?:[\\x09\\x0a\\x0c\\x0d '\\\"]{0}\\x0b[\\x09-\\x0d '\\\"]{0,2}|[\\x09\\x0a\\x0c\\x0d '\\\"]{1}\\x0b[\\x09-\\x0d '\\\"]{0,1}|[\\x09\\x0a\\x0c\\x0d '\\\"]{2}\\x0b[\\x09-\\x0d '\\\"]{0,0})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}|[\\x09\\x0a\\x0c\\x0d '\\\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)(?:[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{0}\\x0b[\\x60'\"\\x09-\\x0d =]{0,4}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{1}\\x0b[\\x60'\"\\x09-\\x0d =]{0,3}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{2}\\x0b[\\x60'\"\\x09-\\x0d =]{0,2}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{3}\\x0b[\\x60'\"\\x09-\\x0d =]{0,1}|[\\x60'\"\\x09\\x0a\\x0c\\x0d =]{4}\\x0b[\\x60'\"\\x09-\\x0d =]{0,0}))([yY][cC][A-Za-z0-9_\\-]{38})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "yandex"
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
        "id": "rustleaks.anthropic-api-key-vt",
        "upstream_id": "anthropic-api-key",
        "source_line": 610,
        "source_pattern": "\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "sk-ant-api03"
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
          "entry": "betterleaks.anthropic-api-key",
          "line": 243,
          "entry_sha256": "ff054d34e4cc5f1e782fb7b5b672722b95eea5064c00e3adec4be18bba543fc2"
        },
        "native_pattern": "\\b(sk-ant-api03-[A-Za-z0-9_\\-]{93}AA)\\x0b",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before vertical tab",
        "transformations": [
          "Append a disjoint residual ending companion; preserve the previous sixty rule definitions and bytes.",
          "Retain the source token prefix, roles, alphabet, bounds, word-boundary ownership and capture 1. Select only the specified missing endings.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.anthropic-api-key-vt",
        "description": "anthropic api key before vertical tab",
        "regex": "\\b(sk-ant-api03-[A-Za-z0-9_\\-]{93}AA)\\x0b",
        "secretGroup": 1,
        "keywords": [
          "sk-ant-api03"
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
        "id": "rustleaks.anthropic-admin-api-key-vt",
        "upstream_id": "anthropic-admin-api-key",
        "source_line": 588,
        "source_pattern": "\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "sk-ant-admin01"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b(sk-ant-admin01-[A-Za-z0-9_\\-]{93}AA)\\x0b",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before vertical tab",
        "transformations": [
          "Append a disjoint residual ending companion; preserve the previous sixty rule definitions and bytes.",
          "Retain the source token prefix, roles, alphabet, bounds, word-boundary ownership and capture 1. Select only the specified missing endings.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.anthropic-admin-api-key-vt",
        "description": "anthropic admin api key before vertical tab",
        "regex": "\\b(sk-ant-admin01-[A-Za-z0-9_\\-]{93}AA)\\x0b",
        "secretGroup": 1,
        "keywords": [
          "sk-ant-admin01"
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
        "id": "rustleaks.digitalocean-refresh-token-vt",
        "upstream_id": "digitalocean-refresh-token",
        "source_line": 2892,
        "source_pattern": "(?i)\\b(dor_v1_[a-f0-9]{64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_filter_ast_sha256": "e2d59e099b186d4d5f3b53f24a76c9c3574db5d415ea83dcb6cc61a77a804d9d",
        "source_keywords": [
          "dor_v1_"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "source_revocation": "absent",
        "kingfisher_revocation_overlay": {
          "status": "absent"
        },
        "native_pattern": "\\b([dD][oO][rR]_[vV]1_[a-fA-F0-9]{64})\\x0b",
        "secret_group": 1,
        "native_path": null,
        "entropy": null,
        "increment": "before vertical tab",
        "transformations": [
          "Append a disjoint residual ending companion; preserve the previous sixty rule definitions and bytes.",
          "Retain the source token prefix, roles, alphabet, bounds, word-boundary ownership and capture 1. Select only the specified missing endings.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.digitalocean-refresh-token-vt",
        "description": "digitalocean refresh token before vertical tab",
        "regex": "\\b([dD][oO][rR]_[vV]1_[a-fA-F0-9]{64})\\x0b",
        "secretGroup": 1,
        "keywords": [
          "dor_v1_"
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
        "id": "rustleaks.openai-api-key-legacy-delimiter",
        "upstream_id": "openai-api-key",
        "source_line": 9133,
        "source_pattern": "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.0\n",
        "source_filter_ast_sha256": "f5e547688a355cfbf3a17f11ad60e71d368d50d2bc3eacd5b8d366ada8828f46",
        "source_keywords": [
          "t3blbkfj"
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
          "entry": "betterleaks.openai-api-key",
          "line": 219,
          "entry_sha256": "54e2ba5ea81a45cb88f7a18247b8d23c32e542cc9c386e804eae7b3eac74668a"
        },
        "native_pattern": "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?:\\\\['\"\\x60]|\\x0b)",
        "secret_group": 1,
        "native_path": null,
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        },
        "increment": "with existing role or bare token forms before an escaped quote or vertical tab",
        "transformations": [
          "Append a disjoint residual ending companion; preserve the previous sixty rule definitions and bytes.",
          "Retain the source token prefix, roles, alphabet, bounds, word-boundary ownership and capture 1. Select only the specified missing endings.",
          "Preserve complete source secret predicates with independently scoped Go-style regexes and case-insensitive stopwords. Native global/path policy additionally applies; no source policy equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.openai-api-key-legacy-delimiter",
        "description": "openai api key with existing role or bare token forms before an escaped quote or vertical tab",
        "regex": "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?:\\\\['\"\\x60]|\\x0b)",
        "secretGroup": 1,
        "keywords": [
          "t3blbkfj"
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
        ],
        "entropy": {
          "algorithm": "byte-shannon-f64-v1",
          "reject": "le",
          "threshold": 3.0
        }
      }
    }
  ]
}"#;

pub(super) fn validate(
    provenance: &serde_json::Value,
    native_rules: &[toml::Value],
) -> Result<(), String> {
    let reviewed: serde_json::Value = serde_json::from_str(REVIEWED)
        .map_err(|error| format!("invalid contextual inventory: {error}"))?;
    if provenance["contextual_delimiter_selection"] != reviewed["selection"] {
        return Err("contextual source selection differs".into());
    }
    let origins = provenance["rules"]
        .as_array()
        .ok_or("provider origins missing")?;
    let expected = reviewed["rules"]
        .as_array()
        .ok_or("contextual rules missing")?;
    if expected.len() != 44 || native_rules.len() != 303 || origins.len() != 303 {
        return Err("contextual inventory differs".into());
    }
    for ((native, origin), expected) in native_rules[60..104]
        .iter()
        .zip(&origins[60..104])
        .zip(expected)
    {
        let native = serde_json::to_value(native)
            .map_err(|error| format!("cannot inspect context rule: {error}"))?;
        if *origin != expected["origin"] || native != expected["native"] {
            return Err(format!(
                "contextual source or native contract differs: {}",
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
    fn rejects_changed_context_capture_path_bounds_predicates_and_provenance() {
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
        for index in 60..104 {
            for field in ["regex", "secretGroup", "keywords", "allowlists"] {
                let mut changed = rules.clone();
                changed[index].as_table_mut().unwrap().remove(field);
                assert!(validate(&provenance, &changed).is_err());
            }
            for field in ["path", "entropy"] {
                let mut changed = rules.clone();
                if changed[index].get(field).is_some() {
                    changed[index].as_table_mut().unwrap().remove(field);
                } else {
                    changed[index]
                        .as_table_mut()
                        .unwrap()
                        .insert(field.into(), toml::Value::String("unreviewed".into()));
                }
                assert!(validate(&provenance, &changed).is_err());
            }
            let mut changed = provenance.clone();
            changed["rules"][index]["source_filter_ast_sha256"] = serde_json::json!("changed");
            assert!(validate(&changed, rules).is_err());
        }
    }
}
