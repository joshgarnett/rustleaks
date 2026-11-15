//! Fixed source and native contracts for fifteen optional provider additions.

use std::path::Path;

const REVIEWED: &str = r#"{
  "additional_sources": [
    {
      "repository": "https://github.com/google/osv-scalibr",
      "revision": "e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845",
      "license": "Apache-2.0",
      "license_url": "https://raw.githubusercontent.com/google/osv-scalibr/e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845/LICENSE",
      "license_sha256": "8d51837cfc3877f9847cc13afd6274bf5df00399f65dbf3eed2ca2ea070582ce",
      "license_path": "LICENSE.veles",
      "copyright": [
        "Copyright 2026 Google LLC",
        "Copyright 2025 Google LLC (additional xAI source header)"
      ],
      "upstream_notice": "absent in pinned source archive",
      "retrieved_via": {
        "repository": "https://github.com/mongodb/kingfisher",
        "revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
        "path": "crates/kingfisher-rules/generated/upstream-sources.json.gz"
      }
    }
  ],
  "rules": [
    {
      "origin": {
        "id": "rustleaks.checkout-secret-key",
        "upstream_id": "checkout-secret-key",
        "source_line": 1671,
        "source_pattern": "(?i)(?:checkout)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(sk_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_keywords": [
          "checkout"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "native_pattern": "(?:[cC][hH][eE][cC][kK][oO][uU][tT])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([sS][kK]_[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.checkout-secret-key",
        "description": "Checkout secret API key in assignment context",
        "regex": "(?:[cC][hH][eE][cC][kK][oO][uU][tT])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([sS][kK]_[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "checkout"
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.crates-io-api-key",
        "upstream_id": "crates-io-api-key",
        "source_line": 2440,
        "source_pattern": "(?i)(?:crates(?:[_.-]?io)?)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(cio[A-Za-z0-9]{32})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_keywords": [
          "crates"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "native_pattern": "(?:[cC][rR][aA][tT][eE][sS](?:[_.-]?[iI][oO])?)(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([cC][iI][oO][A-Za-z0-9]{32})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.crates-io-api-key",
        "description": "crates.io API key in assignment context",
        "regex": "(?:[cC][rR][aA][tT][eE][sS](?:[_.-]?[iI][oO])?)(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([cC][iI][oO][A-Za-z0-9]{32})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "crates"
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.cursor-api-key",
        "upstream_id": "cursor-api-key",
        "source_line": 2502,
        "source_pattern": "(?i)(?:cursor)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key_[0-9a-f]{64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n",
        "source_keywords": [
          "cursor"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "native_pattern": "(?:[cC][uU][rR][sS][oO][rR])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([kK][eE][yY]_[0-9a-fA-F]{64})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": 3.5,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.cursor-api-key",
        "description": "Cursor API key in assignment context",
        "regex": "(?:[cC][uU][rR][sS][oO][rR])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([kK][eE][yY]_[0-9a-fA-F]{64})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "cursor"
        ],
        "entropy": 3.5
      }
    },
    {
      "origin": {
        "id": "rustleaks.databento-api-key",
        "upstream_id": "databento-api-key",
        "source_line": 2526,
        "source_pattern": "(?i)(?:databento)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(db-[A-Za-z0-9]{29})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_keywords": [
          "databento"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "native_pattern": "(?:[dD][aA][tT][aA][bB][eE][nN][tT][oO])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([dD][bB]-[A-Za-z0-9]{29})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.databento-api-key",
        "description": "Databento API key in assignment context",
        "regex": "(?:[dD][aA][tT][aA][bB][eE][nN][tT][oO])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([dD][bB]-[A-Za-z0-9]{29})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "databento"
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.elevenlabs-api-key",
        "upstream_id": "elevenlabs-api-key",
        "source_line": 3200,
        "source_pattern": "(?i)(?:elevenlabs)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(sk_[0-9a-f]{48})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n",
        "source_keywords": [
          "elevenlabs"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "(?:[eE][lL][eE][vV][eE][nN][lL][aA][bB][sS])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([sS][kK]_[0-9a-fA-F]{48})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": 3.5,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.elevenlabs-api-key",
        "description": "ElevenLabs API key in assignment context",
        "regex": "(?:[eE][lL][eE][vV][eE][nN][lL][aA][bB][sS])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([sS][kK]_[0-9a-fA-F]{48})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "elevenlabs"
        ],
        "entropy": 3.5
      }
    },
    {
      "origin": {
        "id": "rustleaks.figma-personal-access-header-token",
        "upstream_id": "figma-personal-access-header-token",
        "source_line": 3444,
        "source_pattern": "(?i)(?:x-figma-token|xfigmatoken|x_figma_token)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-F]{4}-[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": null,
        "source_keywords": [
          "x-figma-token",
          "xfigmatoken",
          "x_figma_token"
        ],
        "source_validation": "present; not imported",
        "source_analysis": "present; not imported",
        "native_pattern": "(?:[xX]-[fF][iI][gG][mM][aA]-[tT][oO][kK][eE][nN]|[xX][fF][iI][gG][mM][aA][tT][oO][kK][eE][nN]|[xX]_[fF][iI][gG][mM][aA]_[tT][oO][kK][eE][nN])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([0-9a-fA-F]{4}-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.figma-personal-access-header-token",
        "description": "Figma personal access token in header context",
        "regex": "(?:[xX]-[fF][iI][gG][mM][aA]-[tT][oO][kK][eE][nN]|[xX][fF][iI][gG][mM][aA][tT][oO][kK][eE][nN]|[xX]_[fF][iI][gG][mM][aA]_[tT][oO][kK][eE][nN])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([0-9a-fA-F]{4}-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "x-figma-token",
          "xfigmatoken",
          "x_figma_token"
        ]
      }
    },
    {
      "origin": {
        "id": "rustleaks.ollama-api-key",
        "upstream_id": "ollama-api-key",
        "source_line": 9021,
        "source_pattern": "(?i)(?:ollama)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32}\\.[a-zA-Z0-9_-]{24})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n",
        "source_keywords": [
          "ollama"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "(?:[oO][lL][lL][aA][mM][aA])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([a-fA-F0-9]{32}\\.[a-zA-Z0-9_-]{24})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": 3.5,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.ollama-api-key",
        "description": "Ollama API key in assignment context",
        "regex": "(?:[oO][lL][lL][aA][mM][aA])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([a-fA-F0-9]{32}\\.[a-zA-Z0-9_-]{24})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "ollama"
        ],
        "entropy": 3.5
      }
    },
    {
      "origin": {
        "id": "rustleaks.polymarket-private-key",
        "upstream_id": "polymarket-private-key",
        "source_line": 9858,
        "source_pattern": "(?i:(?:poly.{0,20}private.{0,20}key)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(0x[a-fA-F0-9]{64})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n",
        "source_keywords": [
          "poly"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "(?:[pP][oO][lL][yY].{0,20}[pP][rR][iI][vV][aA][tT][eE].{0,20}[kK][eE][yY])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}(0x[a-fA-F0-9]{64})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secret_group": 1,
        "entropy": 3.5,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.polymarket-private-key",
        "description": "Polymarket private key in private-key context",
        "regex": "(?:[pP][oO][lL][yY].{0,20}[pP][rR][iI][vV][aA][tT][eE].{0,20}[kK][eE][yY])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}(0x[a-fA-F0-9]{64})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nr]|$)",
        "secretGroup": 1,
        "keywords": [
          "poly"
        ],
        "entropy": 3.5
      }
    },
    {
      "origin": {
        "id": "rustleaks.slack-session-cookie",
        "upstream_id": "slack-session-cookie",
        "source_line": 11074,
        "source_pattern": "(xoxd-[\\w\\/\\\\+-]{100,}={0,2})(?:[^\\w\\/+=-]|\\z)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n",
        "source_keywords": [
          "xoxd-"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "(xoxd-[A-Za-z0-9_/\\\\+-]{100,}={0,2})(?:[^A-Za-z0-9_/+=-]|\\z)",
        "secret_group": 1,
        "entropy": 3.5,
        "transformations": [
          "Preserve case-sensitive xoxd- prefix, unbounded minimum 100-byte body, zero through two padding bytes, consumed delimiter and absence of a leading boundary.",
          "Expand the ASCII word class explicitly in the body and terminal negated class; retain literal slash, backslash, plus and hyphen body bytes.",
          "Preserve the source terminal class, which admits backslash as a delimiter despite its body membership; matching remains greedy.",
          "Retain native entropy > 3.5 and existing input, retained-finding-byte, finding-count and work controls; no source numeric equivalence or live session claim."
        ]
      },
      "native": {
        "id": "rustleaks.slack-session-cookie",
        "description": "Slack browser or desktop session cookie",
        "regex": "(xoxd-[A-Za-z0-9_/\\\\+-]{100,}={0,2})(?:[^A-Za-z0-9_/+=-]|\\z)",
        "secretGroup": 1,
        "keywords": [
          "xoxd-"
        ],
        "entropy": 3.5
      }
    },
    {
      "origin": {
        "id": "rustleaks.slack-session-token",
        "upstream_id": "slack-session-token",
        "source_line": 11087,
        "source_pattern": "xoxc-\\d{9,15}-\\d{9,15}-\\d{9,15}-[a-f0-9]{64}\\b",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n",
        "source_keywords": [
          "xoxc-"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "(xoxc-[0-9]{9,15}-[0-9]{9,15}-[0-9]{9,15}-[a-f0-9]{64})\\b",
        "secret_group": 1,
        "entropy": 3.5,
        "transformations": [
          "Wrap the complete source expression before its trailing ASCII word boundary in capture 1; preserve absent leading boundary and case-sensitive prefix/body.",
          "Spell the three ASCII digit classes explicitly and preserve each 9 through 15 bound.",
          "Retain native entropy > 3.5 without numeric-equivalence claims. Do not invent a required cookie association; full session use and local detection are different claims."
        ]
      },
      "native": {
        "id": "rustleaks.slack-session-token",
        "description": "Slack client session token",
        "regex": "(xoxc-[0-9]{9,15}-[0-9]{9,15}-[0-9]{9,15}-[a-f0-9]{64})\\b",
        "secretGroup": 1,
        "keywords": [
          "xoxc-"
        ],
        "entropy": 3.5
      }
    },
    {
      "origin": {
        "id": "rustleaks.stability-ai-api-key",
        "upstream_id": "stability-ai-api-key",
        "source_line": 11332,
        "source_pattern": "(?i)(?:stability)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(sk-[A-Za-z0-9]{48})(?:\\\\?['\"\\x60]|[\\s;]|\\\\[nr]|$)",
        "source_filter": "entropy(finding[\"secret\"]) <= 3.5\n",
        "source_keywords": [
          "stability"
        ],
        "source_validation": "absent",
        "source_analysis": "absent",
        "native_pattern": "(?:[sS][tT][aA][bB][iI][lL][iI][tT][yY])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([sS][kK]-[A-Za-z0-9]{48})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secret_group": 1,
        "entropy": 3.5,
        "transformations": [
          "Preserve provider assignment context, all bounds, separator alternatives, capture 1 and terminal delimiters; never classify the bare body as this provider.",
          "Expand case-insensitive ASCII literals and body classes explicitly; expand word and whitespace shorthands to ASCII. Polymarket dot context retains existing rune matching, while its 0x and escaped n/r stay case-sensitive.",
          "Retain the native entropy threshold when present, without a claim of cross-engine floating-point equivalence; do not invent entropy when absent.",
          "Inherit unchanged Rustleaks global allowlists and source policy; omit network validation and analysis."
        ]
      },
      "native": {
        "id": "rustleaks.stability-ai-api-key",
        "description": "Stability AI API key in assignment context",
        "regex": "(?:[sS][tT][aA][bB][iI][lL][iI][tT][yY])(?:[ \\tA-Za-z0-9_.-]{0,20})[\\x09-\\x0d '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\x09-\\x0d =]{0,5}([sS][kK]-[A-Za-z0-9]{48})(?:\\\\?['\"\\x60]|[\\x09-\\x0d ;]|\\\\[nNrR]|$)",
        "secretGroup": 1,
        "keywords": [
          "stability"
        ],
        "entropy": 3.5
      }
    },
    {
      "origin": {
        "id": "rustleaks.circleci-project-token",
        "upstream_id": "veles.secrets/circleciproject",
        "source": {
          "url": "https://raw.githubusercontent.com/google/osv-scalibr/e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845/veles/secrets/circleci/detector.go",
          "line": 41,
          "sha256": "359c1a04ca6d2a2d1ce655fdec3a48c5771625ba9649ec6cf019e7d1337ea88a"
        },
        "source_pattern": "CCIPRJ_[A-Za-z0-9]{22}_[0-9a-f]{40}",
        "source_filter": null,
        "source_keywords": [],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_max_length": 70,
        "source_match_conversion": "unconditionally return complete match as typed token",
        "native_pattern": "(CCIPRJ_[A-Za-z0-9]{22}_[0-9a-f]{40})",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Adapt the exact finite Veles source expression directly, wrap capture 1, and namespace the identifier.",
          "Preserve case-sensitive prefix, exact body alphabet and length, absent leading/trailing boundaries and absence of entropy or local rejection predicates.",
          "Finite match length equals source MaxLen; inherit native global allowlists, source policy and scan controls. No scanner-streaming or validation equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.circleci-project-token",
        "description": "CircleCI project token",
        "regex": "(CCIPRJ_[A-Za-z0-9]{22}_[0-9a-f]{40})",
        "secretGroup": 1,
        "keywords": []
      }
    },
    {
      "origin": {
        "id": "rustleaks.deno-organization-token",
        "upstream_id": "veles.secrets/denopatorg",
        "source": {
          "url": "https://raw.githubusercontent.com/google/osv-scalibr/e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845/veles/secrets/denopat/detector.go",
          "line": 35,
          "sha256": "780567ca66ce2ce0e5f018cf474781129cb89e4d7457c7e298d03215b94209bb"
        },
        "source_pattern": "ddo_[A-Za-z0-9]{36}",
        "source_filter": null,
        "source_keywords": [],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_max_length": 40,
        "source_match_conversion": "unconditionally return complete match as typed token",
        "native_pattern": "(ddo_[A-Za-z0-9]{36})",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Adapt the exact finite Veles source expression directly, wrap capture 1, and namespace the identifier.",
          "Preserve case-sensitive prefix, exact body alphabet and length, absent leading/trailing boundaries and absence of entropy or local rejection predicates.",
          "Finite match length equals source MaxLen; inherit native global allowlists, source policy and scan controls. No scanner-streaming or validation equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.deno-organization-token",
        "description": "Deno organization token",
        "regex": "(ddo_[A-Za-z0-9]{36})",
        "secretGroup": 1,
        "keywords": []
      }
    },
    {
      "origin": {
        "id": "rustleaks.xai-api-key-80",
        "upstream_id": "veles.secrets/grokxaiapikey",
        "source": {
          "url": "https://raw.githubusercontent.com/google/osv-scalibr/e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845/veles/secrets/grokxaiapikey/detector.go",
          "line": 47,
          "sha256": "472d636fb093c4c3453ed355a251ffe656fadf7af65a3c57cf3ec624a2b8e39c"
        },
        "source_pattern": "xai-[A-Za-z0-9]{80}",
        "source_filter": null,
        "source_keywords": [],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_max_length": 84,
        "source_match_conversion": "unconditionally return complete match as typed token",
        "native_pattern": "(xai-[A-Za-z0-9]{80})",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Adapt the exact finite Veles source expression directly, wrap capture 1, and namespace the identifier.",
          "Preserve case-sensitive prefix, exact body alphabet and length, absent leading/trailing boundaries and absence of entropy or local rejection predicates.",
          "Finite match length equals source MaxLen; inherit native global allowlists, source policy and scan controls. No scanner-streaming or validation equivalence claim.",
          "Select only the Apache xai- plus 80 alphanumeric-byte source language. The overlapping MIT xai 70..120 rule and Kingfisher suppression overlay are not imported; this is not their union and does not recognize management keys."
        ]
      },
      "native": {
        "id": "rustleaks.xai-api-key-80",
        "description": "xAI API key with 80-byte body",
        "regex": "(xai-[A-Za-z0-9]{80})",
        "secretGroup": 1,
        "keywords": []
      }
    },
    {
      "origin": {
        "id": "rustleaks.postman-collection-token",
        "upstream_id": "veles.secrets/postmancollectiontoken",
        "source": {
          "url": "https://raw.githubusercontent.com/google/osv-scalibr/e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845/veles/secrets/postmanapikey/detector.go",
          "line": 46,
          "sha256": "dcb34f23af7a34d19a31141a12b8c68ccd7148fcc71eed99bbb93ba9695d940f"
        },
        "source_pattern": "PMAT-[A-Za-z0-9]{26}",
        "source_filter": null,
        "source_keywords": [],
        "source_validation": "present; not imported",
        "source_analysis": "absent",
        "source_max_length": 31,
        "source_match_conversion": "unconditionally return complete match as typed token",
        "native_pattern": "(PMAT-[A-Za-z0-9]{26})",
        "secret_group": 1,
        "entropy": null,
        "transformations": [
          "Adapt the exact finite Veles source expression directly, wrap capture 1, and namespace the identifier.",
          "Preserve case-sensitive prefix, exact body alphabet and length, absent leading/trailing boundaries and absence of entropy or local rejection predicates.",
          "Finite match length equals source MaxLen; inherit native global allowlists, source policy and scan controls. No scanner-streaming or validation equivalence claim."
        ]
      },
      "native": {
        "id": "rustleaks.postman-collection-token",
        "description": "Postman collection access token",
        "regex": "(PMAT-[A-Za-z0-9]{26})",
        "secretGroup": 1,
        "keywords": []
      }
    }
  ]
}"#;

pub(super) fn validate(
    root: &Path,
    provenance: &serde_json::Value,
    native_rules: &[toml::Value],
) -> Result<(), String> {
    let reviewed: serde_json::Value = serde_json::from_str(REVIEWED)
        .map_err(|error| format!("invalid reviewed provider inventory: {error}"))?;
    if provenance["additional_sources"] != reviewed["additional_sources"]
        || super::sha256_file(&root.join("crates/rustleaks-core/default/LICENSE.veles"))?
            != reviewed["additional_sources"][0]["license_sha256"]
    {
        return Err("additional provider source identity or license differs".into());
    }
    let origins = provenance["rules"]
        .as_array()
        .ok_or("provider origins missing")?;
    let expected = reviewed["rules"]
        .as_array()
        .ok_or("reviewed providers missing")?;
    if native_rules.len() != 300 || expected.len() != 15 || origins.len() != native_rules.len() {
        return Err("additional provider inventory differs".into());
    }
    for ((native, origin), expected) in native_rules[15..30]
        .iter()
        .zip(&origins[15..30])
        .zip(expected)
    {
        let native = serde_json::to_value(native)
            .map_err(|error| format!("cannot inspect native provider rule: {error}"))?;
        if *origin != expected["origin"] || native != expected["native"] {
            return Err(format!(
                "additional provider source or native contract differs: {}",
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
    fn rejects_omitted_predicates_changed_boundaries_and_source_metadata() {
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
        assert!(validate(&root, &provenance, rules).is_ok());
        for index in 15..30 {
            for field in ["regex", "secretGroup", "keywords"] {
                let mut changed = rules.clone();
                changed[index].as_table_mut().unwrap().remove(field);
                assert!(validate(&root, &provenance, &changed).is_err());
            }
            let mut changed = provenance.clone();
            changed["rules"][index]["source_pattern"] = serde_json::json!("changed");
            assert!(validate(&root, &changed, rules).is_err());
            let mut changed = rules.clone();
            changed[index]
                .as_table_mut()
                .unwrap()
                .insert("entropy".into(), toml::Value::Float(1.0));
            assert!(validate(&root, &provenance, &changed).is_err());
        }
        let mut changed = provenance.clone();
        changed["additional_sources"][0]["revision"] = serde_json::json!("changed");
        assert!(validate(&root, &changed, rules).is_err());
    }
}
