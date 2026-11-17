//! One small source file per language, with synthetic tokens placed in the
//! usual assignment forms of that language, scanned with every default rule.
//!
//! Each expected finding is written from the pinned rule text: the rule ID,
//! the exact secret, the bytes the match adds before and after the secret,
//! and the line and columns that follow from where the token is placed. The
//! files hold `@NAME@` markers so that no token appears in this source file.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::OnceLock;

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Finding, Fragment, Location, ScanOptions};

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(ConfigLoader::new().load_default().unwrap())
            .build()
            .unwrap()
    })
}

fn cycle(alphabet: &str, length: usize) -> String {
    alphabet.chars().cycle().take(length).collect()
}

/// Synthetic token values, built so that each matches exactly one rule.
fn value(marker: &str) -> String {
    const MIXED: &str = "Q7m2Z9v4L1c8R5s0N6b3X";
    match marker {
        // `(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`, not ending in EXAMPLE.
        "AWS" => format!("AKIA{}", cycle("Q7MZ4L2C5R3NBXWT", 16)),
        // `ghp_[0-9a-zA-Z]{36}`
        "GITHUB" => format!("ghp_{}", cycle(MIXED, 36)),
        // `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`
        "SLACK" => format!(
            "xoxb-{}-{}-{}",
            cycle("7302918465", 12),
            cycle("5829104736", 13),
            cycle(MIXED, 24)
        ),
        "SLACK2" => format!(
            "xoxb-{}-{}-{}",
            cycle("8415029376", 11),
            cycle("6930215847", 12),
            cycle("Hk3Wq8Pz2Jv5", 24)
        ),
        // `(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}` and a terminator.
        "STRIPE" => format!("sk_live_{}", cycle(MIXED, 24)),
        // `glpat-[\w-]{20}`
        "GITLAB" => format!("glpat-{}", cycle("Q7m2-Z9v4_L1c8", 20)),
        // `(?i)\b(npm_[a-z0-9]{36})` and a terminator.
        "NPM" => format!("npm_{}", cycle("q7m2z9v4l1c8r5s0n6b3x", 36)),
        // A generic value with Shannon entropy above 3.5 and no stopword.
        "GENERIC" => cycle("Hk3Wq8Pz2Jv5Rt9", 24),
        other => panic!("unknown marker {other}"),
    }
}

const MARKERS: [&str; 8] = [
    "AWS", "GITHUB", "SLACK", "SLACK2", "STRIPE", "GITLAB", "NPM", "GENERIC",
];

/// (rule, marker, match bytes before the secret, match bytes after it)
type Expected = (&'static str, &'static str, &'static str, &'static str);

const AWS: Expected = ("aws-access-token", "AWS", "", "");
const GITHUB: Expected = ("github-pat", "GITHUB", "", "");
const SLACK: Expected = ("slack-bot-token", "SLACK", "", "");
const SLACK2: Expected = ("slack-bot-token", "SLACK2", "", "");
const GITLAB: Expected = ("gitlab-pat", "GITLAB", "", "");

const fn stripe(terminator: &'static str) -> Expected {
    ("stripe-access-token", "STRIPE", "", terminator)
}

const fn npm(terminator: &'static str) -> Expected {
    ("npm-access-token", "NPM", "", terminator)
}

struct Fixture {
    language: &'static str,
    path: &'static str,
    text: &'static str,
    expected: &'static [Expected],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        language: "C",
        path: "src/main.c",
        text: "#include <stdio.h>\n\nstatic const char *aws_id = \"@AWS@\";\nstatic const char *gh = \"@GITHUB@\";\n\nint main(void) {\n    printf(\"%s %s\\n\", aws_id, gh);\n    return 0;\n}\n",
        expected: &[AWS, GITHUB],
    },
    Fixture {
        language: "C++",
        path: "src/config.cpp",
        text: "#include <string>\n\nnamespace config {\nconst std::string kSlack = \"@SLACK@\";\nconst std::string kStripe{\"@STRIPE@\"};\n}  // namespace config\n",
        expected: &[SLACK, stripe("\"")],
    },
    Fixture {
        language: "C#",
        path: "src/Settings.cs",
        text: "namespace Example\n{\n    public static class Settings\n    {\n        public const string GitLab = \"@GITLAB@\";\n        public const string Npm = @\"@NPM@\";\n    }\n}\n",
        expected: &[GITLAB, npm("\"")],
    },
    Fixture {
        language: "Elixir",
        path: "config/config.exs",
        text: "import Config\n\nconfig :example, Example.Client,\n  github: \"@GITHUB@\",\n  region: \"eu-west-1\"\n",
        expected: &[GITHUB],
    },
    Fixture {
        language: "Go",
        path: "cmd/main.go",
        text: "package main\n\nimport \"fmt\"\n\nconst awsID = \"@AWS@\"\n\nfunc main() {\n\tstripe := \"@STRIPE@\"\n\tfmt.Println(awsID, stripe)\n}\n",
        expected: &[AWS, stripe("\"")],
    },
    Fixture {
        language: "Java",
        path: "src/main/java/example/Config.java",
        text: "package example;\n\npublic final class Config {\n    static final String SLACK = \"@SLACK@\";\n    static final String GITLAB = \"@GITLAB@\";\n\n    private Config() {}\n}\n",
        expected: &[SLACK, GITLAB],
    },
    Fixture {
        language: "JavaScript",
        path: "lib/index.js",
        text: "const npm = '@NPM@';\nconst github = `@GITHUB@`;\n\nmodule.exports = { npm, github };\n",
        expected: &[npm("'"), GITHUB],
    },
    Fixture {
        language: "JSON",
        path: "config/settings.json",
        text: "{\n  \"aws\": \"@AWS@\",\n  \"slack\": \"@SLACK@\",\n  \"region\": \"us-east-1\"\n}\n",
        expected: &[AWS, SLACK],
    },
    Fixture {
        language: "Objective-C",
        path: "App/AppDelegate.m",
        text: "#import \"AppDelegate.h\"\n\nstatic NSString * const kStripe = @\"@STRIPE@\";\n\n@implementation AppDelegate\n@end\n",
        expected: &[stripe("\"")],
    },
    Fixture {
        language: "PHP",
        path: "config/app.php",
        text: "<?php\n\nreturn [\n    'gitlab' => '@GITLAB@',\n    'npm' => \"@NPM@\",\n];\n",
        expected: &[GITLAB, npm("\"")],
    },
    Fixture {
        language: "Python 2",
        path: "legacy/settings.py",
        text: "# -*- coding: utf-8 -*-\nAWS_ID = '@AWS@'\n\ndef show():\n    print AWS_ID\n",
        expected: &[AWS],
    },
    Fixture {
        language: "Python 3",
        path: "app/client.py",
        text: "import os\n\nGITHUB = os.environ.get(\"GITHUB\", \"@GITHUB@\")\nSLACK = \"@SLACK@\"\n",
        expected: &[GITHUB, SLACK],
    },
    Fixture {
        language: "Ruby",
        path: "config/initializers/example.rb",
        text: "module Example\n  STRIPE = \"@STRIPE@\".freeze\n  GITLAB = '@GITLAB@'\nend\n",
        expected: &[stripe("\""), GITLAB],
    },
    Fixture {
        language: "Rust",
        path: "src/main.rs",
        text: "const NPM: &str = \"@NPM@\";\n\nfn main() {\n    let aws = \"@AWS@\";\n    println!(\"{NPM} {aws}\");\n}\n",
        expected: &[npm("\""), AWS],
    },
    Fixture {
        language: "Scala",
        path: "src/main/scala/Config.scala",
        text: "object Config {\n  val github: String = \"@GITHUB@\"\n  val slack = s\"@SLACK@\"\n}\n",
        expected: &[GITHUB, SLACK],
    },
    Fixture {
        language: "Shell",
        path: "scripts/deploy.sh",
        text: "#!/bin/sh\nset -eu\nexport STRIPE=\"@STRIPE@\"\nGITLAB=@GITLAB@ ./run.sh\n",
        expected: &[stripe("\""), GITLAB],
    },
    Fixture {
        language: "Swift",
        path: "Sources/App/Config.swift",
        text: "import Foundation\n\nenum Config {\n    static let aws = \"@AWS@\"\n    static let npm = \"@NPM@\"\n}\n",
        expected: &[AWS, npm("\"")],
    },
    Fixture {
        language: "TOML",
        path: "config/settings.toml",
        text: "[service]\ngithub = \"@GITHUB@\"\ngitlab = '@GITLAB@'\n",
        expected: &[GITHUB, GITLAB],
    },
    Fixture {
        language: "TSX",
        path: "web/App.tsx",
        text: "const slack = \"@SLACK@\";\n\nexport function App(): JSX.Element {\n  return <div data-slack={slack} />;\n}\n",
        expected: &[SLACK],
    },
    Fixture {
        language: "TypeScript",
        path: "web/client.ts",
        text: "export const stripe: string = \"@STRIPE@\";\nexport const aws = '@AWS@';\n",
        expected: &[stripe("\""), AWS],
    },
    Fixture {
        language: "YAML",
        path: "deploy/values.yaml",
        text: "service:\n  npm: \"@NPM@\"\n  github: @GITHUB@\n",
        expected: &[npm("\""), GITHUB],
    },
    Fixture {
        language: "Java properties",
        path: "config/slack.properties",
        text: "slack.bot=@SLACK@\nslack.second=@SLACK2@\n",
        expected: &[SLACK, SLACK2],
    },
    Fixture {
        language: "Python, generic assignment",
        path: "app/database.py",
        text: "import sqlalchemy\n\ndb_password = \"@GENERIC@\"\nengine = sqlalchemy.create_engine(\"sqlite://\")\n",
        expected: &[("generic-api-key", "GENERIC", "db_password = \"", "\"")],
    },
];

fn render(text: &str) -> String {
    let mut rendered = text.to_owned();
    for marker in MARKERS {
        rendered = rendered.replace(&format!("@{marker}@"), &value(marker));
    }
    assert!(!rendered.contains("@AWS@") && !rendered.contains("@GENERIC@"));
    rendered
}

/// Columns count from 1 on the first line and from the preceding LF on
/// later lines; the end column is the column of the last byte.
fn location(text: &[u8], start: usize, end: usize) -> Location {
    let before = &text[..start];
    let line = count_lf(before);
    let column = before
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(start + 1, |lf| start - lf + 1);
    Location::new(line, line, column, column + (end - start) - 1).unwrap()
}

fn count_lf(bytes: &[u8]) -> usize {
    bytes.iter().map(|byte| usize::from(*byte == b'\n')).sum()
}

fn scan(path: &str, text: &str) -> Vec<Finding> {
    let fragment = Fragment::builder(text.as_bytes()).file_path(path).build();
    let outcome = engine().scan_fragment(
        &fragment,
        &ScanOptions::builder().max_decode_depth(5).build(),
    );
    assert!(outcome.is_complete());
    outcome.findings().to_vec()
}

#[test]
fn every_language_fixture_reports_exactly_its_planted_tokens() {
    assert_eq!(FIXTURES.len(), 23);
    for fixture in FIXTURES {
        let text = render(fixture.text);
        let mut findings = scan(fixture.path, &text);
        findings.sort_by_key(|finding| {
            let location = finding.location();
            (location.start_line(), location.start_column())
        });
        let actual = findings
            .iter()
            .map(|finding| {
                (
                    String::from_utf8_lossy(finding.rule_id().as_bytes()).into_owned(),
                    String::from_utf8_lossy(finding.secret().as_bytes()).into_owned(),
                    String::from_utf8_lossy(finding.match_text().as_bytes()).into_owned(),
                    finding.location(),
                )
            })
            .collect::<Vec<_>>();
        let expected = fixture
            .expected
            .iter()
            .map(|(rule, marker, before, after)| {
                let secret = value(marker);
                let at = text.find(&secret).unwrap();
                assert_eq!(text.matches(&secret).count(), 1, "{}", fixture.language);
                assert_eq!(
                    &text[at - before.len()..at],
                    *before,
                    "{}",
                    fixture.language
                );
                let start = at - before.len();
                let end = at + secret.len() + after.len();
                (
                    (*rule).to_owned(),
                    secret,
                    text[start..end].to_owned(),
                    location(text.as_bytes(), start, end),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{}", fixture.language);
    }
}

#[test]
fn placeholder_values_in_every_language_fixture_report_nothing() {
    for fixture in FIXTURES {
        let mut text = fixture.text.to_owned();
        for marker in MARKERS {
            text = text.replace(&format!("@{marker}@"), "${CHANGE_ME}");
        }
        assert!(scan(fixture.path, &text).is_empty(), "{}", fixture.language);
    }
}
