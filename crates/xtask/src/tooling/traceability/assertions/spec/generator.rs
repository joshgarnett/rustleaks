//! Assertions for the upstream semi-generic and unique-token regex generators.

use std::path::Path;

use super::super::{Json, boolean, object, record, source_lines, strings, text};

type SemiGroup<'a> = (
    &'a str,
    &'a str,
    usize,
    usize,
    &'a [bool],
    &'a [&'a str],
    &'a [&'a str],
    &'a [&'a str],
);
type UniqueGroup<'a> = (
    &'a str,
    &'a str,
    usize,
    usize,
    bool,
    &'a [&'a str],
    &'a [&'a str],
);

pub(super) fn add_generator_rows(upstream: &Path, rows: &mut Vec<Json>) -> Result<(), String> {
    add_semi_generic_rows(upstream, rows)?;
    add_unique_token_rows(upstream, rows)
}

// Keeping this pinned upstream table contiguous makes source-line and sample drift reviewable.
#[allow(clippy::too_many_lines)]
fn add_semi_generic_rows(upstream: &Path, rows: &mut Vec<Json>) -> Result<(), String> {
    let source = "cmd/generate/config/utils/generate_test.go";
    let semi: &[SemiGroup<'_>] = &[
        (
            "G01",
            "TM-0022",
            16,
            23,
            &[false],
            &["api_key=xxx"],
            &["api_key=XXX", "api_key=xXx"],
            &["api_key"],
        ),
        (
            "G02",
            "TM-0021",
            24,
            31,
            &[true],
            &["api_key=xxx", "api_key=XXX", "api_key=xXx"],
            &["api_key=x!x"],
            &["api_key"],
        ),
        (
            "G03",
            "TM-0019",
            32,
            39,
            &[true, false],
            &["api_key=xxx", "ApI_KeY=xxx", "aPi_kEy=xxx", "API_KEY=xxx"],
            &["api!key=xxx"],
            &["api_key"],
        ),
        (
            "G04",
            "TM-0017",
            40,
            47,
            &[true, false],
            &[
                "apikey=xxx",
                "ApiKey=xxx",
                "Apikey=xxx",
                "APIKEY=xxx",
                "api_key=xxx",
            ],
            &["ApIKeY=xxx", "aPikEy=xxx"],
            &["(?-i:[Aa]pi_?[Kk]ey|API_?KEY)"],
        ),
        (
            "G05",
            "TM-0018",
            48,
            55,
            &[true, false],
            &[
                "mykey=xxx",
                "keys=xxx",
                "key1=xxx",
                "keystore=xxx",
                "monkey=xxx",
            ],
            &[],
            &["key"],
        ),
        (
            "G06",
            "TM-0020",
            56,
            80,
            &[true, false],
            &[
                "api_key-----=xxx",
                "api_key.....=xxx",
                "api_key_____=xxx",
                "'''api_key'''=xxx",
                "\"\"\"api_key\"\"\"=xxx",
                "api_key          =xxx",
                "api_key\t\t\t\t\t=xxx",
                "api_key\n\n\n=xxx",
                "api_key\r\n=xxx",
            ],
            &[
                "api_key&=xxx",
                "$api_key$=xxx",
                "%api_key%=xxx",
                "api_key[0]=xxx",
                "api_key/*REMOVE*/=xxx",
            ],
            &["api_key"],
        ),
        (
            "G07",
            "TM-0016",
            81,
            106,
            &[true, false],
            &[
                "api_key=xxx",
                "api_key: xxx",
                "<api_key>xxx",
                "api_key:=xxx",
                "api_key:::=xxx",
                "api_key => xxx",
                "api_key ?= xxx",
                "api_key, xxx",
            ],
            &[
                "api_keyxxx",
                "api_key\txxx",
                "api_key; xxx",
                "api_key<xxx>",
                "api_key&xxx",
                "api_key = true ? 'xxx' : 'yyy'",
            ],
            &["api_key"],
        ),
        (
            "G08",
            "TM-0023",
            107,
            139,
            &[true, false],
            &[
                "api_key=    xxx ",
                "api_key=xxx\n",
                "api_key=xxx\r\n",
                "api_key=\n\n\n\n\nxxx",
                "api_key=\r\n\r\nxxx",
                "api_key=\t\t\t\txxx\t",
                "api_key======xxx;",
                "api_key='''xxx'''",
                "api_key=\"\"\"xxx\"\"\"",
                "api_key=```xxx```",
                "api_key=\"xxx'",
                "api_key=\"don't do it!\"",
                "api_key=\"xxx;notpartofthematch\"",
            ],
            &[
                "api_key=_xxx",
                "api_key=xxx_",
                "api_key=$xxx",
                "api_key=%xxx%",
                "api_key=[xxx]",
                "api_key=(xxx)",
                "api_key=<xxx>",
                "api_key={xxx}",
                "<api_key>xxx</api_key>",
                "example.com?api_key=xxx&other=yyy",
            ],
            &["api_key"],
        ),
    ];
    for (group, parent, first, last, flags, matches, nonmatches, identifiers) in semi {
        add_sample_group(
            upstream,
            rows,
            &format!("AS-GEN-SG-{group}"),
            parent,
            source,
            *first,
            *last,
            "regex-generator-semi-generic",
            "GenerateSemiGenericRegex",
            &object([
                ("identifiers", strings(identifiers)),
                ("secret_regex", text("[a-z]{3}")),
            ]),
            flags,
            matches,
            nonmatches,
        )?;
    }
    Ok(())
}

fn add_unique_token_rows(upstream: &Path, rows: &mut Vec<Json>) -> Result<(), String> {
    let source = "cmd/generate/config/utils/generate_test.go";
    let unique: &[UniqueGroup<'_>] = &[
        ("G01", "TM-0027", 173, 179, false, &["abc"], &["ABC", "Abc"]),
        (
            "G02",
            "TM-0026",
            180,
            186,
            true,
            &["abc", "ABC", "Abc"],
            &["123"],
        ),
        (
            "G03",
            "TM-0025",
            187,
            213,
            false,
            &[
                "abc",
                " abc ",
                "\nabc\n",
                "\r\nabc\r\n",
                "\tabc\t",
                "'abc'",
                "\"abc\"",
                "```abc```",
                "my abc's",
                ".com?abc",
            ],
            &[
                "abcabc",
                "_abc_",
                ".com?abc&def",
                "/*abc*/",
                "<abc>",
                "<str>abc</str>",
                "{{{abc}}}",
                "abc, d",
            ],
        ),
    ];
    for (group, parent, first, last, flag, matches, nonmatches) in unique {
        add_sample_group(
            upstream,
            rows,
            &format!("AS-GEN-UT-{group}"),
            parent,
            source,
            *first,
            *last,
            "regex-generator-unique-token",
            "GenerateUniqueTokenRegex",
            &object([("secret_regex", text("[a-c]{3}"))]),
            &[*flag],
            matches,
            nonmatches,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_sample_group(
    upstream: &Path,
    rows: &mut Vec<Json>,
    prefix: &str,
    parent: &str,
    source: &str,
    first: usize,
    last: usize,
    domain: &str,
    operation: &str,
    setup: &Json,
    flags: &[bool],
    matches: &[&str],
    nonmatches: &[&str],
) -> Result<(), String> {
    let samples = matches
        .iter()
        .chain(nonmatches.iter())
        .copied()
        .collect::<Vec<_>>();
    let lines = source_lines(upstream, source, first, last, &samples)?;
    for (flag_index, flag) in flags.iter().enumerate() {
        for (kind, values, expected, offset) in [
            ("M", matches, true, 0),
            ("N", nonmatches, false, matches.len()),
        ] {
            for (index, sample) in values.iter().enumerate() {
                let Json::Object(mut input) = setup.to_owned() else {
                    unreachable!()
                };
                input.push(("operation".into(), text(operation)));
                input.push(("case_insensitive".into(), boolean(*flag)));
                input.push(("sample".into(), text(*sample)));
                rows.push(record(
                    &format!(
                        "{prefix}-CI{}-{kind}-{:02}",
                        if *flag { "T" } else { "F" },
                        index + 1
                    ),
                    parent,
                    source,
                    lines[offset + index],
                    &format!(
                        "{}[{index}];isCaseInsensitive[{flag_index}]",
                        if kind == "M" {
                            "validStrings"
                        } else {
                            "invalidStrings"
                        }
                    ),
                    domain,
                    "public-api",
                    Json::Object(input),
                    object([("kind", text("bool")), ("value", boolean(expected))]),
                    Vec::new(),
                ));
            }
        }
    }
    Ok(())
}
