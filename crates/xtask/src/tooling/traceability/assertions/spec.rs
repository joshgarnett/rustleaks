//! Canonical assertion rows recovered from the pinned upstream tests.

#[path = "spec/direct.rs"]
mod direct;
#[path = "spec/generator.rs"]
mod generator;
#[path = "spec/metadata.rs"]
mod metadata;

use std::path::Path;

use super::{Json, boolean, object, record, source_lines, text};

type RegexGroup<'a> = (&'a str, &'a str, usize, usize, &'a [&'a str], &'a [&'a str]);

pub(super) fn build_assertions(upstream: &Path) -> Result<Vec<Json>, String> {
    let mut rows = Vec::new();
    add_base_regex_rows(upstream, &mut rows)?;
    add_base_path_rows(upstream, &mut rows)?;
    generator::add_generator_rows(upstream, &mut rows)?;
    direct::add_direct_rows(&mut rows);
    Ok(rows)
}

// The literal table is the auditable transcription of pinned upstream cases.
#[allow(clippy::too_many_lines)]
fn add_base_regex_rows(upstream: &Path, rows: &mut Vec<Json>) -> Result<(), String> {
    let source = "cmd/generate/config/base/config_test.go";
    let groups: &[RegexGroup<'_>] = &[
        (
            "general-placeholders",
            "TM-0006",
            11,
            15,
            &["true", "True", "false", "False", "null", "NULL"],
            &[],
        ),
        (
            "repeated-characters",
            "TM-0007",
            16,
            21,
            &[
                "aaaaaaaaaaaaaaaaa",
                "BBBBBBBBBBbBBBBBBBbBB",
                "********************",
            ],
            &["aaaaaaaaaaaaaaaaaaabaa", "pas*************d"],
        ),
        (
            "environment-variables",
            "TM-0005",
            22,
            25,
            &["$2", "$GIT_PASSWORD", "${GIT_PASSWORD}", "$password"],
            &["$yP@R.@=ibxI", "$2a6WCust9aE", "${not_complete1"],
        ),
        (
            "ansible",
            "TM-0008",
            26,
            31,
            &[
                "{{ x }}",
                "{{ password }}",
                "{{password}}",
                "{{ data.proxy_password }}",
                "{{ dict1 | ansible.builtin.combine(dict2) }}",
            ],
            &[],
        ),
        (
            "github-actions",
            "TM-0009",
            32,
            45,
            &[
                "${{ env.First_Name }}",
                "${{ env.DAY_OF_WEEK == 'Monday' }}",
                "${{env.JAVA_VERSION}}",
                "${{ github.event.issue.title }}",
                "${{ github.repository == \"Gattocrucco/lsqfitgp\" }}",
                "${{ github.event.pull_request.number || github.ref }}",
                "${{ github.event_name == 'pull_request' && github.event.action == 'unassigned' }}",
                "${{ secrets.SuperSecret }}",
                "${{ vars.JOB_NAME }}",
                "${{ vars.USE_VARIABLES == 'true' }}",
            ],
            &[],
        ),
        (
            "nuget",
            "TM-0010",
            46,
            50,
            &["%MY_PASSWORD%", "%password%"],
            &[],
        ),
        (
            "go-fmt",
            "TM-0011",
            51,
            55,
            &[
                "%b", "%c", "%d", "% d", "%e", "%E", "%f", "%F", "%g", "%G", "%o", "%O", "%p",
                "%q", "%-s", "%s", "%t", "%T", "%U", "%#U", "%+v", "%#v", "%v", "%x", "%X",
            ],
            &[],
        ),
        ("python-fmt", "TM-0012", 56, 60, &["{}", "{0}", "{10}"], &[]),
        (
            "ucd",
            "TM-0013",
            61,
            64,
            &["@password@", "@LDAP_PASS@"],
            &["@username@mastodon.example"],
        ),
        (
            "file-paths",
            "TM-0014",
            65,
            73,
            &[
                "/Users/james/Projects/SwiftCode/build/Release",
                "/tmp/screen-exchange",
            ],
            &[],
        ),
    ];
    for (slug, parent, first, last, allowed, denied) in groups {
        let values = allowed
            .iter()
            .chain(denied.iter())
            .copied()
            .collect::<Vec<_>>();
        let lines = source_lines(upstream, source, *first, *last, &values)?;
        for (kind, samples, expected, class, offset) in [
            ("A", *allowed, true, "invalid", 0),
            ("N", *denied, false, "valid", allowed.len()),
        ] {
            for (index, sample) in samples.iter().enumerate() {
                rows.push(record(
                    &format!("AS-BASE-RX-{slug}-{kind}-{:02}", index + 1),
                    parent,
                    source,
                    lines[offset + index],
                    &format!("{class}[{index}]"),
                    "config-global-allowlist-regex",
                    "public-api",
                    object([
                        ("operation", text("RegexAllowed")),
                        ("sample", text(*sample)),
                        ("source_class", text(class)),
                    ]),
                    object([("kind", text("bool")), ("value", boolean(expected))]),
                    Vec::new(),
                ));
            }
        }
    }
    Ok(())
}

fn add_base_path_rows(upstream: &Path, rows: &mut Vec<Json>) -> Result<(), String> {
    let source = "cmd/generate/config/base/config_test.go";
    let groups: &[(&str, &str, usize, usize, &[&str])] = &[
        (
            "javascript",
            "TM-0002",
            124,
            136,
            &[
                "tests/e2e/nuget/wwwroot/lib/bootstrap/dist/js/bootstrap.esm.min.js",
                "src/main/static/lib/angular.1.2.16.min.js",
                "src/main/resources/static/jquery-ui-1.12.1/jquery-ui-min.js",
                "src/main/resources/static/js/jquery-ui-1.10.4.min.js",
                "src-static/js/plotly.min.js",
                "swagger/swaggerui/swagger-ui-bundle.js.map",
                "swagger/swaggerui/swagger-ui-es-bundle.js.map",
                "src/main/static/swagger-ui.min.js",
                "swagger/swaggerui/swagger-ui.js",
            ],
        ),
        (
            "python",
            "TM-0003",
            137,
            158,
            &[
                "Pipfile.lock",
                "poetry.lock",
                "env/lib/python3.7/site-packages/urllib3/util/url.py",
                "venv/Lib/site-packages/regex-2018.08.29.dist-info/DESCRIPTION.rst",
                "venv/lib64/python3.5/site-packages/pynvml.py",
                "python/python3/virtualenv/Lib/site-packages/pyphonetics/utils.py",
                "virtualenv/lib64/python3.7/base64.py",
                "cde-root/usr/lib64/python2.4/site-packages/Numeric.pth",
                "lib/python3.9/site-packages/setuptools/_distutils/msvccompiler.py",
                "lib/python3.8/site-packages/botocore/data/alexaforbusiness/2017-11-09/service-2.json",
                "code/python/3.7.4/Lib/site-packages/dask/bytes/tests/test_bytes_utils.py",
                "python/3.7.4/Lib/site-packages/fsspec/utils.py",
                "python/2.7.16.32/Lib/bsddb/test/test_dbenv.py",
                "python/lib/python3.8/site-packages/boto3/data/ec2/2016-04-01/resources-1.json",
                "libs/PyX-0.15.dist-info/AUTHORS",
            ],
        ),
    ];
    for (slug, parent, first, last, values) in groups {
        let lines = source_lines(upstream, source, *first, *last, values)?;
        for (index, (line, sample)) in lines.into_iter().zip(values.iter()).enumerate() {
            rows.push(record(
                &format!("AS-BASE-PATH-{slug}-A-{:02}", index + 1),
                parent,
                source,
                line,
                &format!("invalid[{index}]"),
                "config-global-allowlist-path",
                "public-api",
                object([
                    ("operation", text("PathAllowed")),
                    ("sample", text(*sample)),
                    ("source_class", text("invalid")),
                ]),
                object([("kind", text("bool")), ("value", boolean(true))]),
                Vec::new(),
            ));
        }
    }
    Ok(())
}

pub(super) fn build_benchmarks() -> Vec<Json> {
    metadata::build_benchmarks()
}

pub(super) fn build_skips() -> Vec<Json> {
    metadata::build_skips()
}
