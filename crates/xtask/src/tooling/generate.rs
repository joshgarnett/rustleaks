//! Command presentation for Rust-owned repository generators.

use std::path::Path;

use super::{
    Corpus, check_api_dispositions, check_assertions, generate_corpus, generate_go_lowercase,
    generate_regex_fuzz_seeds, self_test_api_dispositions, summarize_api_dispositions,
    write_api_dispositions, write_assertions, write_composite_corpus, write_config_corpus,
    write_git_corpus, write_report_corpus, write_session_corpus, write_source_corpus,
};

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    if let Some(result) = run_traceability(root, args) {
        return result;
    }
    if let Some(result) = run_repository_artifact(root, args) {
        return result;
    }
    run_direct_oracle(root, args)
}

fn run_repository_artifact(root: &Path, args: &[String]) -> Option<Result<(), String>> {
    match args {
        [target] if target == "go-lowercase" => Some(generate_go_lowercase(root, false)),
        [target, flag] if target == "go-lowercase" && flag == "--check" => {
            Some(generate_go_lowercase(root, true))
        }
        [target] if target == "config" => Some(write_config_corpus(
            root,
            &root.join("compat/config-corpus"),
        )),
        [target, flag] if target == "config" && flag == "--check" => {
            Some(super::check_config_corpus(root))
        }
        [target, flag, output] if target == "config" && flag == "--output" => {
            Some(write_config_corpus(root, Path::new(output)))
        }
        [target] if target == "composite" => Some(write_composite_corpus(
            root,
            &root.join("compat/composite-corpus"),
        )),
        [target, flag] if target == "composite" && flag == "--check" => {
            Some(super::check_composite_corpus(root))
        }
        [target, flag, output] if target == "composite" && flag == "--output" => {
            Some(write_composite_corpus(root, Path::new(output)))
        }
        [target] if target == "report" => Some(write_report_corpus(
            root,
            &root.join("compat/report-corpus"),
        )),
        [target, flag] if target == "report" && flag == "--check" => {
            Some(super::check_report_corpus(root))
        }
        [target, flag, output] if target == "report" && flag == "--output" => {
            Some(write_report_corpus(root, Path::new(output)))
        }
        [target] if target == "session" => Some(write_session_corpus(
            root,
            &root.join("compat/session-corpus"),
        )),
        [target, flag] if target == "session" && flag == "--check" => {
            Some(super::check_session_corpus(root))
        }
        [target, flag, output] if target == "session" && flag == "--output" => {
            Some(write_session_corpus(root, Path::new(output)))
        }
        [target] if target == "source" => Some(write_source_corpus(
            root,
            &root.join("compat/source-corpus"),
        )),
        [target, flag] if target == "source" && flag == "--check" => {
            Some(super::check_source_corpus(root))
        }
        [target, flag, output] if target == "source" && flag == "--output" => {
            Some(write_source_corpus(root, Path::new(output)))
        }
        [target] if target == "git" => {
            Some(write_git_corpus(root, &root.join("compat/git-corpus")))
        }
        [target, flag] if target == "git" && flag == "--check" => {
            Some(super::check_git_corpus(root))
        }
        [target, flag, output] if target == "git" && flag == "--output" => {
            Some(write_git_corpus(root, Path::new(output)))
        }
        _ => None,
    }
}

fn run_traceability(root: &Path, args: &[String]) -> Option<Result<(), String>> {
    let canonical_api = root.join("compat/api-dispositions-v1.jsonl");
    match args {
        [target] if target == "assertions" => Some(upstream(root).and_then(|upstream| {
            write_assertions(root, &upstream, &root.join("compat/assertion-corpus")).map(|_| ())
        })),
        [target, flag] if target == "assertions" && flag == "--check" => {
            Some(upstream(root).and_then(|upstream| {
                check_assertions(root, &upstream, &root.join("compat/assertion-corpus")).map(|_| ())
            }))
        }
        [target, flag, output] if target == "assertions" && flag == "--output" => {
            Some(upstream(root).and_then(|upstream| {
                write_assertions(root, &upstream, Path::new(output)).map(|_| ())
            }))
        }
        [target, flag, output] if target == "assertions" && flag == "--check-output" => {
            Some(upstream(root).and_then(|upstream| {
                check_assertions(root, &upstream, Path::new(output)).map(|_| ())
            }))
        }
        [target] if target == "api-dispositions" => {
            Some(print_result(write_api_dispositions(root, &canonical_api)))
        }
        [target, flag] if target == "api-dispositions" && flag == "--check" => {
            Some(print_result(check_api_dispositions(root, &canonical_api)))
        }
        [target, flag] if target == "api-dispositions" && flag == "--self-test" => Some(
            print_result(self_test_api_dispositions(root, &canonical_api)),
        ),
        [target, flag] if target == "api-dispositions" && flag == "--summary" => Some(
            print_result(summarize_api_dispositions(root, &canonical_api)),
        ),
        [target, flag, output] if target == "api-dispositions" && flag == "--output" => Some(
            print_result(write_api_dispositions(root, Path::new(output))),
        ),
        _ => None,
    }
}

fn run_direct_oracle(root: &Path, args: &[String]) -> Result<(), String> {
    match args {
        [target] if Corpus::from_name(target).is_some() => {
            let corpus = Corpus::from_name(target).expect("guarded corpus name");
            generate_corpus(
                root,
                corpus,
                &root
                    .join("compat")
                    .join(format!("{}-corpus", corpus.name())),
                false,
            )
        }
        [target, flag] if Corpus::from_name(target).is_some() && flag == "--check" => {
            let corpus = Corpus::from_name(target).expect("guarded corpus name");
            generate_corpus(
                root,
                corpus,
                &root
                    .join("compat")
                    .join(format!("{}-corpus", corpus.name())),
                true,
            )
        }
        [target, flag, output]
            if Corpus::from_name(target).is_some() && flag == "--output" =>
        {
            generate_corpus(
                root,
                Corpus::from_name(target).expect("guarded corpus name"),
                Path::new(output),
                false,
            )
        }
        [target, requests, output] if target == "regex-fuzz-seeds" => {
            generate_regex_fuzz_seeds(Path::new(requests), Path::new(output)).map(|count| {
                println!("wrote {count} GoRegex seeds to {output}");
            })
        }
        _ => Err(
            "usage: cargo xtask generate <go-lowercase [--check]|api-dispositions [--check|--self-test|--summary|--output PATH]|assertions [--check|--output PATH|--check-output PATH]|config|composite|regex|detect|allowlist|decoder|session|source|git|report [--check|--output PATH]|regex-fuzz-seeds REQUESTS OUTPUT>"
                .into(),
        ),
    }
}

fn upstream(root: &Path) -> Result<std::path::PathBuf, String> {
    root.parent()
        .map(|parent| parent.join("gitleaks"))
        .ok_or_else(|| format!("repository root {} has no parent", root.display()))
}

fn print_result(result: Result<String, String>) -> Result<(), String> {
    result.map(|output| print!("{output}"))
}
