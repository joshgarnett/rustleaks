//! Command presentation for Rust-owned repository generators.

use std::path::Path;

use super::{
    Corpus, check_assertions, generate_corpus, generate_go_lowercase, generate_regex_fuzz_seeds,
    write_assertions, write_config_corpus, write_report_corpus, write_session_corpus,
    write_source_corpus,
};

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    match args {
        [target] if target == "go-lowercase" => generate_go_lowercase(root, false),
        [target, flag] if target == "go-lowercase" && flag == "--check" => {
            generate_go_lowercase(root, true)
        }
        [target] if target == "config" => {
            write_config_corpus(root, &root.join("compat/config-corpus"))
        }
        [target, flag] if target == "config" && flag == "--check" => {
            super::check_config_corpus(root)
        }
        [target, flag, output] if target == "config" && flag == "--output" => {
            write_config_corpus(root, Path::new(output))
        }
        [target] if target == "report" => {
            write_report_corpus(root, &root.join("compat/report-corpus"))
        }
        [target, flag] if target == "report" && flag == "--check" => {
            super::check_report_corpus(root)
        }
        [target, flag, output] if target == "report" && flag == "--output" => {
            write_report_corpus(root, Path::new(output))
        }
        [target] if target == "session" => {
            write_session_corpus(root, &root.join("compat/session-corpus"))
        }
        [target, flag] if target == "session" && flag == "--check" => {
            super::check_session_corpus(root)
        }
        [target, flag, output] if target == "session" && flag == "--output" => {
            write_session_corpus(root, Path::new(output))
        }
        [target] if target == "source" => {
            write_source_corpus(root, &root.join("compat/source-corpus"))
        }
        [target, flag] if target == "source" && flag == "--check" => {
            super::check_source_corpus(root)
        }
        [target, flag, output] if target == "source" && flag == "--output" => {
            write_source_corpus(root, Path::new(output))
        }
        [target] if target == "assertions" => {
            let upstream = upstream(root)?;
            write_assertions(root, &upstream, &root.join("compat/assertion-corpus")).map(|_| ())
        }
        [target, flag] if target == "assertions" && flag == "--check" => {
            let upstream = upstream(root)?;
            check_assertions(root, &upstream, &root.join("compat/assertion-corpus")).map(|_| ())
        }
        [target, flag, output] if target == "assertions" && flag == "--output" => {
            write_assertions(root, &upstream(root)?, Path::new(output)).map(|_| ())
        }
        [target, flag, output] if target == "assertions" && flag == "--check-output" => {
            check_assertions(root, &upstream(root)?, Path::new(output)).map(|_| ())
        }
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
            "usage: cargo xtask generate <go-lowercase [--check]|assertions [--check|--output PATH|--check-output PATH]|config|regex|detect|allowlist|decoder|session|source|report [--check|--output PATH]|regex-fuzz-seeds REQUESTS OUTPUT>"
                .into(),
        ),
    }
}

fn upstream(root: &Path) -> Result<std::path::PathBuf, String> {
    root.parent()
        .map(|parent| parent.join("gitleaks"))
        .ok_or_else(|| format!("repository root {} has no parent", root.display()))
}
