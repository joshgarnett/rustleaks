//! Command presentation for Rust-owned repository generators.

use std::path::Path;

use super::{
    Corpus, generate_corpus, generate_go_lowercase, generate_regex_fuzz_seeds, write_report_corpus,
};

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    match args {
        [target] if target == "go-lowercase" => generate_go_lowercase(root, false),
        [target, flag] if target == "go-lowercase" && flag == "--check" => {
            generate_go_lowercase(root, true)
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
            "usage: cargo xtask generate <go-lowercase [--check]|regex|detect|allowlist|decoder|report [--check|--output PATH]|regex-fuzz-seeds REQUESTS OUTPUT>"
                .into(),
        ),
    }
}
