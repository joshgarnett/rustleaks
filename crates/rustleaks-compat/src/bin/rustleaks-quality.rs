#![forbid(unsafe_code)]
//! Evaluates the maintained synthetic detection-quality corpus.

use std::path::{Path, PathBuf};
use std::{env, fs, io};

use rustleaks_compat::evaluation::{check_generated_corpus, evaluate_corpus, generated_corpus};

fn maintained_path(name: &str) -> PathBuf {
    env::var_os("BUILD_WORKSPACE_DIRECTORY")
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join("compat/quality-corpus")
        .join(name)
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    use io::Read as _;
    let file = fs::File::open(path).map_err(|_| "cannot open quality input")?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read quality input")?;
    if bytes.len() > 1024 * 1024 {
        return Err("quality input exceeds 1 MiB".into());
    }
    Ok(bytes)
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|_| "cannot write quality output".into())
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    let corpus_path = maintained_path("cases-v1.json");
    let baseline_path = maintained_path("baseline-v1.json");
    match arguments.as_slice() {
        [] => evaluate(&corpus_path, true),
        [command] if command == "generate" => write(&corpus_path, &generated_corpus()?),
        [command] if command == "check" => check_generated_corpus(&read(&corpus_path)?),
        [command] if command == "evaluate" => evaluate(&corpus_path, true),
        [command, path] if command == "evaluate" => evaluate(Path::new(path), false),
        [command] if matches!(command.as_str(), "baseline" | "check-baseline") => {
            let corpus = read(&corpus_path)?;
            check_generated_corpus(&corpus)?;
            let baseline = evaluate_corpus(&corpus)?;
            if command == "baseline" {
                write(&baseline_path, &baseline)
            } else if read(&baseline_path)? == baseline {
                Ok(())
            } else {
                Err("quality baseline differs from the current corpus and evaluator".into())
            }
        }
        _ => Err(
            "usage: rustleaks-quality {generate|check|evaluate [CORPUS]|baseline|check-baseline}"
                .into(),
        ),
    }
}

fn evaluate(path: &Path, maintained: bool) -> Result<(), String> {
    use io::Write as _;
    let bytes = read(path)?;
    if maintained {
        check_generated_corpus(&bytes)?;
    }
    io::stdout()
        .lock()
        .write_all(&evaluate_corpus(&bytes)?)
        .map_err(|_| "cannot write quality report".into())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
