#![forbid(unsafe_code)]
//! Thin command-line consumer of Rustleaks libraries with legacy CLI aliases.

use rustleaks_cli::{RunEnvironment, run_from};

fn main() {
    let environment = RunEnvironment::from_process();
    let code = run_from(
        std::env::args_os().skip(1),
        environment,
        std::io::stdin(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(code);
}
