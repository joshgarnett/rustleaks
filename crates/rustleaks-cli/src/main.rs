#![forbid(unsafe_code)]
//! The `rustleaks` executable. It runs `rustleaks_cli` with the process environment.

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
