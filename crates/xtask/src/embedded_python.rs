//! Runs the embedded Python programs of `compare`, `compare-quality` and
//! `compare-workloads`.
//!
//! Each program is Python 3.9 standard-library code: `embedded_python/support.py`
//! followed by the modules of one tool. All modules run in one global
//! namespace with `__name__` set to `'__main__'`, and the last module starts
//! the tool. The program runs with `python3 -I -`, so it needs no installed
//! package and ignores Python environment variables. It is written to
//! standard input, not passed as an argument, because it is larger than some
//! platforms allow for one command-line argument. Each module keeps its own
//! file name, so tracebacks name the module and line.

use std::env;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::tooling::sha256_bytes;

/// The module that every program runs first.
pub(crate) const SUPPORT: (&str, &str) = (
    "embedded_python/support.py",
    include_str!("embedded_python/support.py"),
);

/// One embedded tool: its modules in load order, as (path, source) pairs.
pub(crate) struct Program {
    pub(crate) modules: &'static [(&'static str, &'static str)],
}

impl Program {
    /// Every module of the program, starting with [`SUPPORT`].
    pub(crate) fn sources(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        std::iter::once(SUPPORT).chain(self.modules.iter().copied())
    }

    /// SHA-256 over every module path and source, in load order.
    pub(crate) fn sha256(&self) -> String {
        let mut joined = Vec::new();
        for (name, text) in self.sources() {
            joined.extend_from_slice(name.as_bytes());
            joined.push(0);
            joined.extend_from_slice(text.as_bytes());
            joined.push(0);
        }
        sha256_bytes(&joined)
    }

    /// Builds the program text. `globals` are string constants that the
    /// modules can read, such as a source digest.
    fn bootstrap(&self, globals: &[(&str, String)]) -> String {
        let sources = serde_json::to_string(&self.sources().collect::<Vec<_>>())
            .expect("module table serializes");
        let globals = serde_json::to_string(
            &globals
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .expect("globals serialize");
        format!(
            "import base64, json\n\
             _modules = json.loads(base64.b64decode('{}').decode('utf-8'))\n\
             _namespace = {{'__name__': '__main__', '__builtins__': __builtins__}}\n\
             _namespace.update(json.loads(base64.b64decode('{}').decode('utf-8')))\n\
             for _name, _text in _modules:\n\
             \x20   exec(compile(_text, _name, 'exec'), _namespace)\n",
            STANDARD.encode(sources),
            STANDARD.encode(globals),
        )
    }

    /// Returns `python3 -I - ARGUMENTS`. Under `bazelisk run`, the command
    /// runs in the folder where the user started it, so relative paths work.
    pub(crate) fn command<S: AsRef<std::ffi::OsStr>>(arguments: &[S]) -> Command {
        let mut command = Command::new("python3");
        command
            .args(["-I", "-"])
            .args(arguments)
            .stdin(Stdio::piped());
        if let Some(directory) =
            env::var_os("BUILD_WORKING_DIRECTORY").filter(|value| !value.is_empty())
        {
            command.current_dir(directory);
        }
        command
    }

    /// Runs `command` with this program on its standard input. Python reads
    /// the whole program before it starts, so closing the pipe after the
    /// write cannot block. Output is captured only when `capture` is set.
    pub(crate) fn run(
        &self,
        mut command: Command,
        globals: &[(&str, String)],
        capture: bool,
    ) -> Result<Output, String> {
        if capture {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot start python3 (3.9 or newer): {error}"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or("python3 standard input is not available")?;
        let written = stdin.write_all(self.bootstrap(globals).as_bytes());
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|error| format!("cannot wait for python3: {error}"))?;
        written.map_err(|error| format!("cannot write the program to python3: {error}"))?;
        Ok(output)
    }
}

/// Returns the `--source-root ROOT` arguments that compare-quality and
/// compare-workloads read.
pub(crate) fn source_root_arguments(root: &Path) -> [std::ffi::OsString; 2] {
    ["--source-root".into(), root.as_os_str().to_owned()]
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULES: &[(&str, &str)] = &[
        ("demo/one.py", "VALUE = sha256_bytes(b'') + GREETING\n"),
        (
            "demo/two.py",
            "import sys\nprint(VALUE[-5:], __name__, sys.argv[1:])\n",
        ),
    ];

    #[test]
    fn program_is_not_a_command_line_argument() {
        let lengths = Program::command(&["x"])
            .get_args()
            .map(std::ffi::OsStr::len)
            .collect::<Vec<_>>();
        assert_eq!(lengths, [2, 1, 1]);
    }

    #[test]
    fn digest_covers_support_and_every_module() {
        let program = Program { modules: MODULES };
        let names = program.sources().map(|(name, _)| name).collect::<Vec<_>>();
        assert_eq!(names, [SUPPORT.0, "demo/one.py", "demo/two.py"]);
        let other = Program {
            modules: &MODULES[..1],
        };
        assert_ne!(program.sha256(), other.sha256());
    }

    #[cfg(unix)]
    #[test]
    fn modules_share_one_namespace_after_support() {
        let program = Program { modules: MODULES };
        let output = program
            .run(
                Program::command(&["a", "b"]),
                &[("GREETING", "hello".to_owned())],
                true,
            )
            .expect("python3 runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"hello __main__ ['a', 'b']\n");
    }
}
