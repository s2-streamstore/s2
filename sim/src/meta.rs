//! Determinism meta-test: run the same simulation twice and require
//! byte-identical output.
//!
//! Spawns this binary as two concurrent child processes with identical
//! arguments, each in its own temp directory, and compares stdout/stderr in a
//! streaming fashion: dedicated threads read both pipes in lockstep, one line
//! at a time, so memory stays constant regardless of output volume (trace
//! logging produces tens of MB). On the first divergence both child processes
//! are terminated immediately. Exit statuses and any produced `history.*.jsonl` files
//! are compared as well.
//!
//! Log lines use simulated time rather than wall-clock time (see
//! `SimStepTimeFormat`), so no normalization is needed.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
};

use eyre::{WrapErr, bail, ensure, eyre};
use tracing::info;

#[derive(clap::Args, Debug)]
pub struct MetaArgs {
    /// Arguments to run the child simulations with, passed through verbatim
    /// (e.g. `sim meta linearizable --seed 42`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub args: Vec<String>,
}

pub fn run(meta: MetaArgs, seed: u64, fail_rate: f64) -> eyre::Result<()> {
    let exe = std::env::current_exe()?;
    let base = std::env::temp_dir().join(format!("s2-sim-meta-{}", std::process::id()));

    // Global flags given before `meta` are consumed by our own parser; forward
    // them to the children unless the trailing args already specify them.
    let mut args = meta.args;
    for (flag, value) in [
        ("--seed", seed.to_string()),
        ("--fail-rate", fail_rate.to_string()),
    ] {
        if !args
            .iter()
            .any(|a| a == flag || a.starts_with(&format!("{flag}=")))
        {
            args.extend([flag.to_string(), value]);
        }
    }

    let dir_a = base.join("a");
    let dir_b = base.join("b");
    fs::create_dir_all(&dir_a)?;
    fs::create_dir_all(&dir_b)?;

    info!(?args, "running both child simulations concurrently");
    let mut child_a = spawn_child(&exe, &args, &dir_a)?;
    let mut child_b = spawn_child(&exe, &args, &dir_b)?;

    // Each thread compares one stream pair and reports its result as soon as
    // it finishes — which is early, on the first mismatch. The other side may
    // then be blocked on a full pipe; terminating the child processes
    // unblocks it.
    type ChildOutput = Box<dyn Read + Send>;
    let (results_tx, results_rx) = mpsc::channel();
    let streams: [(&'static str, ChildOutput, ChildOutput); 2] = [
        (
            "stdout",
            Box::new(pipe(child_a.stdout.take())?),
            Box::new(pipe(child_b.stdout.take())?),
        ),
        (
            "stderr",
            Box::new(pipe(child_a.stderr.take())?),
            Box::new(pipe(child_b.stderr.take())?),
        ),
    ];
    for (name, pipe_a, pipe_b) in streams {
        let results_tx = results_tx.clone();
        std::thread::spawn(move || {
            let _ = results_tx.send(compare_streams(name, pipe_a, pipe_b));
        });
    }
    drop(results_tx);

    let mut comparisons = Vec::new();
    let mut killed = false;
    while let Ok(result) = results_rx.recv() {
        let comparison = result?;
        if comparison.first_mismatch.is_some() && !killed {
            child_a.kill().ok();
            child_b.kill().ok();
            killed = true;
        }
        comparisons.push(comparison);
    }
    let status_a = child_a.wait()?;
    let status_b = child_b.wait()?;

    let result = (|| -> eyre::Result<(usize, usize)> {
        for comparison in &comparisons {
            comparison.ensure_identical()?;
        }
        ensure!(
            status_a == status_b,
            "exit status differs: {status_a} vs {status_b}"
        );
        ensure!(status_a.success(), "child simulations failed ({status_a})");
        compare_history_files(&dir_a, &dir_b)
    })();

    match &result {
        Ok((history_files, history_lines)) => {
            fs::remove_dir_all(&base).ok();
            let lines = |name| {
                comparisons
                    .iter()
                    .find(|c| c.name == name)
                    .map_or(0, |c| c.lines)
            };
            info!(
                stdout_lines = lines("stdout"),
                stderr_lines = lines("stderr"),
                history_files,
                history_lines,
                "deterministic: both runs produced identical output"
            );
            Ok(())
        }
        Err(err) => {
            tracing::error!("determinism violated: {err}");
            fs::remove_dir_all(&base).ok();
            result.map(|_| ())
        }
    }
}

fn spawn_child(exe: &Path, args: &[String], dir: &Path) -> eyre::Result<Child> {
    Command::new(exe)
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .wrap_err("failed to spawn child simulation")
}

fn pipe<T>(pipe: Option<T>) -> eyre::Result<T> {
    pipe.ok_or_else(|| eyre!("missing child pipe"))
}

struct StreamComparison {
    name: &'static str,
    first_mismatch: Option<Mismatch>,
    /// Lines read from the first stream.
    lines: usize,
}

struct Mismatch {
    line: usize,
    a: String,
    b: String,
}

impl StreamComparison {
    fn ensure_identical(&self) -> eyre::Result<()> {
        if let Some(m) = &self.first_mismatch {
            bail!(
                "{} differs at line {}:\n  a: {}\n  b: {}",
                self.name,
                m.line,
                m.a,
                m.b,
            );
        }
        Ok(())
    }
}

/// Compare two byte streams line by line, in lockstep, returning at the first
/// mismatch (the caller is expected to terminate the producing processes to
/// unblock the remaining stream).
fn compare_streams(
    name: &'static str,
    a: impl Read,
    b: impl Read,
) -> eyre::Result<StreamComparison> {
    let mut a = std::io::BufReader::with_capacity(64 * 1024, a);
    let mut b = std::io::BufReader::with_capacity(64 * 1024, b);
    let mut line_a = Vec::new();
    let mut line_b = Vec::new();
    let mut lines = 0;

    loop {
        line_a.clear();
        line_b.clear();
        let read_a = read_line(&mut a, &mut line_a)?;
        let read_b = read_line(&mut b, &mut line_b)?;
        if read_a == 0 && read_b == 0 {
            break;
        }
        if read_a > 0 {
            lines += 1;
        }
        if line_a != line_b {
            return Ok(StreamComparison {
                name,
                first_mismatch: Some(Mismatch {
                    line: lines,
                    a: preview(&line_a),
                    b: preview(&line_b),
                }),
                lines,
            });
        }
    }

    Ok(StreamComparison {
        name,
        first_mismatch: None,
        lines,
    })
}

fn read_line(reader: &mut impl std::io::BufRead, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    reader.read_until(b'\n', buf)
}

fn preview(line: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(line.strip_suffix(b"\n").unwrap_or(line)).into_owned();
    s.truncate(512);
    s
}

/// Compare `history.*.jsonl` files produced by the two runs, streaming from
/// disk. Returns (file count, total lines).
fn compare_history_files(dir_a: &Path, dir_b: &Path) -> eyre::Result<(usize, usize)> {
    let names_a = history_file_names(dir_a)?;
    let names_b = history_file_names(dir_b)?;
    ensure!(
        names_a == names_b,
        "history file sets differ: {names_a:?} vs {names_b:?}"
    );
    let mut total_lines = 0;
    for name in &names_a {
        let cmp = compare_streams(
            "history",
            File::open(dir_a.join(name))?,
            File::open(dir_b.join(name))?,
        )?;
        cmp.ensure_identical().wrap_err_with(|| name.clone())?;
        total_lines += cmp.lines;
    }
    Ok((names_a.len(), total_lines))
}

fn history_file_names(dir: &Path) -> eyre::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with("history.") && name.ends_with(".jsonl") {
            names.insert(name);
        }
    }
    Ok(names)
}
