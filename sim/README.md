# s2-sim

Deterministic simulation plumbing for s2-lite.

Basic smoke test:

```bash
just sim smoke --seed 12345
```

Meta-test, which compares the output of two runs of a selected sim and compares logging output. Helpful for determining if determinism has been broken.

```bash
# RUST_LOG determines the logging level of the `smoke` test; trace is most likely to uncover determinism regressions
RUST_LOG=trace just sim meta smoke --seed 12345
```

Collect logs for linearizability testing using [s2-verification](https://github.com/s2-streamstore/s2-verification):

```bash
just sim linearizable --seed 12345

# with `s2-porcupine` from <https://github.com/s2-streamstore/s2-verification> installed:
s2-porcupine -file history.12345.jsonl
```