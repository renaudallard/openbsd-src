# OpenBSD Userland Fuzzing

Automated fuzzing of OpenBSD userland programs using AFL++ on GitHub Actions.

Runs daily for ~4 hours in an OpenBSD VM. Corpus state persists between
runs via GitHub Actions cache. Crashes are uploaded as artifacts.

## Structure

- `targets.conf` - fuzzing target definitions
- `scripts/build.sh` - builds programs with AFL++ instrumentation
- `scripts/run.sh` - runs AFL++ with time budget and target rotation
- `scripts/report.sh` - collects crashes and generates summary
- `scripts/issue.sh` - opens GitHub issues for new findings
- `seeds/` - initial seed corpora per target

## Adding a target

Add a line to `targets.conf`:

    name:srcdir:seeds:args:status

- `name` - target identifier
- `srcdir` - source directory relative to repository root
- `seeds` - seed corpus directory under `seeds/`
- `args` - program arguments (`@@` = AFL input file, absent = stdin)
- `status` - optional: `skip` (don't build/fuzz), `reported`, `ubsan_only`,
  `false_positive`

Create a seed corpus in `seeds/<name>/` with at least one small file.

## Crash triage

`scripts/issue.sh` classifies findings by signal. SIGSEGV, SIGABRT,
SIGBUS and SIGFPE are genuine crashes and open a `crash (SIGxxx)` issue.
SIGILL is filed separately as a `UBSan trap (SIGILL)` issue: the build
uses `-fsanitize=undefined`, and because the full UBSan runtime is
unavailable on OpenBSD the compiler traps undefined behaviour with
SIGILL instead of logging and recovering, so such findings are usually
undefined behaviour on trusted input rather than memory-safety bugs.
Once a UBSan trap is triaged and judged benign, mark the target
`ubsan_only` in `targets.conf` so it stops being reported.

## Running locally

On an OpenBSD system with `afl++` installed:

    pkg_add afl++
    cd fuzz
    sh scripts/build.sh
    sh scripts/run.sh 3600
    sh scripts/report.sh

Build a single target:

    sh scripts/build.sh awk

## Target rotation

With ~170 targets and a 15-minute minimum per target, not all targets
fit in a single run. The runner selects a rotating subset each day,
cycling through all targets over multiple runs.
