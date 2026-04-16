#!/bin/sh
# AFL++ fuzzing runner with time budget and target rotation
#
# Usage: sh run.sh [total_seconds] [batch_id] [total_batches]

set -e

SRCROOT="${SRCROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
FUZZDIR="${SRCROOT}/fuzz"
BUILDDIR="${FUZZDIR}/build"
OUTPUTDIR="${FUZZDIR}/output"
SEEDSDIR="${FUZZDIR}/seeds"
LOGSDIR="${FUZZDIR}/logs"
TARGETS="${FUZZDIR}/targets.conf"

TOTAL_SECONDS="${1:-12600}"
BATCH_ID="${2:-0}"
TOTAL_BATCHES="${3:-1}"
MIN_PER_TARGET=900

export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_AUTORESUME=1
export AFL_TESTCACHE_SIZE=100

mkdir -p "$OUTPUTDIR" "$LOGSDIR"

# Collect available targets (built successfully)
available=""
count=0
while IFS=: read -r name srcdir seeds args status; do
	case "$name" in '#'*|'') continue ;; esac
	[ "$status" = "skip" ] && continue
	if [ -x "${BUILDDIR}/${name}" ]; then
		available="${available}${name}:"
		count=$((count + 1))
	fi
done < "$TARGETS"

if [ "$count" -eq 0 ]; then
	echo "No targets available. Run build.sh first."
	exit 1
fi

echo "Available targets: ${count}"
echo "Time budget: ${TOTAL_SECONDS}s"
echo "Batch: ${BATCH_ID}/${TOTAL_BATCHES}"

# Filter targets for this batch (round-robin assignment)
if [ "$TOTAL_BATCHES" -gt 1 ]; then
	filtered=""
	fcount=0
	idx=0
	OLD_IFS="$IFS"
	IFS=":"
	for t in $available; do
		[ -z "$t" ] && continue
		if [ $((idx % TOTAL_BATCHES)) -eq "$BATCH_ID" ]; then
			filtered="${filtered}${t}:"
			fcount=$((fcount + 1))
		fi
		idx=$((idx + 1))
	done
	IFS="$OLD_IFS"
	available="$filtered"
	count=$fcount
	echo "Targets in this batch: ${count}"
fi

# Calculate time per target
per_target=$((TOTAL_SECONDS / count))

# If not enough time for all targets, select a rotating subset
if [ "$per_target" -lt "$MIN_PER_TARGET" ]; then
	max_targets=$((TOTAL_SECONDS / MIN_PER_TARGET))
	per_target=$MIN_PER_TARGET

	# Rotate based on day of year
	day=$(date +%j)
	day=$((10#$day))

	# Select targets starting from a rotating offset
	all_names=""
	n=0
	OLD_IFS="$IFS"
	IFS=":"
	for t in $available; do
		[ -z "$t" ] && continue
		all_names="${all_names} ${t}"
		n=$((n + 1))
	done
	IFS="$OLD_IFS"

	offset=$(( (day * max_targets) % n ))
	selected=""
	sel_count=0
	i=0
	# Two passes to wrap around
	for pass in 1 2; do
		for t in $all_names; do
			if [ "$sel_count" -ge "$max_targets" ]; then
				break 2
			fi
			if [ "$pass" -eq 1 ] && [ "$i" -lt "$offset" ]; then
				i=$((i + 1))
				continue
			fi
			selected="${selected}${t} "
			sel_count=$((sel_count + 1))
			i=$((i + 1))
		done
		i=0
	done

	available=""
	for t in $selected; do
		available="${available}${t}:"
	done
	count=$sel_count
	echo "Selected ${count} targets (rotating subset)"
fi

echo "Time per target: ${per_target}s"
echo ""

# Read target config into a temp file for lookup
tmpconf=$(mktemp)
grep -v '^#' "$TARGETS" | grep -v '^$' > "$tmpconf"

start_time=$(date +%s)
fuzzed=0

OLD_IFS="$IFS"
IFS=":"
for name in $available; do
	[ -z "$name" ] && continue

	# Check remaining time
	elapsed=$(( $(date +%s) - start_time ))
	remaining=$((TOTAL_SECONDS - elapsed))
	if [ "$remaining" -lt 60 ]; then
		echo "Time budget exhausted."
		break
	fi
	time_left=$((remaining < per_target ? remaining : per_target))

	# Look up target config
	IFS="$OLD_IFS"
	seeds=""
	args=""
	while IFS=: read -r tname tsrcdir tseeds targs tstatus; do
		if [ "$tname" = "$name" ]; then
			seeds="$tseeds"
			args="$targs"
			break
		fi
	done < "$tmpconf"

	# Determine input directory
	target_output="${OUTPUTDIR}/${name}"
	target_seeds="${SEEDSDIR}/${seeds}"
	mkdir -p "$target_output"

	if [ -d "$target_seeds" ] && [ "$(ls -A "$target_seeds" 2>/dev/null)" ]; then
		input_dir="$target_seeds"
	else
		echo "${name}: SKIP (no seeds in ${seeds}/)"
		IFS=":"
		continue
	fi

	binary="${BUILDDIR}/${name}"

	echo "=== ${name} (${time_left}s) ==="

	# Reset AFL timing so -V starts fresh (cached fuzzer_stats has old times)
	rm -f "${target_output}/default/fuzzer_stats"

	# Run in a temp directory to contain file creation
	workdir=$(mktemp -d "${FUZZDIR}/work.${name}.XXXXXX")

	(cd "$workdir" && \
	 timeout "$((time_left + 30))" \
	 afl-fuzz -i "$input_dir" \
	          -o "$target_output" \
	          -V "$time_left" \
	          -- "$binary" $args \
	 >"${LOGSDIR}/${name}.log" 2>&1) || true

	rm -rf "$workdir"
	fuzzed=$((fuzzed + 1))

	# Brief stats or error
	if [ -f "${target_output}/default/fuzzer_stats" ]; then
		execs=$(grep "^execs_done" "${target_output}/default/fuzzer_stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
		paths=$(grep "^corpus_count" "${target_output}/default/fuzzer_stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
		crashes=$(grep "^saved_crashes" "${target_output}/default/fuzzer_stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
		echo "  execs=${execs:-0} paths=${paths:-0} crashes=${crashes:-0}"
	else
		echo "  AFL FAILED - last 3 lines of log:"
		tail -3 "${LOGSDIR}/${name}.log" 2>/dev/null || echo "  (no log)"
	fi

	echo ""
	IFS=":"
done
IFS="$OLD_IFS"

rm -f "$tmpconf"
echo "Fuzzing complete: ${fuzzed} targets processed"
