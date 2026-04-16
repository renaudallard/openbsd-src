#!/bin/sh
# Open GitHub issues for new, genuine crashes
#
# Filters out known false positives, UBSan-only crashes, and
# already-reported bugs.  Only opens issues for truly new findings.
#
# Crashes are classified by signal.  SIGSEGV/SIGABRT/SIGBUS/SIGFPE are
# genuine crashes and get a "crash" issue.  On the OpenBSD fuzz build
# SIGILL is a UBSan trap (the -fsanitize=undefined build traps on
# undefined behaviour because the full UBSan runtime is unavailable),
# so SIGILL-only findings get a distinct "UBSan trap" issue instead of
# being reported as a memory-safety crash.
#
# Usage: sh issue.sh

set -e

SRCROOT="${SRCROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
FUZZDIR="${SRCROOT}/fuzz"
CRASHDIR="${FUZZDIR}/crashes"
TARGETS="${FUZZDIR}/targets.conf"
ISSUELOG="${FUZZDIR}/issued.log"

# Create issue log if it doesn't exist
touch "$ISSUELOG"

# Map a signal number to its name.
signame_of() {
	case "$1" in
		4)  echo "SIGILL" ;;
		6)  echo "SIGABRT" ;;
		8)  echo "SIGFPE" ;;
		10) echo "SIGBUS" ;;
		11) echo "SIGSEGV" ;;
		*)  echo "signal $1" ;;
	esac
}

# Has an issue of this kind (or a legacy bare entry) already been opened?
already_issued() {
	grep -qx "$1" "$ISSUELOG" 2>/dev/null || \
	grep -qx "$1 $2" "$ISSUELOG" 2>/dev/null
}

new_issues=0

while IFS=: read -r name srcdir seeds args status; do
	case "$name" in '#'*|'') continue ;; esac

	# Skip known false positives, UBSan-only, already reported, and skipped
	case "$status" in
		false_positive|ubsan_only|reported|skip) continue ;;
	esac

	crash_dir="${CRASHDIR}/${name}"
	[ -d "$crash_dir" ] || continue

	# Classify crashes by signal, tracking the count and smallest
	# reproducer for genuine crashes and for UBSan traps separately.
	crash_n=0; crash_sig=""; crash_size=""
	ubsan_n=0; ubsan_size=""
	for f in "${crash_dir}"/*; do
		[ -f "$f" ] || continue
		case "$(basename "$f")" in README.txt) continue ;; esac
		sig=$(basename "$f" | sed -n 's/.*sig[_:]0*\([0-9]*\).*/\1/p')
		sz=$(wc -c < "$f" | tr -d ' ')
		if [ "$sig" = "4" ]; then
			ubsan_n=$((ubsan_n + 1))
			if [ -z "$ubsan_size" ] || [ "$sz" -lt "$ubsan_size" ]; then
				ubsan_size="$sz"
			fi
		else
			crash_n=$((crash_n + 1))
			if [ -z "$crash_size" ] || [ "$sz" -lt "$crash_size" ]; then
				crash_size="$sz"; crash_sig="$sig"
			fi
		fi
	done

	[ $((crash_n + ubsan_n)) -eq 0 ] && continue

	# A genuine crash takes precedence; only file a UBSan-trap issue
	# when there is nothing else for the target.
	if [ "$crash_n" -gt 0 ]; then
		kind="crash"
		signame=$(signame_of "$crash_sig")
		extra=""
		if [ "$ubsan_n" -gt 0 ]; then
			extra="
(Plus ${ubsan_n} UBSan-trap (SIGILL) input(s) for the same target.)"
		fi
		title="${name}(1): crash (${signame}) found by fuzzing"
		body="AFL++ fuzzing found ${crash_n} crash input(s) for \`${name}\`.

**Signal:** ${signame}
**Smallest reproducer:** ${crash_size} bytes
**Source:** \`${srcdir}\`
**Arguments:** \`${args}\`${extra}

Crash inputs are attached to the workflow run artifacts.

This issue was automatically created by the fuzzing CI."
	else
		kind="ubsan"
		title="${name}(1): UBSan trap (SIGILL) found by fuzzing"
		body="AFL++ fuzzing found ${ubsan_n} input(s) for \`${name}\` that trigger a UBSan trap (SIGILL).

**Signal:** SIGILL (undefined-behavior trap)
**Smallest reproducer:** ${ubsan_size} bytes
**Source:** \`${srcdir}\`
**Arguments:** \`${args}\`

The fuzz build uses \`-fsanitize=undefined\`.  On OpenBSD the full UBSan
runtime is unavailable, so the compiler traps on undefined behaviour with
SIGILL instead of logging and recovering.  This finding is therefore most
likely undefined behaviour (for example signed-integer overflow, an
out-of-range shift, or misalignment) reached on trusted input, not a
memory-safety crash.  Please triage; if confirmed benign, mark this target
\`ubsan_only\` in \`fuzz/targets.conf\`.

Crash inputs are attached to the workflow run artifacts.

This issue was automatically created by the fuzzing CI."
	fi

	if already_issued "$name" "$kind"; then
		echo "${name}: ${crash_n} crash(es), ${ubsan_n} UBSan trap(s) (${kind} issue already opened)"
		continue
	fi

	echo "${name}: opening ${kind} issue (${crash_n} crash(es), ${ubsan_n} UBSan trap(s))"

	if gh issue create \
		--title "$title" \
		--body "$body" \
		--label "fuzz-finding" \
		2>/dev/null; then
		echo "$name $kind" >> "$ISSUELOG"
		new_issues=$((new_issues + 1))
	else
		echo "${name}: failed to create issue"
	fi
done < "$TARGETS"

echo ""
echo "New issues opened: ${new_issues}"
