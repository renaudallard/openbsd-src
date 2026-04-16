#!/bin/sh
# Collect fuzzing crashes and generate summary report

set -e

SRCROOT="${SRCROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
FUZZDIR="${SRCROOT}/fuzz"
OUTPUTDIR="${FUZZDIR}/output"
CRASHDIR="${FUZZDIR}/crashes"
TARGETS="${FUZZDIR}/targets.conf"

mkdir -p "$CRASHDIR"

count_files() {
	dir="$1"
	n=0
	for f in "${dir}"/*; do
		[ -f "$f" ] || continue
		case "$(basename "$f")" in
			README.txt) continue ;;
		esac
		n=$((n + 1))
	done
	echo "$n"
}

total_crashes=0
total_hangs=0

# Collect crashes and hangs
while IFS=: read -r name srcdir seeds args status; do
	case "$name" in '#'*|'') continue ;; esac

	crash_dir="${OUTPUTDIR}/${name}/default/crashes"
	if [ -d "$crash_dir" ]; then
		c=$(count_files "$crash_dir")
		if [ "$c" -gt 0 ]; then
			echo "${name}: ${c} crash(es)"
			mkdir -p "${CRASHDIR}/${name}"
			for f in "${crash_dir}"/*; do
				[ -f "$f" ] || continue
				case "$(basename "$f")" in README.txt) continue ;; esac
				# Rename to replace colons (rejected by upload-artifact)
				safe=$(basename "$f" | tr ':' '_')
				cp "$f" "${CRASHDIR}/${name}/${safe}"
			done
			total_crashes=$((total_crashes + c))
		fi
	fi

	hang_dir="${OUTPUTDIR}/${name}/default/hangs"
	if [ -d "$hang_dir" ]; then
		h=$(count_files "$hang_dir")
		if [ "$h" -gt 0 ]; then
			echo "${name}: ${h} hang(s)"
			total_hangs=$((total_hangs + h))
		fi
	fi
done < "$TARGETS"

# Generate summary
{
	echo "# Fuzzing Summary - $(date -u '+%Y-%m-%d %H:%M UTC')"
	echo ""
	echo "Crashes: ${total_crashes}"
	echo "Hangs: ${total_hangs}"
	echo ""

	if [ "$total_crashes" -gt 0 ]; then
		echo "## Crashes"
		for dir in "${CRASHDIR}"/*/; do
			[ -d "$dir" ] || continue
			tname=$(basename "$dir")
			c=$(count_files "$dir")
			echo "- ${tname}: ${c}"
		done
		echo ""
	fi

	echo "## Target Stats"
	while IFS=: read -r name srcdir seeds args status; do
		case "$name" in '#'*|'') continue ;; esac
		stats="${OUTPUTDIR}/${name}/default/fuzzer_stats"
		[ -f "$stats" ] || continue
		execs=$(grep "^execs_done" "$stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
		paths=$(grep "^corpus_count" "$stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
		crashes=$(grep "^saved_crashes" "$stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
		speed=$(grep "^execs_per_sec" "$stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
		echo "- ${name}: execs=${execs:-0} paths=${paths:-0} crashes=${crashes:-0} speed=${speed:-0}/s"
	done < "$TARGETS"
} > "${FUZZDIR}/summary.md"

echo ""
cat "${FUZZDIR}/summary.md"
