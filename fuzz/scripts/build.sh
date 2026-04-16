#!/bin/sh
# Build OpenBSD userland programs with AFL++ instrumentation
#
# Usage: sh build.sh [target_name]

set -e

SRCROOT="${SRCROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
FUZZDIR="${SRCROOT}/fuzz"
BUILDDIR="${FUZZDIR}/build"
TARGETS="${FUZZDIR}/targets.conf"
AFL_CC="${AFL_CC:-afl-clang-fast}"
# Use COPTS (not CFLAGS) to add flags without replacing Makefile's own CFLAGS
# -fsanitize-recover=undefined: log UBSan errors but don't abort, so AFL can
# fuzz past UBSan issues and focus on finding SIGSEGV/SIGABRT crashes
FUZZ_COPTS="-g -fsanitize=undefined -fsanitize-recover=all -fno-omit-frame-pointer"
FUZZ_LDFLAGS="-fsanitize=undefined"

filter="${1:-}"

mkdir -p "$BUILDDIR"

# Verify cross-tree dependencies exist.
# The full source tree (from GitHub mirror) has everything, but log
# warnings if key files are missing so build failures are obvious.
check_deps() {
	ok=true
	for f in \
		lib/libc/gen/charclass.h \
		sbin/pfctl/pfctl.h \
		sbin/pfctl/pfctl_parser.h \
		sbin/pfctl/pfctl_osfp.c \
		usr.sbin/hostapd/iapp.h \
		sys/net/pf_osfp.c \
		lib/libpcap/pcap.h; do
		if [ ! -f "${SRCROOT}/${f}" ]; then
			echo "WARN: missing ${f} (some targets may fail to build)"
			ok=false
		fi
	done
	$ok && echo "Cross-tree dependencies: OK"
}

check_deps

built=0
failed=0
skipped=0

while IFS=: read -r name srcdir seeds args status; do
	case "$name" in '#'*|'') continue ;; esac
	[ -n "$filter" ] && [ "$name" != "$filter" ] && continue

	# Skip targets marked as skip
	if [ "$status" = "skip" ]; then
		printf "%-20s SKIP (marked)\n" "$name"
		skipped=$((skipped + 1))
		continue
	fi

	printf "%-20s " "$name"

	progdir="${SRCROOT}/${srcdir}"
	if [ ! -d "$progdir" ]; then
		echo "SKIP (no source)"
		skipped=$((skipped + 1))
		continue
	fi

	logfile="${BUILDDIR}/${name}.build.log"
	if (cd "$progdir" && \
	    make clean >/dev/null 2>&1; \
	    make CC="$AFL_CC" COPTS="$FUZZ_COPTS" LDFLAGS="$FUZZ_LDFLAGS" \
	    >"$logfile" 2>&1); then
		prog=$(cd "$progdir" && make -V PROG 2>/dev/null) || prog=""
		[ -z "$prog" ] && prog="$name"
		# Find the binary (may be in a subdirectory for multi-dir builds)
		binary=""
		if [ -f "${progdir}/${prog}" ] && [ -x "${progdir}/${prog}" ]; then
			binary="${progdir}/${prog}"
		elif [ -f "${progdir}/${prog}/${prog}" ] && [ -x "${progdir}/${prog}/${prog}" ]; then
			binary="${progdir}/${prog}/${prog}"
		fi
		if [ -n "$binary" ]; then
			cp "$binary" "${BUILDDIR}/${name}"
			echo "OK"
			built=$((built + 1))
		else
			echo "FAIL (no binary)"
			failed=$((failed + 1))
		fi
	else
		echo "FAIL (build error)"
		tail -5 "$logfile" 2>/dev/null
		failed=$((failed + 1))
	fi
done < "$TARGETS"

# Generate binary seeds from system files
seedsdir="${FUZZDIR}/seeds"

if [ ! -f "${seedsdir}/compress/valid.Z" ]; then
	mkdir -p "${seedsdir}/compress"
	echo "test data" | compress > "${seedsdir}/compress/valid.Z" 2>/dev/null || true
fi

if [ ! -f "${seedsdir}/binary/elf" ]; then
	mkdir -p "${seedsdir}/binary"
	dd if=/bin/true of="${seedsdir}/binary/elf" bs=256 count=1 2>/dev/null || true
fi

if [ ! -f "${seedsdir}/tcpdump/capture.pcap" ]; then
	mkdir -p "${seedsdir}/tcpdump"
	# Minimal pcap header: magic + version 2.4 + snaplen 0xffff + linktype 1
	printf '\324\303\262\241\002\000\004\000\000\000\000\000\000\000\000\000\377\377\000\000\001\000\000\000' \
		> "${seedsdir}/tcpdump/capture.pcap" 2>/dev/null || true
fi

if [ ! -f "${seedsdir}/signify/test.pub" ]; then
	mkdir -p "${seedsdir}/signify"
	signify -G -n -p "${seedsdir}/signify/test.pub" \
		-s "${seedsdir}/signify/test.sec" 2>/dev/null || true
	rm -f "${seedsdir}/signify/test.sec"
fi

if [ ! -f "${seedsdir}/ffs/mini.img" ]; then
	mkdir -p "${seedsdir}/ffs"
	dd if=/dev/zero of="${seedsdir}/ffs/mini.img" bs=512 count=2048 2>/dev/null
	vnconfig vnd0 "${seedsdir}/ffs/mini.img" 2>/dev/null && \
		newfs -m 0 /dev/rvnd0c >/dev/null 2>&1 && \
		vnconfig -u vnd0 2>/dev/null || true
fi

if [ ! -f "${seedsdir}/ext2fs/mini.img" ]; then
	mkdir -p "${seedsdir}/ext2fs"
	dd if=/dev/zero of="${seedsdir}/ext2fs/mini.img" bs=512 count=2048 2>/dev/null
	vnconfig vnd0 "${seedsdir}/ext2fs/mini.img" 2>/dev/null && \
		newfs_ext2fs /dev/rvnd0c >/dev/null 2>&1 && \
		vnconfig -u vnd0 2>/dev/null || true
fi

if [ ! -f "${seedsdir}/msdos/mini.img" ]; then
	mkdir -p "${seedsdir}/msdos"
	dd if=/dev/zero of="${seedsdir}/msdos/mini.img" bs=512 count=2048 2>/dev/null
	vnconfig vnd0 "${seedsdir}/msdos/mini.img" 2>/dev/null && \
		newfs_msdos /dev/rvnd0c >/dev/null 2>&1 && \
		vnconfig -u vnd0 2>/dev/null || true
fi

echo ""
echo "Build: ${built} ok, ${failed} failed, ${skipped} skipped"
