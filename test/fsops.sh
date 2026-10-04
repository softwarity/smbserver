#!/usr/bin/env bash
# Exercises a mounted share with the operations a developer performs on a
# volume, and prints one line per operation: "ok <name>" or "FAIL <name>".
# The same script runs on Linux, macOS and (through Git Bash) Windows, which
# is what makes the compatibility matrix of the README comparable across
# clients.
#
# usage: fsops.sh <mountpoint> [results-file]
#
# BIG_MB sets the size of the large file (default 1024).
set -u

mnt=${1:?usage: fsops.sh <mountpoint> [results-file]}
results=${2:-/dev/null}
big_mb=${BIG_MB:-1024}
failed=0
work="$mnt/fsops-$$"

sha() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

size_of() {
	wc -c <"$1" | tr -d ' '
}

mtime_of() {
	case "$(uname -s)" in
	Darwin) stat -f %m "$1" ;;
	*) stat -c %Y "$1" ;;
	esac
}

# check <name> <command...>: runs the command and records the outcome.
check() {
	local name=$1
	shift
	if "$@" >/dev/null 2>"$errors"; then
		echo "ok $name"
		echo "$name ok" >>"$results"
	else
		echo "FAIL $name: $(tr '\n' ' ' <"$errors")"
		echo "$name FAIL" >>"$results"
		failed=1
	fi
}

errors=$(mktemp)
trap 'rm -f "$errors"' EXIT
: >"$results" 2>/dev/null || true

t_mkdir() { mkdir "$work" && mkdir -p "$work/a/b/c" && test -d "$work/a/b/c"; }
t_create() { : >"$work/empty" && test -f "$work/empty" && test "$(size_of "$work/empty")" = 0; }
t_write() { printf 'hello world\n' >"$work/file" && test "$(size_of "$work/file")" = 12; }
t_read() { test "$(cat "$work/file")" = "hello world"; }
t_append() { printf 'more\n' >>"$work/file" && test "$(tail -n 1 "$work/file")" = more && test "$(size_of "$work/file")" = 17; }
t_overwrite() { printf 'short\n' >"$work/file" && test "$(cat "$work/file")" = short; }
t_list() {
	touch "$work/l1" "$work/l2" "$work/l3" || return 1
	test "$(ls "$work" | grep -c '^l[123]$')" = 3
}
t_list_many() {
	mkdir "$work/many" || return 1
	local i
	for i in $(seq 1 300); do : >"$work/many/f$i" || return 1; done
	test "$(ls "$work/many" | wc -l | tr -d ' ')" = 300
}
t_stat() { test -f "$work/file" && test -d "$work/a" && ! test -e "$work/nope"; }
t_rename() { mv "$work/l1" "$work/renamed" && test -f "$work/renamed" && ! test -e "$work/l1"; }
t_rename_over() {
	printf one >"$work/r1" && printf two >"$work/r2" && mv -f "$work/r1" "$work/r2" &&
		test "$(cat "$work/r2")" = one && ! test -e "$work/r1"
}
t_rename_dir() { mv "$work/a" "$work/z" && test -d "$work/z/b/c" && ! test -e "$work/a"; }
t_move_across() { mv "$work/renamed" "$work/z/b/moved" && test -f "$work/z/b/moved"; }
t_delete() { rm "$work/l2" && ! test -e "$work/l2"; }
t_rmdir() { rmdir "$work/z/b/c" && ! test -e "$work/z/b/c"; }
t_rmdir_nonempty() { ! rmdir "$work/z" 2>/dev/null && test -d "$work/z"; }
t_rm_recursive() { rm -r "$work/many" && ! test -e "$work/many"; }
t_truncate() {
	printf '0123456789' >"$work/trunc" || return 1
	# Shrink, then grow: both go through the end-of-file information.
	if command -v truncate >/dev/null 2>&1; then
		truncate -s 4 "$work/trunc" && test "$(cat "$work/trunc")" = 0123 &&
			truncate -s 100 "$work/trunc" && test "$(size_of "$work/trunc")" = 100
	else
		dd if=/dev/null of="$work/trunc" bs=1 seek=4 2>/dev/null && test "$(cat "$work/trunc")" = 0123 &&
			dd if=/dev/null of="$work/trunc" bs=1 seek=100 2>/dev/null && test "$(size_of "$work/trunc")" = 100
	fi
}
t_dates() {
	# 2020-01-02 03:04:05 UTC, as seconds since the epoch.
	TZ=UTC touch -t 202001020304.05 "$work/dated" || return 1
	test "$(mtime_of "$work/dated")" = 1577934245
}
t_statfs() {
	local avail
	avail=$(df -Pk "$mnt" | tail -n 1 | awk '{print $4}')
	test "${avail:-0}" -gt 0
}
t_names() {
	local n
	for n in 'with space' 'accentué' 'UPPER' 'upper.lower' '.hidden' 'trailing.dot.txt'; do
		printf x >"$work/$n" && test -f "$work/$n" || return 1
	done
	# Both cases of a name are distinct files, or the same one: either is
	# coherent, but creating one must not destroy the other's content.
	printf up >"$work/UPPER" && test "$(cat "$work/UPPER")" = up
}
t_big() {
	# Content that does not compress, produced quickly: a cipher stream
	# where openssl is at hand, the kernel's generator otherwise.
	local src="$errors.big" bytes=$((big_mb * 1024 * 1024)) want got
	if command -v openssl >/dev/null 2>&1; then
		openssl enc -aes-128-ctr -pass pass:fsops -nosalt </dev/zero 2>/dev/null | head -c $bytes >"$src"
	fi
	test "$(size_of "$src" 2>/dev/null)" = $bytes || head -c $bytes /dev/urandom >"$src"
	want=$(sha <"$src")
	cp "$src" "$work/big" || { rm -f "$src"; return 1; }
	rm -f "$src"
	if test "$(size_of "$work/big")" != $bytes; then
		echo "size $(size_of "$work/big"), want $bytes" >&2
		return 1
	fi
	got=$(sha <"$work/big")
	rm -f "$work/big"
	test "$want" = "$got" || { echo "hash $got, want $want" >&2; return 1; }
}
t_concurrent() {
	# Two processes write interleaved 1 MiB blocks of the same file, then
	# each block is checked to hold what its writer put there.
	local f="$work/concurrent" i
	: >"$f" || return 1
	writer() {
		local start=$1 byte=$2 i
		for i in $(seq "$start" 2 31); do
			head -c 1048576 /dev/zero | tr '\0' "$byte" | dd of="$f" bs=1048576 seek="$i" conv=notrunc 2>/dev/null || return 1
		done
	}
	writer 0 A &
	local p1=$!
	writer 1 B &
	local p2=$!
	wait $p1 || return 1
	wait $p2 || return 1
	test "$(size_of "$f")" = $((32 * 1048576)) || return 1
	for i in 0 1 14 15 30 31; do
		local want=A
		test $((i % 2)) = 1 && want=B
		test "$(dd if="$f" bs=1048576 skip="$i" count=1 2>/dev/null | tr -d "$want" | wc -c | tr -d ' ')" = 0 || return 1
	done
	rm -f "$f"
}
t_concurrent_files() {
	# Two processes each create and remove files in the same directory.
	mkdir "$work/cc" || return 1
	churn() {
		local tag=$1 i
		for i in $(seq 1 100); do
			printf '%s' "$tag$i" >"$work/cc/$tag$i" && test "$(cat "$work/cc/$tag$i")" = "$tag$i" || return 1
		done
	}
	churn x &
	local p1=$!
	churn y &
	local p2=$!
	wait $p1 || return 1
	wait $p2 || return 1
	test "$(ls "$work/cc" | wc -l | tr -d ' ')" = 200
}
t_cleanup() { rm -rf "$work" && ! test -e "$work"; }

check mkdir t_mkdir
check create t_create
check write t_write
check read t_read
check append t_append
check overwrite t_overwrite
check list t_list
check list-many t_list_many
check stat t_stat
check rename t_rename
check rename-over t_rename_over
check rename-dir t_rename_dir
check move-across-dirs t_move_across
check delete t_delete
check rmdir t_rmdir
check rmdir-nonempty-refused t_rmdir_nonempty
check rm-recursive t_rm_recursive
check truncate t_truncate
check dates t_dates
check statfs t_statfs
check names t_names
check big-file-hash t_big
check concurrent-writes t_concurrent
check concurrent-files t_concurrent_files
check cleanup t_cleanup

exit $failed
