#!/usr/bin/env bash
# Integration test on macOS: mount_smbfs against a local server on a high
# port, as an ordinary user, with nothing configured on the machine.
#
# usage: macos.sh <bin-dir> [results-dir]
set -u

bin=$(cd "${1:?usage: macos.sh <bin-dir> [results-dir]}" && pwd)
results=${2:-$(mktemp -d)}
mkdir -p "$results"
here=$(cd "$(dirname "$0")" && pwd)

port=1445
relay=1446
control=1447
user=dev
password=s3cret-pass
share=vol
# The physical path: mount(8) reports /private/var where mktemp says /var.
work=$(cd "$(mktemp -d)" && pwd -P)
root=$work/root
mnt=$work/mnt
failed=0
out=$results/macos-smbfs.txt
: >"$out"

step() { printf '\n== %s\n' "$*"; }
record() {
	local name=$1
	shift
	if "$@"; then
		echo "ok $name"
		echo "$name ok" >>"$out"
	else
		echo "FAIL $name"
		echo "$name FAIL" >>"$out"
		failed=1
	fi
}
cut() { (exec 3<>/dev/tcp/127.0.0.1/$control) 2>/dev/null; }

cleanup() {
	for m in "$mnt" "$work/bad"; do
		umount "$m" 2>/dev/null || diskutil unmount force "$m" >/dev/null 2>&1
	done
	kill "$server_pid" "$relay_pid" 2>/dev/null
	if test "$failed" != 0; then
		echo "---- server log"
		tail -n 300 "$work/server.log"
	fi
	rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$root" "$mnt" "$work/bad"
"$bin/smbserver" -root "$root" -addr 127.0.0.1:$port -share $share -user $user -password "$password" -v >"$work/server.log" 2>&1 &
server_pid=$!
"$bin/tcpcut" -listen 127.0.0.1:$relay -to 127.0.0.1:$port -control 127.0.0.1:$control >"$work/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 1 50); do
	(exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break
	sleep 0.1
done

step "mount_smbfs, through the relay"
# -N: never prompt. A mount that needs a dialog is a failed mount.
t_mount() { mount_smbfs -N "//$user:$password@127.0.0.1:$relay/$share" "$mnt"; }
# Before any good mount: macOS reuses an authenticated session to a server
# for later mounts, whatever password they carry.
t_bad_password() {
	if mount_smbfs -N "//$user:wrong@127.0.0.1:$port/$share" "$work/bad" 2>/dev/null; then
		umount "$work/bad"
		return 1
	fi
}
record bad-password-refused t_bad_password
record mount t_mount

if mount | grep -q " on $mnt (smbfs"; then
	BIG_MB=${BIG_MB:-1024} bash "$here/fsops.sh" "$mnt" "$work/fsops.txt" || failed=1
	cat "$work/fsops.txt" >>"$out"

	step "no trace left in the volume"
	t_no_traces() {
		# What a developer's tools do on a Mac: copy a file that carries
		# extended attributes, browse, remove. None of it may leave
		# AppleDouble or Finder files behind on the server.
		printf data >"$work/local" && xattr -w com.example.note hello "$work/local" &&
			xattr -w com.apple.quarantine '0081;00000000;test;' "$work/local" || return 1
		mkdir "$mnt/traces" && cp "$work/local" "$mnt/traces/copied" && cp -p "$work/local" "$mnt/traces/copied-p" &&
			ls -la "$mnt/traces" >/dev/null && test "$(cat "$mnt/traces/copied")" = data || return 1
		sync
		local found
		found=$(find "$root" \( -name '._*' -o -name '.DS_Store' -o -name '.Trashes' -o -name '.fseventsd' -o -name '.Spotlight-V100' \) | head -n 5)
		rm -rf "$mnt/traces"
		test -z "$found" || { echo "left behind: $found"; return 1; }
	}
	record no-traces-in-volume t_no_traces

	step "survive a cut"
	t_cut_idle() {
		echo before >"$mnt/cut-idle" || return 1
		cut
		test "$(cat "$mnt/cut-idle")" = before && echo after >"$mnt/cut-idle" &&
			test "$(cat "$mnt/cut-idle")" = after && ls "$mnt" >/dev/null && rm "$mnt/cut-idle"
	}
	t_cut_busy() {
		head -c 268435456 /dev/urandom >"$work/busy" || return 1
		(sleep 1; cut) &
		local cutter=$!
		cp "$work/busy" "$mnt/busy"
		wait $cutter
		# The operation in flight when the connection drops may fail,
		# which is for the client to decide. What is required is that
		# the mount is usable again at once: the copy is redone and
		# must then be intact.
		cp "$work/busy" "$mnt/busy" && cmp "$work/busy" "$mnt/busy" && rm "$mnt/busy"
	}
	t_cut_repeated() {
		local i
		for i in 1 2 3 4 5; do
			cut
			echo "round $i" >"$mnt/cut-$i" && test "$(cat "$mnt/cut-$i")" = "round $i" && rm "$mnt/cut-$i" || return 1
		done
	}
	record reconnect-after-cut-idle t_cut_idle
	record reconnect-after-cut-during-copy t_cut_busy
	record reconnect-after-repeated-cuts t_cut_repeated

	t_umount() { umount "$mnt"; }
	record unmount t_umount
fi

echo
test "$failed" = 0 && echo "ALL PASSED" || echo "SOME FAILED"
exit $failed
