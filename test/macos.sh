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
# record <name> <command...>: runs the check under a time limit, since an
# operation on a mount whose server does not answer waits forever.
record() {
	local name=$1 pid watchdog
	shift
	("$@") &
	pid=$!
	(sleep "${LIMIT:-300}" && echo "timed out: $name" && kill -9 $pid) 2>/dev/null &
	watchdog=$!
	if wait $pid 2>/dev/null; then
		echo "ok $name"
		echo "$name ok" >>"$out"
	else
		echo "FAIL $name"
		echo "$name FAIL" >>"$out"
		failed=1
	fi
	# The sleep first: left behind, it would keep the output of the script
	# open for as long as it lasts.
	pkill -P $watchdog 2>/dev/null
	kill $watchdog 2>/dev/null
}
cut() { (exec 3<>/dev/tcp/127.0.0.1/$control) 2>/dev/null; }

cleanup() {
	for m in "$mnt" "$work/bad"; do
		(umount "$m" 2>/dev/null || diskutil unmount force "$m" >/dev/null 2>&1) &
	done
	sleep 5
	kill "$server_pid" "$relay_pid" 2>/dev/null
	if test "$failed" != 0; then
		echo "---- server log"
		tail -n 40 "$work/server.log"
		echo "---- relay log"
		cat "$work/relay.log"
	fi
	rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$root" "$mnt" "$work/bad"
SMBSERVER_TRACE=1 "$bin/smbserver" -root "$root" -addr 127.0.0.1:$port -share $share -user $user -password "$password" -v >"$work/server.log" 2>&1 &
server_pid=$!
"$bin/tcpcut" -listen 127.0.0.1:$relay -to 127.0.0.1:$port -control 127.0.0.1:$control >"$work/relay.log" 2>&1 &
relay_pid=$!
for p in $port $relay; do
	for _ in $(seq 1 50); do
		(exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && break
		sleep 0.1
	done
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
	t_fsops() { BIG_MB=${BIG_MB:-1024} bash "$here/fsops.sh" "$mnt" "$work/fsops.txt"; }
	LIMIT=900 record operations t_fsops
	# The operations report one by one; their summary line is not a row.
	sed -i '' '/^operations /d' "$out"
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

	step "the Finder"
	# The Finder itself, driven by AppleScript: it asks the server for
	# things no shell command does. Where the system does not let a script
	# drive it, the check is left out rather than reported as passed.
	mkdir -p "$work/finder-src/sub" && printf one >"$work/finder-src/a.txt" && printf two >"$work/finder-src/sub/b.txt" &&
		head -c 3000000 /dev/urandom >"$work/finder-src/blob" && xattr -w com.example.note hello "$work/finder-src/a.txt"
	if osascript -e 'tell application "Finder" to get name of startup disk' >/dev/null 2>"$work/finder.err"; then
		# One Finder action per call, so that a failure names its step.
		finder() {
			local what=$1
			shift
			if ! osascript -e 'on run argv' -e 'with timeout of 90 seconds' -e 'tell application "Finder"' "$@" \
				-e 'end tell' -e 'end timeout' -e 'end run' "$mnt" "$work/finder-src" >/dev/null; then
				echo "Finder step failed: $what"
				return 1
			fi
		}
		t_finder() {
			local before found
			before=$(wc -l <"$work/server.log")
			if ! { finder open -e 'open (POSIX file (item 1 of argv) as alias)' &&
				finder duplicate -e 'duplicate (POSIX file (item 2 of argv) as alias) to (POSIX file (item 1 of argv) as alias)' &&
				finder count -e 'count (every item of folder (POSIX file ((item 1 of argv) & "/finder-src") as alias))' &&
				finder rename -e 'set name of (POSIX file ((item 1 of argv) & "/finder-src/a.txt") as alias) to "renamed.txt"' &&
				finder close -e 'close every window'; }; then
				# What the screen showed, and what the server was asked
				# during the step: the refusals, then the last requests.
				screencapture -x "$results/finder.png" 2>/dev/null
				echo "---- refusals during the Finder step"
				tail -n +"$((before + 1))" "$work/server.log" | grep -v 'status 0x0$' | sed 's/^.*: command/command/' | sort | uniq -c | sort -rn | head -n 30
				echo "---- last requests of the Finder step"
				tail -n +"$((before + 1))" "$work/server.log" | tail -n 25
				return 1
			fi
			# Deleting is left to the shell: on a network volume the Finder
			# asks for confirmation, whatever the server.
			diff "$work/finder-src/a.txt" "$mnt/finder-src/renamed.txt" && cmp "$work/finder-src/blob" "$mnt/finder-src/blob" &&
				test "$(cat "$mnt/finder-src/sub/b.txt")" = two && ! test -e "$mnt/finder-src/a.txt" || return 1
			found=$(find "$root" \( -name '._*' -o -name '.DS_Store' -o -name '.Trashes' \) | head -n 5)
			rm -rf "$mnt/finder-src"
			test -z "$found" || { echo "left behind: $found"; return 1; }
		}
		LIMIT=600 record finder-browse-copy-rename t_finder
	else
		echo "the Finder cannot be scripted here: $(tr '\n' ' ' <"$work/finder.err")"
	fi

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
