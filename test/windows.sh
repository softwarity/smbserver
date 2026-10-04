#!/usr/bin/env bash
# Integration test on Windows, run from Git Bash as an administrator: the
# kernel redirector ("net use") against a local server.
#
# The redirector only ever connects to port 445, which the machine's own SMB
# server holds. The test frees it by stopping that service and its drivers,
# which a CI runner can afford; the relay then listens on 445 in front of the
# server, so the cut test works as on the other systems.
#
# usage: windows.sh <bin-dir> [results-dir]
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

bin=$(cd "${1:?usage: windows.sh <bin-dir> [results-dir]}" && pwd)
results=${2:-$(mktemp -d)}
mkdir -p "$results"
here=$(cd "$(dirname "$0")" && pwd)

port=1445
control=1447
user=dev
password=s3cret-pass
share=vol
drive=S
work=$(mktemp -d)
root=$work/root
failed=0
out=$results/windows.txt
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
	net use $drive: /delete /y >/dev/null 2>&1
	kill "$server_pid" "$relay_pid" 2>/dev/null
	if test "$failed" != 0; then
		echo "---- server log"
		tail -n 300 "$work/server.log"
	fi
	rm -rf "$work"
}
trap cleanup EXIT

step "free port 445"
# The server service first, then the drivers under it, in dependency order.
stopped() { sc query "$1" | grep -q 'STATE *: 1 '; }
net stop LanmanServer /y
# One driver at a time, each fully stopped before the one under it is asked
# to: stopping srvnet while srv2 is still on its way down leaves it pending.
for svc in srv2 srvnet; do
	for _ in $(seq 1 60); do
		stopped $svc && break
		sc stop $svc >/dev/null 2>&1
		sleep 2
	done
	sc query $svc | grep STATE
done
for _ in $(seq 1 30); do
	netstat -ano -p TCP | grep -q ':445 .*LISTENING' || break
	sleep 2
done
if netstat -ano -p TCP | grep ':445 .*LISTENING'; then
	echo "port 445 is still held"
fi

mkdir -p "$root"
SMBSERVER_TRACE="${SMBSERVER_TRACE:-}" "$bin/smbserver.exe" -root "$(cygpath -w "$root")" -addr 127.0.0.1:$port -share $share -user $user -password "$password" -v >"$work/server.log" 2>&1 &
server_pid=$!
"$bin/tcpcut.exe" -listen 127.0.0.1:445 -to 127.0.0.1:$port -control 127.0.0.1:$control >"$work/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 1 50); do
	(exec 3<>/dev/tcp/127.0.0.1/445) 2>/dev/null && break
	sleep 0.2
done
cat "$work/relay.log"

step "net use"
unc='\\127.0.0.1\'$share
# Error 86 or 1326 is the server refusing the password; any other failure
# would only say that the server was not reached.
t_bad_password() { net use $drive: "$unc" wrong-password /user:$user /persistent:no 2>&1 | grep -Eq 'error (86|1326) '; }
t_mount() { net use $drive: "$unc" "$password" /user:$user /persistent:no; }
record bad-password-refused t_bad_password
net use $drive: /delete /y >/dev/null 2>&1
record mount t_mount

mnt=/${drive,,}
if test -d "$mnt/"; then
	BIG_MB=${BIG_MB:-1024} bash "$here/fsops.sh" "$mnt" "$work/fsops.txt" || failed=1
	cat "$work/fsops.txt" >>"$out"

	step "no trace left in the volume"
	t_no_traces() {
		mkdir "$mnt/traces" && printf data >"$mnt/traces/file" && ls -la "$mnt/traces" >/dev/null || return 1
		cmd /c "dir $drive:\\traces" >/dev/null
		local found
		found=$(find "$root" \( -iname 'Thumbs.db' -o -iname 'desktop.ini' -o -iname '$RECYCLE.BIN' -o -iname 'System Volume Information' \) | head -n 5)
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

	t_umount() { net use $drive: /delete /y; }
	record unmount t_umount
fi

echo
test "$failed" = 0 && echo "ALL PASSED" || echo "SOME FAILED"
exit $failed
