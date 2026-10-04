#!/usr/bin/env bash
# Integration test on Linux: smbclient, then a kernel cifs mount, against a
# server running under an unprivileged uid that exists in no account file.
#
# usage: linux.sh <bin-dir> [results-dir]
#
# Needs root or passwordless sudo (mount, and switching to the test uid),
# smbclient and cifs-utils.
set -u

bin=$(cd "${1:?usage: linux.sh <bin-dir> [results-dir]}" && pwd)
results=${2:-$(mktemp -d)}
mkdir -p "$results"
here=$(cd "$(dirname "$0")" && pwd)

uid=54321
port=1445
relay=1446
control=1447
user=dev
password='p@ss w0rd'
share=vol
work=$(mktemp -d)
root=$work/root
mnt=$work/mnt
failed=0

sudo=
test "$(id -u)" = 0 || sudo=sudo

step() { printf '\n== %s\n' "$*"; }
# record <results-file> <name> <command...>
record() {
	local file=$1 name=$2
	shift 2
	if "$@"; then
		echo "ok $name"
		echo "$name ok" >>"$file"
	else
		echo "FAIL $name"
		echo "$name FAIL" >>"$file"
		failed=1
	fi
}

cleanup() {
	$sudo umount -f "$mnt" 2>/dev/null
	$sudo kill "$server_pid" "$relay_pid" 2>/dev/null
	if test "$failed" != 0; then
		echo "---- server log"
		tail -n 200 "$work/server.log"
		echo "---- kernel log"
		$sudo dmesg 2>/dev/null | grep -i cifs | tail -n 40
	fi
	$sudo rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$root" "$mnt"
chmod 755 "$work"
$sudo chown "$uid:$uid" "$root"

step "server as uid $uid, no capability, no passwd entry"
$sudo env SMBSERVER_TRACE="${SMBSERVER_TRACE:-}" setpriv --reuid=$uid --regid=$uid --clear-groups --inh-caps=-all --bounding-set=-all \
	"$bin/smbserver" -root "$root" -addr 127.0.0.1:$port -share $share -user $user -password "$password" -v >"$work/server.log" 2>&1 &
server_pid=$!
"$bin/tcpcut" -listen 127.0.0.1:$relay -to 127.0.0.1:$port -control 127.0.0.1:$control >"$work/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 1 50); do
	(exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break
	sleep 0.1
done

step "smbclient"
sc=$results/smbclient.txt
: >"$sc"
smb() { smbclient "//127.0.0.1/$share" -p $port -U "$user%$password" "$@"; }
t_login() { smb -c 'ls' >/dev/null; }
t_bad_password() { ! smbclient "//127.0.0.1/$share" -p $port -U "$user%wrong" -c 'ls' >/dev/null 2>&1; }
t_bad_user() { ! smbclient "//127.0.0.1/$share" -p $port -U "nobody%$password" -c 'ls' >/dev/null 2>&1; }
t_put_get() {
	head -c 3000000 /dev/urandom >"$work/up" &&
		smb -c "put $work/up up.bin; get up.bin $work/down" >/dev/null 2>&1 &&
		cmp "$work/up" "$work/down"
}
t_dirs() {
	smb -c 'mkdir d1; cd d1; mkdir d2; cd ..; rmdir d1\d2; rmdir d1' >/dev/null 2>&1 &&
		! $sudo test -e "$root/d1"
}
t_rename_delete() {
	smb -c 'rename up.bin moved.bin; ls' 2>/dev/null | grep -q moved.bin &&
		smb -c 'del moved.bin' >/dev/null 2>&1 && ! $sudo test -e "$root/moved.bin"
}
t_owner() {
	smb -c "put $work/up owned.bin" >/dev/null 2>&1 &&
		test "$($sudo stat -c %u "$root/owned.bin")" = $uid
}
t_escape() {
	# smbclient normalises "..", so this mostly proves the server holds
	# when asked for the parent of its root.
	! smb -c 'get ..\server.log /dev/null' >/dev/null 2>&1
}
record "$sc" login t_login
record "$sc" bad-password-refused t_bad_password
record "$sc" bad-user-refused t_bad_user
record "$sc" put-get t_put_get
record "$sc" mkdir-rmdir t_dirs
record "$sc" rename-delete t_rename_delete
record "$sc" files-owned-by-server-uid t_owner
record "$sc" no-escape t_escape

step "cifs mount, through the relay"
cf=$results/linux-cifs.txt
: >"$cf"
opts="username=$user,password=$password,port=$relay,vers=2.1,uid=$(id -u),gid=$(id -g),noperm,hard"
t_mount() { $sudo mount -t cifs "//127.0.0.1/$share" "$mnt" -o "$opts"; }
record "$cf" mount t_mount
if mountpoint -q "$mnt"; then
	BIG_MB=${BIG_MB:-1024} bash "$here/fsops.sh" "$mnt" "$work/fsops.txt" || failed=1
	cat "$work/fsops.txt" >>"$cf"

	step "survive a cut"
	t_cut_idle() {
		echo before >"$mnt/cut-idle" || return 1
		echo cut | nc -w 2 127.0.0.1 $control >/dev/null 2>&1 || (exec 3<>/dev/tcp/127.0.0.1/$control) || return 1
		# The very next operations must succeed on their own.
		test "$(cat "$mnt/cut-idle")" = before && echo after >"$mnt/cut-idle" &&
			test "$(cat "$mnt/cut-idle")" = after && ls "$mnt" >/dev/null && rm "$mnt/cut-idle"
	}
	t_cut_busy() {
		head -c 268435456 /dev/urandom >"$work/busy" || return 1
		(sleep 1; (exec 3<>/dev/tcp/127.0.0.1/$control) 2>/dev/null) &
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
			(exec 3<>/dev/tcp/127.0.0.1/$control) 2>/dev/null
			echo "round $i" >"$mnt/cut-$i" && test "$(cat "$mnt/cut-$i")" = "round $i" && rm "$mnt/cut-$i" || return 1
		done
	}
	record "$cf" reconnect-after-cut-idle t_cut_idle
	record "$cf" reconnect-after-cut-during-copy t_cut_busy
	record "$cf" reconnect-after-repeated-cuts t_cut_repeated

	t_umount() { $sudo umount "$mnt"; }
	record "$cf" unmount t_umount
fi

# A client told to speak SMB 3.0 and nothing else, as older callers did.
t_vers30() {
	$sudo mount -t cifs "//127.0.0.1/$share" "$mnt" -o "${opts/vers=2.1/vers=3.0}" || return 1
	local ok=1
	echo "over 3.0" >"$mnt/v30" && test "$(cat "$mnt/v30")" = "over 3.0" && rm "$mnt/v30" && ok=0
	$sudo umount "$mnt"
	return $ok
}
record "$cf" mount-pinned-to-smb-3.0 t_vers30

if command -v docker >/dev/null 2>&1 && test "${SKIP_DOCKER:-}" = ""; then
	step "docker volume backed by cifs"
	dv=$results/docker-volume.txt
	: >"$dv"
	t_docker() {
		docker volume create --driver local -o type=cifs -o "device=//127.0.0.1/$share" \
			-o "o=addr=127.0.0.1,username=$user,password=$password,port=$port,vers=2.1" smbserver-test >/dev/null &&
			docker run --rm -v smbserver-test:/v busybox sh -c 'echo from-docker >/v/docker.txt && cat /v/docker.txt && ls /v >/dev/null' | grep -q from-docker &&
			test "$($sudo cat "$root/docker.txt")" = from-docker
	}
	record "$dv" volume-read-write t_docker
	docker volume rm -f smbserver-test >/dev/null 2>&1
fi

echo
test "$failed" = 0 && echo "ALL PASSED" || echo "SOME FAILED"
exit $failed
