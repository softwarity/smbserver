#!/usr/bin/env bash
# Times a developer's everyday operations through a cifs mount of this server
# and of Samba, on the same machine, with the same mount options. The point
# is not an absolute figure but the ratio: a server noticeably slower than
# Samba in ordinary use is not acceptable.
#
# usage: bench.sh <bin-dir> [results-dir]
#
# Needs root or passwordless sudo, cifs-utils and samba.
set -u

bin=$(cd "${1:?usage: bench.sh <bin-dir> [results-dir]}" && pwd)
results=${2:-$(mktemp -d)}
mkdir -p "$results"

uid=54321
user=bench
password=bench-pass
work=$(mktemp -d)
sudo=
test "$(id -u)" = 0 || sudo=sudo
opts="username=$user,password=$password,vers=2.1,uid=$(id -u),gid=$(id -g),noperm,hard"

cleanup() {
	for m in ours samba; do $sudo umount -f "$work/mnt-$m" 2>/dev/null; done
	$sudo kill "$ours_pid" "$samba_pid" 2>/dev/null
	$sudo rm -rf "$work"
}
trap cleanup EXIT

chmod 755 "$work"
mkdir -p "$work/root-ours" "$work/root-samba" "$work/mnt-ours" "$work/mnt-samba" "$work/samba"
$sudo chown $uid:$uid "$work/root-ours"

$sudo setpriv --reuid=$uid --regid=$uid --clear-groups "$bin/smbserver" -root "$work/root-ours" -addr 127.0.0.1:1445 \
	-share vol -user $user -password "$password" >"$work/ours.log" 2>&1 &
ours_pid=$!

# Samba needs a Unix account behind its user.
id $user >/dev/null 2>&1 || $sudo useradd -M -s /usr/sbin/nologin $user
$sudo chown $user "$work/root-samba"
cat >"$work/smb.conf" <<EOF
[global]
	smb ports = 1455
	security = user
	map to guest = Never
	server signing = mandatory
	disable netbios = yes
	load printers = no
	private dir = $work/samba
	lock directory = $work/samba
	state directory = $work/samba
	cache directory = $work/samba
	pid directory = $work/samba
	ncalrpc dir = $work/samba/ncalrpc
	log file = $work/samba/log
[vol]
	path = $work/root-samba
	read only = no
	valid users = $user
EOF
printf '%s\n%s\n' "$password" "$password" | $sudo smbpasswd -c "$work/smb.conf" -a -s $user >/dev/null
# In a session of its own: smbd signals its whole process group when it
# stops, which would take the caller of this script down with it.
$sudo setsid smbd --foreground --no-process-group -s "$work/smb.conf" >"$work/samba.log" 2>&1 &
samba_pid=$!

for port in 1445 1455; do
	for _ in $(seq 1 100); do
		(exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break
		sleep 0.1
	done
done
$sudo mount -t cifs //127.0.0.1/vol "$work/mnt-ours" -o "$opts,port=1445" || exit 1
$sudo mount -t cifs //127.0.0.1/vol "$work/mnt-samba" -o "$opts,port=1455" || { tail "$work/samba.log" "$work/samba/log"*; exit 1; }

# Each measure starts from cold client caches, so that it times the protocol
# and not the page cache of the client.
cold() { sync; echo 3 | $sudo tee /proc/sys/vm/drop_caches >/dev/null; }
# timed <command...>: best of three, in seconds.
timed() {
	local best= i s e t
	for i in 1 2 3; do
		cold
		s=$(date +%s.%N)
		"$@" >/dev/null 2>&1 || { echo failed; return; }
		e=$(date +%s.%N)
		t=$(awk "BEGIN{printf \"%.2f\", $e-$s}")
		if test -z "$best" || awk "BEGIN{exit !($t<$best)}"; then best=$t; fi
	done
	echo "$best"
}

b_small_write() { rm -rf "$1/small"; mkdir "$1/small" && for i in $(seq 1 1000); do head -c 4096 /dev/zero >"$1/small/f$i" || return 1; done; }
b_small_read() { cat "$1"/small/f* | wc -c; }
b_list_prepare() { mkdir -p "$1/many" && (cd "$1/many" && seq 1 5000 | xargs touch); }
b_list() { ls -l "$1/many" | wc -l; }
b_write() { dd if=/dev/zero of="$1/big" bs=1M count=100 conv=fsync; }
b_read() { dd if="$1/big" of=/dev/null bs=1M; }

declare -a rows
measure() {
	local title=$1 fn=$2 ours samba ratio
	ours=$(timed $fn "$work/mnt-ours")
	samba=$(timed $fn "$work/mnt-samba")
	ratio=$(awk "BEGIN{if ($samba>0) printf \"%.1f\", $ours/$samba; else print \"-\"}" 2>/dev/null)
	rows+=("| $title | $ours s | $samba s | $ratio |")
	echo "$title: smbserver ${ours}s, samba ${samba}s"
}

b_list_prepare "$work/mnt-ours" >/dev/null 2>&1
b_list_prepare "$work/mnt-samba" >/dev/null 2>&1
measure "Create 1000 files of 4 KiB" b_small_write
measure "Read 1000 files of 4 KiB" b_small_read
measure "List a directory of 5000 files" b_list
measure "Write 100 MiB" b_write
measure "Read 100 MiB" b_read

{
	echo "| Operation | smbserver | Samba $(smbd --version | awk '{print $2}') | Ratio |"
	echo "|---|--:|--:|--:|"
	printf '%s\n' "${rows[@]}"
} >"$results/bench.md"
echo
cat "$results/bench.md"
