# smbserver

An SMB 2 file server in pure Go, as a library: one directory, one share, one
user, on a listener you provide.

```go
ln, _ := net.Listen("tcp", ":1445")
err := smbserver.Serve(ctx, ln, smbserver.Config{
	Root:   "/data",
	Share:  "vol",
	User:   "dev",
	NTHash: smbserver.NTHash("the password"),
})
```

The native SMB client of Linux, macOS or Windows then mounts `//host/vol`.

## Why

A program that wants to hand a directory to a developer's machine over SMB
normally ships Samba: tens of megabytes in the image, configuration files, a
Unix account to fake, and capabilities when the process is root. This package
replaces all of that with a function call in the binary.

It was designed for two Softwarity projects, and their needs are what shaped
it:

- [plug](https://github.com/softwarity/plug) runs a local process as if it
  were inside the cluster. When that process needs the files of a workload,
  plug starts a helper next to the workload that serves its volume, and the
  developer's machine mounts it through plug's tunnel with the SMB client it
  already has.
- [meerkat](https://github.com/softwarity/meerkat-ce), a gateway that embeds
  plug's agent, serves volumes the same way from its own image.

Hence the choices made here: one share and one user per server, started and
stopped with the helper; nothing to install or configure on either side; a
mount that comes back on its own when the tunnel reconnects; no encryption,
since the tunnel provides it; and nothing left in a volume that belongs to
the cluster. Nothing in the package depends on either project, and it serves
any program with the same need.

It runs next to a workload, as that workload's user:

- **Any uid, no privilege.** No root, no capability, no `/etc/passwd` entry, no
  configuration or state file. The files it creates belong to the uid of the
  process and get the mode its umask gives.
- **Pure Go, no cgo.** The only dependency is `golang.org/x/crypto`, for the MD4
  of the NT hash.
- **A library.** No daemon, no global state: `Serve` runs until its context is
  cancelled.

It was written from Microsoft's open specifications ([MS-SMB2], [MS-NLMP],
[MS-SPNG], [MS-FSCC], [MS-ERREF], [MS-DTYP]) and from the observed behaviour of
the clients.

## Usage

```go
type Config struct {
	Root     string         // directory to serve
	Share    string         // share name, as in //host/Share
	User     string         // the only account
	NTHash   [16]byte       // NT hash of its password
	Allow    []netip.Prefix // accepted sources; empty means any
	ReadOnly bool           // refuse every modification
	Logf     func(format string, args ...any)
}

func Serve(ctx context.Context, ln net.Listener, cfg Config) error
func NTHash(password string) [16]byte
```

`Serve` accepts connections until `ctx` is cancelled, then closes the listener
and every connection and returns `nil`. The caller owns the listener, hence the
port: an unprivileged process cannot bind 445 and does not need to, except for
Windows (see below).

The server takes the NT hash rather than the password, so the caller never has
to hold the password itself: `NTHash` is MD4 over the UTF-16LE password.

### The command

`cmd/smbserver` serves a directory from the command line. It is the manual
test bench and what the integration tests run.

```
go run ./cmd/smbserver -root /tmp/share -addr :1445 -share vol -user dev -password secret -v
```

| Flag | Default | |
|---|---|---|
| `-root` | `.` | directory to serve |
| `-addr` | `:1445` | address to listen on |
| `-share` | `share` | share name |
| `-user` | `user` | user name |
| `-password` | `$SMB_PASSWORD` | password |
| `-allow` | any | comma separated source prefixes or addresses |
| `-readonly` | off | refuse modifications |
| `-v` | off | log connections and sessions |

Setting `SMBSERVER_TRACE=1` together with `-v` logs every command and its
status, which is how a client that misbehaves is diagnosed.

### Mounting

These are the client options the integration tests run with, and the
reference for a program that mounts the share on its user's behalf.

**Linux, kernel cifs**

```bash
mount -t cifs //host/vol /mnt -o username=dev,password=secret,port=1445,vers=2.1,uid=1000,gid=1000,noperm,hard
```

| Option | Why |
|---|---|
| `vers=2.1` | the dialect of the server. Optional: left out, the client negotiates it; `vers=3.0` works too |
| `hard` | a soft mount (the default) fails operations with `EAGAIN` while it reconnects; a hard one waits, and the cut goes unnoticed |
| `uid=`, `gid=`, `noperm` | the files appear as the local user's and the client does not second-guess the server on permissions |

A hard mount waits for a server that is gone for good, too: unmount (lazily if
need be) before stopping the server.

**Linux, Docker volume**

```bash
docker volume create --driver local -o type=cifs -o device=//host/vol \
  -o o=addr=host,username=dev,password=secret,port=1445,vers=2.1,hard vol
```

**macOS**

```bash
mount_smbfs -N //dev:secret@host:1445/vol /mnt
```

`-N` forbids any prompt. Nothing has to be set in `nsmb.conf`: the client
negotiates SMB 2.1 by itself, where multichannel does not exist.

**Windows**

```bat
net use S: \\host\vol secret /user:dev /persistent:no
```

The Windows redirector only ever connects to port 445, so the server must be
reachable there under the name or address the client uses: either the server
listens on 445, or something in front of it forwards 445 to its port. The
server checks neither the host name of the tree connect nor the target name of
the NTLM exchange, so any name that resolves to it works.

**smbclient**

```bash
smbclient //host/vol -p 1445 -U dev%secret
```

## Security

- **Confinement.** Nothing outside `Root` is reachable. Names are validated
  component by component (`..`, absolute paths, embedded separators and NUL are
  refused), then every access goes through `os.Root`, which resolves the path
  without leaving the directory. A symbolic link that points outside is
  listed, never followed; one that stays inside is followed.
- **Authentication first.** NTLMv2 only, through NTLMSSP in SPNEGO. LM and
  NTLMv1 responses, anonymous and guest sessions are refused. Before a
  session is established a peer can negotiate, authenticate and echo, nothing
  else.
- **Signing required.** Every request of a session must carry a valid
  signature (HMAC-SHA256, or AES-CMAC on SMB 3.0); every response is signed.
- **Source filter.** `Allow` is applied when the connection is accepted,
  before a single byte is read.
- **Bounds.** Message size (128 KiB before login, 8 MiB after), credits (8192),
  connections (256), sessions per connection (16), trees per session (16), open
  files (16384), commands per compound message (32), and a 30 second deadline to
  authenticate.
- **No panic.** Every client-controlled offset and length is checked; the
  decoders are fuzzed in CI; a connection that still manages to panic is
  closed and the process carries on.

There is no encryption (see the scope below). Run it
over a transport that provides confidentiality, a tunnel for instance.

## Scope

The rule is: the smallest server the native clients accept for one file share.
A feature gets in when a real client fails without it, with a trace or a test
as evidence. Everything else is answered with a clean "not supported".

What it does:

- SMB 2.0.2 and 2.1. An SMB1 multi-protocol negotiate is steered to SMB2; a
  client that only speaks SMB1 is disconnected.
- SMB 3.0 for a client that offers nothing lower, which is one mounted with an
  explicit `vers=3.0`: same server, signed with AES-CMAC, with the negotiate
  validation that dialect requires. A client that offers 2.1 gets 2.1.
- `NEGOTIATE`, `SESSION_SETUP`, `LOGOFF`, `TREE_CONNECT`, `TREE_DISCONNECT`,
  `CREATE`, `CLOSE`, `FLUSH`, `READ`, `WRITE`, `LOCK`, `QUERY_DIRECTORY`,
  `QUERY_INFO`, `SET_INFO`, `ECHO`, `CANCEL`, `IOCTL`.
- Credits, multi-credit reads and writes up to 8 MiB, compound requests.
- Rename, delete on close, truncation, timestamps, the read-only attribute
  (mapped to the write permission bits), filesystem size.
- Byte-range locks between the clients of the server, refused at once when
  they conflict.
- Named streams, held in memory and never written to the volume: this is
  where a macOS client puts Finder information and extended attributes, which
  it would otherwise scatter as `._name` files. They last as long as the
  server, within 64 MiB in total. Creating a `.DS_Store` is refused.
- Level II oplocks, so that clients may cache what they read. They are broken
  when the file is written through the server, and within a second when it
  is changed behind it, by the workload that owns the volume.

What it leaves out, and how clients cope:

| Feature | Answer | Clients |
|---|---|---|
| SMB 3.0.2 and 3.1.1, encryption, negotiate contexts | SMB 2.1 is negotiated | All negotiate down |
| Exclusive and batch oplocks, leases | level II at most | Readers cache, writers do not |
| Durable and persistent handles | ignored | After a cut, clients reopen by path |
| Multichannel | not offered | |
| Change notifications | not supported | Clients refresh on their own |
| Apple extensions (AAPL) | not negotiated | macOS uses plain named streams |
| Extended attributes | not supported | macOS stores them in named streams |
| Security descriptors | a fixed minimal one; setting is accepted and ignored | |
| Server-side copy, sparse files, reparse points | not supported | Clients copy through read and write |
| Symbolic links as such | followed on the server | |
| DFS | "not found" to referral requests | |
| Share enumeration (srvsvc) | IPC$ connects, holds no pipe | The share name must be known |
| Blocking byte-range locks | refused at once | |
| Kerberos, domains, printers, quotas, snapshots | none | |

Names are case sensitive, like the filesystem underneath, and the server says
so to the clients. Characters Windows forbids in a name (`: * ? " < > |`, a
trailing dot or space) travel in the private Unicode range the Linux and macOS
clients use for them, so a file named `a:b` in the volume is `a:b` on the
mounted side.

## Compatibility

The table below is written by CI from the result of the integration tests of
the last run on `main`: each client mounts the share and goes through the
same operations. On Linux the server runs under a uid that exists in no
account file, without any capability. Each mount is made without a prompt
and with nothing configured on the client beyond the mount command itself.
On the Windows runner the redirector is pointed at a high port with
`net use /tcpport`, which Windows Server 2025 and Windows 11 24H2 have; the
server it talks to is the Windows build of this package. A Windows client
against a server on Linux, through port 445, is the one combination CI does
not hold.

✅ passed, ❌ failed, · not part of that client's run: `smbclient` is not a
mount and has checks of its own, and the dialect can only be pinned on cifs.

<!-- matrix:start -->
| Operation | smbclient | Linux (cifs) | Docker volume (cifs) | macOS (mount_smbfs) | Windows (redirector) |
|---|:-:|:-:|:-:|:-:|:-:|
| login | ✅ | · | · | · | · |
| bad-password-refused | ✅ | ✅ | · | ✅ | ✅ |
| bad-user-refused | ✅ | · | · | · | · |
| put-get | ✅ | · | · | · | · |
| mkdir-rmdir | ✅ | · | · | · | · |
| rename-delete | ✅ | · | · | · | · |
| files-owned-by-server-uid | ✅ | · | · | · | · |
| no-escape | ✅ | · | · | · | · |
| mount | · | ✅ | ✅ | ✅ | ✅ |
| mkdir | · | ✅ | ✅ | ✅ | ✅ |
| create | · | ✅ | ✅ | ✅ | ✅ |
| write | · | ✅ | ✅ | ✅ | ✅ |
| read | · | ✅ | ✅ | ✅ | ✅ |
| append | · | ✅ | ✅ | ✅ | ✅ |
| overwrite | · | ✅ | ✅ | ✅ | ✅ |
| list | · | ✅ | ✅ | ✅ | ✅ |
| list-many | · | ✅ | ✅ | ✅ | ✅ |
| stat | · | ✅ | ✅ | ✅ | ✅ |
| rename | · | ✅ | ✅ | ✅ | ✅ |
| rename-over | · | ✅ | ✅ | ✅ | ✅ |
| rename-dir | · | ✅ | ✅ | ✅ | ✅ |
| move-across-dirs | · | ✅ | ✅ | ✅ | ✅ |
| delete | · | ✅ | ✅ | ✅ | ✅ |
| rmdir | · | ✅ | ✅ | ✅ | ✅ |
| rmdir-nonempty-refused | · | ✅ | ✅ | ✅ | ✅ |
| rm-recursive | · | ✅ | ✅ | ✅ | ✅ |
| truncate | · | ✅ | ✅ | ✅ | ✅ |
| dates | · | ✅ | ✅ | ✅ | ✅ |
| statfs | · | ✅ | ✅ | ✅ | ✅ |
| names | · | ✅ | ✅ | ✅ | ✅ |
| big-file-hash | · | ✅ | ✅ | ✅ | ✅ |
| concurrent-writes | · | ✅ | ✅ | ✅ | ✅ |
| concurrent-files | · | ✅ | ✅ | ✅ | ✅ |
| cleanup | · | ✅ | ✅ | ✅ | ✅ |
| no-traces-in-volume | · | ✅ | · | ✅ | ✅ |
| reconnect-after-cut-idle | · | ✅ | · | ✅ | ✅ |
| reconnect-after-cut-during-copy | · | ✅ | · | ✅ | ✅ |
| reconnect-after-repeated-cuts | · | ✅ | · | ✅ | ✅ |
| unmount | · | ✅ | · | ✅ | ✅ |
| mount-pinned-to-smb-3.0 | · | ✅ | · | · | · |
<!-- matrix:end -->

### Speed

Timings of everyday operations through a Linux cifs mount, against Samba on
the same machine with the same mount options, from the same CI run. Best of
three, client caches dropped before each.

<!-- bench:start -->
| Operation | smbserver | Samba 4.19.5-Ubuntu | Ratio |
|---|--:|--:|--:|
| Create 1000 files of 4 KiB | 2.28 s | 2.87 s | 0.8 |
| Read 1000 files of 4 KiB | 0.56 s | 0.45 s | 1.2 |
| List a directory of 5000 files | 0.88 s | 1.52 s | 0.6 |
| Write 100 MiB | 0.17 s | 0.16 s | 1.1 |
| Read 100 MiB | 0.19 s | 0.18 s | 1.1 |
<!-- bench:end -->

## Tests

```bash
go test -race ./...                                  # unit and socket-level tests
go test -run '^$' -fuzz '^FuzzMessage$' -fuzztime 1m . # one fuzz target

go build -o bin/ ./cmd/smbserver ./test/tcpcut
bash test/linux.sh bin results   # smbclient, cifs mount, docker volume; needs sudo
bash test/macos.sh bin results   # mount_smbfs
bash test/windows.sh bin results # net use, from Git Bash as administrator
bash test/bench.sh bin results   # timings against Samba; needs sudo and samba
```

- **Unit**: NTLMv2 against the vectors of [MS-NLMP], signing, the wire
  encodings, name validation.
- **Socket level** (`server_test.go`): a minimal SMB 2.1 client written for the
  tests checks authentication, signing, confinement, read-only mode, the source
  filter and the bounds, on every platform.
- **Fuzzing**: the decoders reachable before and after authentication.
- **Integration** (`test/`): the real clients, the operations of the matrix, a
  1 GiB file checked by hash, concurrent writers, and the cut test, where
  `test/tcpcut` drops the TCP connections under a mounted share and the next
  operations must succeed without anyone remounting.

To iterate on Linux clients from a Mac, the integration script runs in a
privileged container:

```bash
GOOS=linux go build -o /tmp/linbin/ ./cmd/smbserver ./test/tcpcut
docker run --rm --privileged -e SKIP_DOCKER=1 -e BIG_MB=64 \
  -v /tmp/linbin:/bin-smb:ro -v "$PWD/test:/test:ro" <image with smbclient and cifs-utils> \
  bash /test/linux.sh /bin-smb /tmp/results
```

## Releases

A release is an approval on a green run. Every CI run on `main` ends on a job
named "Release (approve to publish)", waiting on the `release` environment.
Approving it, in the page of the run (Review deployments) or from a terminal,
releases the commit that run tested: the `NEXT RELEASE` section of
`RELEASE_NOTES.md` becomes the new version, the commit is tagged `vX.Y.Z` and
the GitHub Release is published from those notes.

```bash
gh run list -R softwarity/smbserver --branch main --status waiting
gh api -X POST repos/softwarity/smbserver/actions/runs/<run-id>/pending_deployments \
  -f 'environment_ids[]=<env-id>' -f state=approved -f comment=minor
```

The bump rides in the comment of the approval: empty is a patch, `minor` or
`major` say so. Not approving costs nothing: the next push to `main` cancels
the waiting run. A commit whose message says `[skip release]` offers none.
Release notes pushed with `[skip ci]` after the run do not block it.

What the repository needs, once (Settings > Environments > `release`):

- **Required reviewers**: whoever may release. Without one the job stops with
  "nobody approved this release", since GitHub creates an unprotected
  environment the first time a job names it.
- **Deployment branches**: `main` only.
- Environment variable `RELEASE_APP_ID` and environment secret
  `RELEASE_APP_PRIVATE_KEY`: the GitHub App the Softwarity repositories
  release with, installed on this repository with Contents read and write.
  The job mints a one-hour token from it to push the version commit and the
  tag and to create the Release.

## License

[Apache-2.0](LICENSE).
