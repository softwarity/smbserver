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

It is meant to run next to a workload, as that workload's user:

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

```bash
# Linux
mount -t cifs //host/vol /mnt -o username=dev,password=secret,port=1445,vers=2.1,hard

# Linux, as a Docker volume
docker volume create --driver local -o type=cifs -o device=//host/vol \
  -o o=addr=host,username=dev,password=secret,port=1445,vers=2.1 vol

# macOS
mount_smbfs -N //dev:secret@host:1445/vol /mnt

# anywhere
smbclient //host/vol -p 1445 -U dev%secret
```

On Linux, `hard` matters: a soft cifs mount (the default) fails operations
with `EAGAIN` while it reconnects, a hard one waits for the connection to come
back.

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
  HMAC-SHA256 signature; every response is signed.
- **Source filter.** `Allow` is applied when the connection is accepted,
  before a single byte is read.
- **Bounds.** Message size (128 KiB before login, 8 MiB after), credits (8192),
  connections (256), sessions per connection (16), trees per session (16), open
  files (16384), commands per compound message (32), and a 30 second deadline to
  authenticate.
- **No panic.** Every client-controlled offset and length is checked; the
  decoders are fuzzed in CI; a connection that still manages to panic is
  closed and the process carries on.

There is no encryption: the protocol is capped at SMB 2.1 (see below). Run it
over a transport that provides confidentiality, a tunnel for instance.

## Scope

The rule is: the smallest server the native clients accept for one file share.
A feature gets in when a real client fails without it, with a trace or a test
as evidence. Everything else is answered with a clean "not supported".

What it does:

- SMB 2.0.2 and 2.1. An SMB1 multi-protocol negotiate is steered to SMB2; a
  client that only speaks SMB1 is disconnected.
- `NEGOTIATE`, `SESSION_SETUP`, `LOGOFF`, `TREE_CONNECT`, `TREE_DISCONNECT`,
  `CREATE`, `CLOSE`, `FLUSH`, `READ`, `WRITE`, `LOCK`, `QUERY_DIRECTORY`,
  `QUERY_INFO`, `SET_INFO`, `ECHO`, `CANCEL`, `IOCTL`.
- Credits, multi-credit reads and writes up to 8 MiB, compound requests.
- Rename, delete on close, truncation, timestamps, the read-only attribute
  (mapped to the write permission bits), filesystem size.
- Byte-range locks between the clients of the server, refused at once when
  they conflict.

What it leaves out, and how clients cope:

| Feature | Answer | Clients |
|---|---|---|
| SMB 3.x, encryption, negotiate contexts | SMB 2.1 is negotiated | All negotiate down |
| `FSCTL_VALIDATE_NEGOTIATE_INFO` | not supported | Only required on SMB 3.0 |
| Oplocks and leases | none granted | Clients cache less |
| Durable and persistent handles | ignored | After a cut, clients reopen by path |
| Multichannel | not offered | |
| Change notifications | not supported | Clients refresh on their own |
| Named streams, Apple extensions (AAPL) | names with a stream are refused | See the matrix |
| Extended attributes | not supported | |
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
the last run on `main`: each client mounts a server running under an
unprivileged uid and goes through the same operations.

<!-- matrix:start -->
<!-- matrix:end -->

Windows is not covered yet: its redirector only connects to port 445, which
the runner's own SMB server holds.

## Tests

```bash
go test -race ./...                                  # unit and socket-level tests
go test -run '^$' -fuzz '^FuzzMessage$' -fuzztime 1m . # one fuzz target

go build -o bin/ ./cmd/smbserver ./test/tcpcut
bash test/linux.sh bin results   # smbclient, cifs mount, docker volume; needs sudo
bash test/macos.sh bin results   # mount_smbfs
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

`RELEASE_NOTES.md` holds the notes; the `Release` workflow turns its
`NEXT RELEASE` section into a version, tags it and publishes the GitHub
Release.

## License

[Apache-2.0](LICENSE).
