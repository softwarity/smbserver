# smbserver

An SMB 2 file server in pure Go, as a library (`github.com/softwarity/smbserver`).
One directory, one share, one user, on a listener the caller provides. Its
first consumer is plug (`github.com/softwarity/plug`), whose helper serves a
workload's volume to the developer's machine; the library itself knows
nothing about plug.

The README is the documentation: scope, security model, client options,
compatibility matrix. There is no documentation site. Keep the README current
with every change of behaviour.

## What decides

1. **The developer's experience.** The mount must work with no action from the
   person: no prompt, nothing to install or configure, no manual recovery
   after a cut, no trace left in the volume (`._*`, `.DS_Store`), no
   perceptible slowness. Any option needed on the client must be one plug can
   set by itself at mount time.
2. **The smallest server the native clients accept.** A feature gets in when a
   real client fails without it, with a trace or a test as evidence; a prompt
   or a manual setting counts as a failure. Everything else answers "not
   supported", and the README table "What it leaves out" says so.
3. When the two conflict, the experience wins.

Clients that must work: Linux kernel cifs (`mount -t cifs`, and as a Docker
volume), macOS `mount_smbfs`, the Windows redirector, and `smbclient` as the
quick test client.

## Hard constraints

- Pure Go, no cgo, Go 1.26. Must build on linux, darwin and windows.
- Runs under any uid: no root, no capability, no account file, no file on
  disk besides the served directory.
- No access outside `Config.Root`: names are validated in `names.go`, then
  every filesystem access goes through `os.Root`. Never open a path with the
  `os` package functions directly.
- Nothing is served before authentication; every client-controlled length or
  offset goes through `sub` or an explicit bound.
- Never copy code from Samba or any GPL or AGPL implementation. Work from the
  Microsoft open specifications and observed client behaviour.

## Layout

| File | Content |
|---|---|
| `smbserver.go` | `Config`, `Serve`, limits, accept loop |
| `conn.go` | framing, compound requests, credits, signing, dispatch |
| `negotiate.go` | dialects (2.1 preferred, 3.0 only for clients pinned to it), SMB1 to SMB2 switch |
| `crypto.go` | AES-CMAC signing of SMB 3.0 |
| `session.go` | session setup, tree connect |
| `spnego.go`, `ntlm.go` | SPNEGO wrapping, NTLMv2 |
| `open.go` | CREATE, CLOSE, handle table, delete on close |
| `io.go`, `dir.go`, `info.go`, `lock.go`, `ioctl.go` | the other commands |
| `oplock.go` | level II oplocks, watch for changes made behind the server |
| `streams.go` | named streams kept in memory |
| `names.go` | path validation, character mapping, wildcards |
| `stat*.go` | per-OS file metadata and disk space |
| `cmd/smbserver` | command for manual tests and CI |
| `test/` | integration scripts, the cut relay, the matrix generator |

## Working here

- Work on `main`, no branches. Commit and push freely; use CI as needed.
- Never a `Co-Authored-By` line nor any mention of Claude or Anthropic in
  commits or pull requests.
- Never the em dash character (U+2014), anywhere.
- Public repository: no customer name, no private data.
- A commit that touches no code (README, notes) ends with `[skip ci]`.
- `RELEASE_NOTES.md`: write only under `## NEXT RELEASE`, never touch the
  numbered sections nor the heading line. A note says what the version
  brings, not what the previous one got wrong.
- Code comments in English, explaining why. README in English.
- Look for the simplest form that covers all cases.
- Tests without OS-specific literal paths (`t.TempDir()`, `filepath.Join`).
- CI rewrites the compatibility table of the README on `main`: pull before
  pushing.
- A release is an approval of the last job of a green CI run on `main` (see
  "Releases" in the README). Never approve one yourself; a commit that
  should not be offered for release says `[skip release]`.

## Testing

```bash
go test -race ./...
bash test/linux.sh bin results   # needs sudo, smbclient, cifs-utils
bash test/macos.sh bin results
bash test/windows.sh bin results # Git Bash, administrator
bash test/bench.sh bin results   # timings against Samba
```

From a Mac, Linux clients run in a privileged container (see the README).
A local `mount_smbfs` needs the terminal to be allowed on network volumes
(System Settings, Privacy and Security, Files and Folders); without it the
mount succeeds but listing and reading fail with "Operation not permitted".

`SMBSERVER_TRACE=1` with `-v` logs every command and its status.
