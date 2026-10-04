# Release Notes

## NEXT RELEASE

### First release

An SMB 2 file server as a Go library: one directory, one share, one user, on a
listener you provide.

- **No privilege.** It runs under any uid, without root, capabilities, account
  files or configuration on disk. Files it creates belong to the uid of the
  process.
- **Native clients.** Mounts with the Linux kernel (cifs), macOS
  (`mount_smbfs`) and `smbclient`, and resumes on its own after the connection
  is cut.
- **Confined.** Nothing outside the served directory is reachable, symbolic
  links included; NTLMv2 authentication and signed requests are mandatory.
