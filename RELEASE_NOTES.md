# Release Notes

## NEXT RELEASE

---

## 0.1.1

### The Finder and the Explorer

- **Copying with the Finder needs no confirmation.** The Finder sees the share
  as a folder it can read and write, and copies into it without asking.
- **Checked with the desktop applications.** Browsing, copying and renaming
  through the Finder, and copying through the Windows Explorer with its
  alternate streams, are part of what every build is tested against.

---

## 0.1.0

### First release

An SMB 2 file server as a Go library: one directory, one share, one user, on a
listener you provide.

- **No privilege.** It runs under any uid, without root, capabilities, account
  files or configuration on disk. Files it creates belong to the uid of the
  process.
- **Native clients.** Mounts with the Linux kernel (cifs), macOS
  (`mount_smbfs`) and `smbclient`, and resumes on its own after the connection
  is cut.
- **Nothing left behind.** What macOS attaches to the files it copies goes to
  named streams the server keeps in memory, not to `._` files in the volume.
- **Fast on small files.** Clients may cache what they read, and are told
  when a file changes, including when the workload writes it directly.
- **Confined.** Nothing outside the served directory is reachable, symbolic
  links included; NTLMv2 authentication and signed requests are mandatory.
