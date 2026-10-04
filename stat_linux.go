package smbserver

import (
	"os"
	"syscall"
	"time"
)

func sysStat(fi os.FileInfo) (sysInfo, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return sysInfo{}, false
	}
	return sysInfo{
		dev:   uint64(st.Dev),
		ino:   uint64(st.Ino),
		nlink: uint32(st.Nlink),
		alloc: uint64(st.Blocks) * 512,
		atime: time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)),
		ctime: time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
	}, true
}

// diskSpace reports the capacity of the filesystem holding dir, in units of
// unit bytes: total, free, and free to an unprivileged user.
func diskSpace(dir string) (total, free, avail uint64, unit uint32, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(dir, &st); err != nil {
		return
	}
	return uint64(st.Blocks), uint64(st.Bfree), uint64(st.Bavail), uint32(st.Bsize), nil
}
