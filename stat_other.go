//go:build !linux && !darwin

package smbserver

import (
	"errors"
	"os"
)

// On platforms without a portable inode the server falls back on paths for
// file identity and on a fixed figure for the capacity. The package is meant
// to run on Linux; these exist so that it builds and its tests run elsewhere.

func sysStat(os.FileInfo) (sysInfo, bool) { return sysInfo{}, false }

func diskSpace(string) (total, free, avail uint64, unit uint32, err error) {
	return 0, 0, 0, 0, errors.ErrUnsupported
}
