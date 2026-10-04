package smbserver

import (
	"errors"
	"io/fs"
	"syscall"
)

// ntStatus is an NTSTATUS value as defined in [MS-ERREF].
type ntStatus uint32

const (
	statusSuccess                ntStatus = 0x00000000
	statusPending                ntStatus = 0x00000103
	statusNotifyCleanup          ntStatus = 0x0000010B
	statusBufferOverflow         ntStatus = 0x80000005
	statusNoMoreFiles            ntStatus = 0x80000006
	statusInvalidInfoClass       ntStatus = 0xC0000003
	statusInfoLengthMismatch     ntStatus = 0xC0000004
	statusInvalidParameter       ntStatus = 0xC000000D
	statusNoSuchFile             ntStatus = 0xC000000F
	statusInvalidDeviceRequest   ntStatus = 0xC0000010
	statusEndOfFile              ntStatus = 0xC0000011
	statusMoreProcessingRequired ntStatus = 0xC0000016
	statusAccessDenied           ntStatus = 0xC0000022
	statusBufferTooSmall         ntStatus = 0xC0000023
	statusObjectNameInvalid      ntStatus = 0xC0000033
	statusObjectNameNotFound     ntStatus = 0xC0000034
	statusObjectNameCollision    ntStatus = 0xC0000035
	statusObjectPathNotFound     ntStatus = 0xC000003A
	statusSharingViolation       ntStatus = 0xC0000043
	statusEasNotSupported        ntStatus = 0xC000004F
	statusNoEasOnFile            ntStatus = 0xC0000052
	statusLockNotGranted         ntStatus = 0xC0000055
	statusDeletePending          ntStatus = 0xC0000056
	statusLogonFailure           ntStatus = 0xC000006D
	statusRangeNotLocked         ntStatus = 0xC000007E
	statusDiskFull               ntStatus = 0xC000007F
	statusInsufficientResources  ntStatus = 0xC000009A
	statusMediaWriteProtected    ntStatus = 0xC00000A2
	statusFileIsADirectory       ntStatus = 0xC00000BA
	statusNotSupported           ntStatus = 0xC00000BB
	statusNetworkNameDeleted     ntStatus = 0xC00000C9
	statusBadNetworkName         ntStatus = 0xC00000CC
	statusRequestNotAccepted     ntStatus = 0xC00000D0
	statusNotSameDevice          ntStatus = 0xC00000D4
	statusDirectoryNotEmpty      ntStatus = 0xC0000101
	statusNotADirectory          ntStatus = 0xC0000103
	statusTooManyOpenedFiles     ntStatus = 0xC000011F
	statusCancelled              ntStatus = 0xC0000120
	statusFileClosed             ntStatus = 0xC0000128
	statusUserSessionDeleted     ntStatus = 0xC0000203
	statusNotFound               ntStatus = 0xC0000225
	statusNotAReparsePoint       ntStatus = 0xC0000275
)

// errStatus maps a filesystem error to the status a Windows server would
// return for the same situation. Anything unrecognised, including the error
// os.Root reports when a path escapes the share, becomes ACCESS_DENIED so
// that no detail about the host leaks to the client.
func errStatus(err error) ntStatus {
	switch {
	case err == nil:
		return statusSuccess
	// ENOTEMPTY must be tested before fs.ErrExist, which also matches it.
	case errors.Is(err, syscall.ENOTEMPTY):
		return statusDirectoryNotEmpty
	case errors.Is(err, fs.ErrNotExist):
		return statusObjectNameNotFound
	case errors.Is(err, fs.ErrExist):
		return statusObjectNameCollision
	case errors.Is(err, fs.ErrPermission):
		return statusAccessDenied
	case errors.Is(err, fs.ErrClosed):
		return statusFileClosed
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return statusDiskFull
	case errors.Is(err, syscall.EISDIR):
		return statusFileIsADirectory
	case errors.Is(err, syscall.ENOTDIR):
		return statusObjectPathNotFound
	case errors.Is(err, syscall.EROFS):
		return statusMediaWriteProtected
	case errors.Is(err, syscall.EXDEV):
		return statusNotSameDevice
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		return statusTooManyOpenedFiles
	case errors.Is(err, syscall.ENAMETOOLONG):
		return statusObjectNameInvalid
	case errors.Is(err, syscall.EINVAL):
		return statusInvalidParameter
	}
	return statusAccessDenied
}
