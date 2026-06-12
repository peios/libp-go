// Package errno is libp-go's typed kernel error number.
//
// A failed Peios syscall returns a negated errno; Errno is its typed Go
// form. It implements error and is comparable, so it works directly with
// errors.Is against the sentinels below.
//
// errno is hand-written and libp-go-owned. The pkm UAPI binding
// (github.com/peios/pkm/uapi/go) is purely generated struct layouts and
// #define constants; pkm publishes no errno header, so that binding
// carries no error type. See libp-design.md §2.4.
package errno

import "strconv"

// Errno is a Peios kernel error number — the negated return value of a
// failed syscall.
type Errno int32

// Standard Linux errno numbering. Extended as domain packages need more.
const (
	EPERM   Errno = 1
	ENOENT  Errno = 2
	EINTR   Errno = 4
	EIO     Errno = 5
	EBADF   Errno = 9
	EAGAIN  Errno = 11
	EACCES  Errno = 13
	EFAULT  Errno = 14
	EBUSY   Errno = 16
	EEXIST  Errno = 17
	ENOTDIR Errno = 20
	EISDIR  Errno = 21
	EINVAL  Errno = 22
	ENOTTY  Errno = 25
	ERANGE  Errno = 34
	ENOSYS  Errno = 38
)

func (e Errno) Error() string {
	switch e {
	case EPERM:
		return "operation not permitted"
	case ENOENT:
		return "no such file or directory"
	case EINTR:
		return "interrupted system call"
	case EIO:
		return "input/output error"
	case EBADF:
		return "bad file descriptor"
	case EAGAIN:
		return "resource temporarily unavailable"
	case EACCES:
		return "permission denied"
	case EFAULT:
		return "bad address"
	case EBUSY:
		return "device or resource busy"
	case EEXIST:
		return "file exists"
	case ENOTDIR:
		return "not a directory"
	case EISDIR:
		return "is a directory"
	case EINVAL:
		return "invalid argument"
	case ENOTTY:
		return "inappropriate ioctl for device"
	case ERANGE:
		return "numerical result out of range"
	case ENOSYS:
		return "function not implemented"
	default:
		return "errno " + strconv.Itoa(int(e))
	}
}
