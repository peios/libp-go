package files

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	uapi "github.com/peios/pkm/uapi/go"
)

// PolicyKind is how KACS treats objects on a mount that lack managed
// security state.
type PolicyKind uint32

const (
	PolicyUnmanaged            PolicyKind = uapi.KACS_MOUNT_POLICY_UNMANAGED
	PolicyDenyMissing          PolicyKind = uapi.KACS_MOUNT_POLICY_DENY_MISSING
	PolicySynthesizeEphemeral  PolicyKind = uapi.KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL
	PolicySynthesizePersistent PolicyKind = uapi.KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT
)

// MountPolicy is the KACS security policy of a mounted filesystem.
type MountPolicy struct {
	// Policy is the kind of policy in force.
	Policy PolicyKind
	// Generation is the kernel's policy version counter. GetMountPolicy
	// reports the current value; pass it back unchanged to SetMountPolicy
	// to perform a get-modify-set without clobbering a concurrent change.
	Generation uint32
	// TemplateSD is the policy's template security descriptor, or nil
	// if the policy carries none.
	TemplateSD []byte
}

// GetMountPolicy returns the KACS mount policy of the filesystem that
// fd resides on. It requires the SeTcbPrivilege.
func GetMountPolicy(fd int) (MountPolicy, error) {
	// Probe with no template buffer: learn the policy and the template
	// length.
	probe := uapi.Kacs_mount_policy_args{}
	if err := mountPolicyCall(uapi.SYS_KACS_GET_MOUNT_POLICY, fd, &probe); err != nil {
		return MountPolicy{}, fmt.Errorf("libp/files: get mount policy: %w", err)
	}
	mp := MountPolicy{
		Policy:     PolicyKind(probe.Policy),
		Generation: probe.Generation,
	}
	if probe.Template_sd_len == 0 {
		return mp, nil
	}

	// Fetch the template security descriptor into a sized buffer.
	buf := make([]byte, probe.Template_sd_len)
	args := uapi.Kacs_mount_policy_args{
		Template_sd_ptr: uint64(uintptr(unsafe.Pointer(&buf[0]))),
		Template_sd_len: uint32(len(buf)),
	}
	err := mountPolicyCall(uapi.SYS_KACS_GET_MOUNT_POLICY, fd, &args)
	runtime.KeepAlive(buf)
	if err != nil {
		return MountPolicy{}, fmt.Errorf("libp/files: get mount policy: %w", err)
	}
	mp.TemplateSD = buf
	return mp, nil
}

// SetMountPolicy sets the KACS mount policy of the filesystem that fd
// resides on. It requires the SeTcbPrivilege.
func SetMountPolicy(fd int, mp MountPolicy) error {
	args := uapi.Kacs_mount_policy_args{
		Policy:     uint32(mp.Policy),
		Generation: mp.Generation,
	}
	if len(mp.TemplateSD) > 0 {
		args.Template_sd_ptr = uint64(uintptr(unsafe.Pointer(&mp.TemplateSD[0])))
		args.Template_sd_len = uint32(len(mp.TemplateSD))
	}
	err := mountPolicyCall(uapi.SYS_KACS_SET_MOUNT_POLICY, fd, &args)
	runtime.KeepAlive(mp.TemplateSD)
	if err != nil {
		return fmt.Errorf("libp/files: set mount policy: %w", err)
	}
	return nil
}

// mountPolicyCall issues one mount-policy syscall against args.
func mountPolicyCall(trap uintptr, fd int, args *uapi.Kacs_mount_policy_args) error {
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(trap, uintptr(fd),
			uintptr(unsafe.Pointer(args)), unsafe.Sizeof(*args))
		return 0, e
	})
	return err
}
