// Package consumer exercises the forbidden POSIX-identity surface so
// libp-vet's analysistest can confirm every misuse is flagged. Each
// flagged line carries an analysistest expectation comment.
package consumer

import (
	"os"
	"os/user" // want `importing os/user is forbidden`
	"syscall"
)

func uses() (int, error) {
	uid := os.Getuid()                                // want `os\.Getuid is forbidden`
	_ = os.Geteuid()                                  // want `os\.Geteuid is forbidden`
	_ = syscall.Getgid()                              // want `syscall\.Getgid is forbidden`
	if err := os.Chmod("/etc/x", 0o600); err != nil { // want `os\.Chmod is forbidden`
		return uid, err
	}
	cur, _ := user.Current()
	_ = cur

	var st syscall.Stat_t
	_ = st.Uid // want `syscall\.Uid is forbidden`
	return uid, nil
}
