// Command libp-vet flags the host stdlib's POSIX-identity surface, and
// direct imports of the generated uapi binding from consumer code, in
// libp-using Go.
//
// uid/gid/mode are meaningless on Peios — identity is the KACS token,
// authority is a security descriptor. Code that reads or authorizes off
// the POSIX surface (os/user, os.Getuid, os.Chmod, syscall.Stat_t.Uid,
// exec.Cmd.SysProcAttr.Credential, …) has a security bug, not a style
// nit. libp-vet makes that enforced rather than merely documented.
//
// Run it like go vet:
//
//	libp-vet ./...
//
// It is CI-enforced in libp-go and in every daemon repo. See
// libp-design.md §2.7.
package main

import "golang.org/x/tools/go/analysis/singlechecker"

func main() {
	singlechecker.Main(analyzer)
}
