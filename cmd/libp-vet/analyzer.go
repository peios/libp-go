package main

import (
	"go/ast"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// uapiImportPath is the generated UAPI binding — libp's mechanical
// layer. Consumer code uses the libp tier, not this directly.
const uapiImportPath = "github.com/peios/pkm/uapi/go"

// libpGoModule is the libp-go library module path. Its own packages may
// import the uapi binding; consumer code may not.
const libpGoModule = "github.com/peios/libp-go"

// analyzer is the libp-vet forbidden-surface analyzer.
var analyzer = &analysis.Analyzer{
	Name:     "libpvet",
	Doc:      "flag the POSIX-identity stdlib surface and direct uapi imports in libp-using code",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// Why-categories shared by the banned entries below.
const (
	whyIdentity = "POSIX uid/gid is meaningless on Peios — identity is the KACS token (libp-go/token)"
	whyMode     = "POSIX mode bits are meaningless on Peios — authority is a security descriptor (libp-go/sd)"
	whyCred     = "POSIX credentials are meaningless on Peios — use KACS tokens (libp-go/token)"
)

// bannedRef names one forbidden function, method, or struct field by
// its defining package's import path and its identifier. One entry
// covers both a package function and a same-named method — e.g. os.Chmod
// and (*os.File).Chmod both resolve to (os, Chmod).
type bannedRef struct {
	pkg  string
	name string
	why  string
}

var banned = []bannedRef{
	{"os", "Getuid", whyIdentity},
	{"os", "Geteuid", whyIdentity},
	{"os", "Getgid", whyIdentity},
	{"os", "Getegid", whyIdentity},
	{"os", "Getgroups", whyIdentity},
	{"os", "Chmod", whyMode},
	{"os", "Chown", whyMode},
	{"os", "Lchown", whyMode},
	{"syscall", "Getuid", whyIdentity},
	{"syscall", "Geteuid", whyIdentity},
	{"syscall", "Getgid", whyIdentity},
	{"syscall", "Getegid", whyIdentity},
	{"syscall", "Getgroups", whyIdentity},
	{"syscall", "Setuid", whyIdentity},
	{"syscall", "Setgid", whyIdentity},
	{"syscall", "Setgroups", whyIdentity},
	{"syscall", "Chmod", whyMode},
	{"syscall", "Chown", whyMode},
	{"syscall", "Fchown", whyMode},
	{"syscall", "Lchown", whyMode},
	{"syscall", "Uid", whyIdentity},    // syscall.Stat_t.Uid and kin
	{"syscall", "Gid", whyIdentity},    // syscall.Stat_t.Gid and kin
	{"syscall", "Credential", whyCred}, // syscall.SysProcAttr.Credential
}

// isLibpGoInternal reports whether pkgPath is a package of the libp-go
// library module — which may legitimately import the uapi binding.
func isLibpGoInternal(pkgPath string) bool {
	return pkgPath == libpGoModule || strings.HasPrefix(pkgPath, libpGoModule+"/")
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	internal := isLibpGoInternal(pass.Pkg.Path())

	// Forbidden imports.
	insp.Preorder([]ast.Node{(*ast.ImportSpec)(nil)}, func(n ast.Node) {
		spec := n.(*ast.ImportSpec)
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return
		}
		switch {
		case path == "os/user":
			pass.Reportf(spec.Pos(),
				"libp-vet: importing os/user is forbidden — %s", whyIdentity)
		case path == uapiImportPath && !internal:
			pass.Reportf(spec.Pos(),
				"libp-vet: directly importing %s is forbidden — it is libp's mechanical layer; use the libp tier (token/sd/files/event)",
				uapiImportPath)
		}
	})

	// Forbidden functions, methods, and struct fields.
	insp.Preorder([]ast.Node{(*ast.SelectorExpr)(nil)}, func(n ast.Node) {
		sel := n.(*ast.SelectorExpr)
		obj := pass.TypesInfo.Uses[sel.Sel]
		if obj == nil {
			if s := pass.TypesInfo.Selections[sel]; s != nil {
				obj = s.Obj()
			}
		}
		if obj == nil || obj.Pkg() == nil {
			return
		}
		for _, b := range banned {
			if obj.Pkg().Path() == b.pkg && obj.Name() == b.name {
				pass.Reportf(sel.Sel.Pos(),
					"libp-vet: %s.%s is forbidden — %s", b.pkg, b.name, b.why)
				return
			}
		}
	})

	return nil, nil
}
