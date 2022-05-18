//go:build linux
// +build linux

package los

func init() {
	OS = OSLinux

	ExecExt = ""
	LibraryExt = ".so"

	PathSep = NixPathSep

	EnvVarSep = NixEnvVarSep
	PathEnvVar = NixPathEnvVar
}
