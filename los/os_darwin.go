//go:build darwin
// +build darwin

package los

func init() {
	OS = OSDarwin

	ExecExt = ""
	LibraryExt = ".dylib"

	PathSep = NixPathSep

	EnvVarSep = NixEnvVarSep
	PathEnvVar = NixPathEnvVar
}
