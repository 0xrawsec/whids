//go:build windows
// +build windows

package los

func init() {
	OS = OSWindows

	ExecExt = ".exe"
	LibraryExt = ".dll"

	PathSep = WinPathSep

	EnvVarSep = WinEnvVarSep
	PathEnvVar = WinPathEnvVar
}
