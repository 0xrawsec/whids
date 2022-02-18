package os

const (
	OSWindows = "windows"
	OSLinux   = "linux"
	OSDarwin  = "darwin"
)

var (
	OS string
)

func IsKnownOS(os string) bool {
	return os == OSWindows || os == OSLinux || os == OSDarwin
}
