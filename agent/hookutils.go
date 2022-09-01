package agent

import (
	"fmt"
	"os"
	"syscall"

	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/whids/event"
)

func toString(i any) string {
	return fmt.Sprintf("%v", i)
}

func toHex(i any) string {
	switch i.(type) {
	case int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("0x%x", i)
	}
	return "cannot format to hex"
}

func terminate(pid int) error {
	// prevents from terminating our own process
	if os.Getpid() != pid {
		pHandle, err := kernel32.OpenProcess(kernel32.PROCESS_ALL_ACCESS, win32.FALSE, win32.DWORD(pid))
		if err != nil {
			return err
		}
		err = syscall.TerminateProcess(syscall.Handle(pHandle), 0)
		if err != nil {
			return err
		}
	}
	return nil
}

// helper function which checks if the event belongs to current WHIDS
func isSysmonProcessTerminate(e *event.EdrEvent) bool {
	return e.Channel() == sysmonChannel && e.EventID() == SysmonProcessTerminate
}
