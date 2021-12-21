package hids

import (
	"fmt"
	"os"
	"syscall"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/whids/event"
)

func toString(i interface{}) string {
	return fmt.Sprintf("%v", i)
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

func srcPIDFromEvent(e *event.EdrEvent) int64 {

	if pid, ok := e.GetInt(pathSysmonProcessId); ok {
		return pid
	}

	if pid, ok := e.GetInt(pathSysmonSourceProcessId); ok {
		return pid
	}

	return -1
}

func srcGUIDFromEvent(e *event.EdrEvent) string {
	var procGUIDPath engine.XPath

	// the interesting pid to dump depends on the event
	switch e.EventID() {
	case SysmonAccessProcess:
		procGUIDPath = pathSysmonSourceProcessGUID
	case SysmonCreateRemoteThread:
		procGUIDPath = pathSysmonCRTSourceProcessGuid
	default:
		procGUIDPath = pathSysmonProcessGUID
	}

	if guid, ok := e.GetString(procGUIDPath); ok {
		return guid
	}

	return nullGUID
}

func processTrackFromEvent(h *HIDS, e *event.EdrEvent) *ProcessTrack {
	if uuid := srcGUIDFromEvent(e); uuid != nullGUID {
		return h.tracker.GetByGuid(uuid)
	}
	return EmptyProcessTrack()
}

func hasAction(e *event.EdrEvent, action string) bool {
	if d := e.GetDetection(); d != nil {
		return d.Actions.Contains(action)
	}
	return false
}

// Todo: move this function into evtx package
func eventHas(e *event.EdrEvent, p engine.XPath) bool {
	_, ok := e.GetString(p)
	return ok
}

func getCriticality(e *event.EdrEvent) int {
	if d := e.GetDetection(); d != nil {
		return d.Criticality
	}
	return 0
}
