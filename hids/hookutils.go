package hids

import (
	"fmt"
	"os"
	"sort"
	"syscall"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/0xrawsec/whids/utils"
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
func isSysmonProcessTerminate(e *evtx.GoEvtxMap) bool {
	return e.Channel() == sysmonChannel && e.EventID() == SysmonProcessTerminate
}

func srcPIDFromEvent(e *evtx.GoEvtxMap) int64 {

	if pid, err := e.GetInt(&pathSysmonProcessId); err == nil {
		return pid
	}

	if pid, err := e.GetInt(&pathSysmonSourceProcessId); err == nil {
		return pid
	}

	return -1
}

func srcGUIDFromEvent(e *evtx.GoEvtxMap) string {
	var procGUIDPath *evtx.GoEvtxPath

	// the interesting pid to dump depends on the event
	switch e.EventID() {
	case SysmonAccessProcess:
		procGUIDPath = &pathSysmonSourceProcessGUID
	case SysmonCreateRemoteThread:
		procGUIDPath = &pathSysmonCRTSourceProcessGuid
	default:
		procGUIDPath = &pathSysmonProcessGUID
	}

	if guid, err := e.GetString(procGUIDPath); err == nil {
		return guid
	}

	return nullGUID
}

func processTrackFromEvent(h *HIDS, e *evtx.GoEvtxMap) *ProcessTrack {
	if uuid := srcGUIDFromEvent(e); uuid != nullGUID {
		return h.processTracker.GetByGuid(uuid)
	}
	return nil
}

func hasAction(e *evtx.GoEvtxMap, action string) bool {
	if i, err := e.Get(&engine.ActionsPath); err == nil {
		if actions, ok := (*i).([]string); ok {
			for _, a := range actions {
				if a == action {
					return true
				}
			}
		}
	}
	return false
}

// Todo: move this function into evtx package
func eventHas(e *evtx.GoEvtxMap, p *evtx.GoEvtxPath) bool {
	_, err := e.GetString(p)
	return err == nil
}

func getCriticality(e *evtx.GoEvtxMap) int {
	if c, err := e.Get(&pathGeneCriticality); err == nil {
		return (*c).(int)
	}
	return 0
}

func idFromEvent(e *evtx.GoEvtxMap) string {
	bs := utils.ByteSlice(evtx.ToJSON(e))
	sort.Stable(bs)
	return data.Md5(bs)
}
