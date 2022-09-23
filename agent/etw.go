package agent

import (
	"github.com/0xrawsec/golang-etw/etw"
	"github.com/0xrawsec/whids/utils"
)

var (
	microsoftKernelFileGUID = etw.MustParseGUIDFromString("{EDD08927-9CC4-4E65-B970-C2560FB5C289}")
	targetFileName          = pathSysmonTargetFilename.Last()
)

func (a *Agent) eventRecordCallback(er *etw.EventRecord) bool {
	// skip EDR events early
	return !(er.EventHeader.ProviderId.Equals(microsoftKernelFileGUID) && er.EventHeader.ProcessId == u32PID)
}

func (a *Agent) microsoftKernelFileProcessing(h *etw.EventRecordHelper) (err error) {
	var fo uint64
	var fn string

	switch h.EventID() {
	case 12:

		// we skip file create events
		h.Skip()

		if fo, err = h.GetPropertyUint("FileObject"); err != nil {
			break
		}

		if fn, err = h.GetPropertyString("FileName"); err != nil {
			break
		}

		kf := &KernelFile{
			FileName:   utils.ResolveCDrive(fn),
			FileObject: fo,
		}

		a.tracker.AddKernelFile(kf)

	case 14:

		// skip file close events
		h.Skip()

		if object, err := h.GetPropertyUint("FileObject"); err == nil {
			a.tracker.DelKernelFile(object)
		}

	case 15, 16:
		var kf *KernelFile
		var ok bool

		h.Skip()

		// check if it it worth processing the event
		if (h.EventID() == KernelFileRead && !a.config.EtwConfig.TraceFiles.Read) ||
			(h.EventID() == KernelFileWrite && !a.config.EtwConfig.TraceFiles.Write) {
			break
		}

		// Default
		h.SetProperty("TargetFileName", unkFieldValue)

		if fo, err = h.GetPropertyUint("FileObject"); err != nil {
			break
		}

		if kf, ok = a.tracker.GetKernelFile(fo); !ok {
			break
		}

		if (h.EventID() == KernelFileRead && kf.Flags.Read) || (h.EventID() == KernelFileWrite && kf.Flags.Write) {
			break
		}

		h.SetProperty(targetFileName, kf.FileName)
		h.SelectFields(targetFileName)
		kf.Flags.Read = (h.EventID() == KernelFileRead)
		kf.Flags.Write = (h.EventID() == KernelFileWrite)
		// don't skip event
		h.Flags.Skip = false

	default:
		h.Skip()
	}

	return
}

func (a *Agent) preparedCallback(h *etw.EventRecordHelper) (err error) {

	switch {
	// if events are comming from Microsoft-Kernel-File provider
	case h.TraceInfo.ProviderGUID.Equals(microsoftKernelFileGUID) && a.config.EtwConfig.FileTraceEnabled():
		return a.microsoftKernelFileProcessing(h)
	}

	return
}
