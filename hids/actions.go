package hids

const (
	// Actions
	ActionKill      = "kill"
	ActionBlacklist = "blacklist"
	ActionMemdump   = "memdump"
	ActionFiledump  = "filedump"
	ActionRegdump   = "regdump"
	ActionReport    = "report"
	ActionBrief     = "brief"
)

var (
	AvailableActions = []string{
		ActionKill,
		ActionBlacklist,
		ActionMemdump,
		ActionFiledump,
		ActionRegdump,
		ActionReport,
		ActionBrief,
	}
)
