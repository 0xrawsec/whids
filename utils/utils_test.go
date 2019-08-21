package utils

import (
	"path/filepath"
	"testing"
)

var (
	pid = 604
)

func TestSvcFromPid(t *testing.T) {
	t.Logf("SVC from PID=%d: %s", pid, SvcFromPid(int32(pid)))
}

func TestRegQuery(t *testing.T) {
	path := `HKLM\System\CurrentControlSet\Services\SysmonDrv\Parameters\HashingAlgorithm`
	key, value := filepath.Split(path)
	t.Logf("Sysmon hashing algorithm: %s", RegQuery(key, value))
}
