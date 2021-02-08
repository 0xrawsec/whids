package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"github.com/0xrawsec/whids/utils/powershell"
)

const (
	jsonEvent = `{"Event":{"EventData":{"CommandLine":"\"powershell\" -command -","Company":"Microsoft Corporation","CurrentDirectory":"C:\\Windows\\system32\\","Description":"Windows PowerShell","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=5330FEDAD485E0E4C23B2ABE1075A1F984FDE9FC,MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","IntegrityLevel":"System","LogonGuid":"{49F1AF32-124E-5A90-0000-0020E7030000}","LogonId":"0x3e7","ParentCommandLine":"C:\\commander.exe -f","ParentImage":"C:\\commander.exe","ParentProcessGuid":"{49F1AF32-3441-5A94-0000-00103A440800}","ParentProcessId":"2720","ProcessGuid":"{49F1AF32-3490-5A94-0000-0010CC690900}","ProcessId":"184","Product":"Microsoft® Windows® Operating System","TerminalSessionId":"0","User":"NT AUTHORITY\\SYSTEM","UtcTime":"2018-02-26 16:23:44.789"},"GeneInfo":{"Criticality":5,"Signature":["PowershellStdin"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA02.caldera.loc","Correlation":{},"EventID":"1","EventRecordID":"815443","Execution":{"ProcessID":"1464","ThreadID":"1680"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"1","TimeCreated":{"SystemTime":"2018-02-26T16:23:44.789394500Z"},"Version":"5"}}}`
)

func TestCommand(t *testing.T) {
	p, err := powershell.NewShell()
	if err != nil {
		t.Log("Failed to create Powershell Shell")
		t.Fail()
	}
	// Assembly needed to show window
	p.ExecuteString("Add-Type -AssemblyName PresentationCore,PresentationFramework")
	p.ExecuteString("[System.Windows.MessageBox]::Show('Powershell executed from Go')")
	time.Sleep(time.Second * 2)
	p.Kill()
}

func TestEventLog(t *testing.T) {
	p, err := powershell.NewShell()
	if err != nil {
		t.Log("Failed to create Powershell Shell")
		t.Fail()
	}
	// Assembly needed to show window
	p.ExecuteString(`New-EventLog -Source "GolangTest" -LogName "Application"`)
	p.ExecuteString(`Write-EventLog -LogName "Application" -Source "GolangTest" -EventID 1337 -EntryType Warning -Message "My awesome message from Golang"`)
	p.ExecuteString(`Remove-EventLog -Source "GolangTest"`)
	time.Sleep(time.Second * 1)
	p.Kill()
}

func TestEventLogJSONMessage(t *testing.T) {
	p, err := powershell.NewShell()
	if err != nil {
		t.Log("Failed to create Powershell Shell")
		t.Fail()
	}
	// Assembly needed to show window
	p.ExecuteString(`New-EventLog -Source "TestJsonEvent" -LogName "Application"`)
	p.ExecuteString(fmt.Sprintf(`Write-EventLog -LogName "Application" -Source "TestJsonEvent" -EventID 1337 -EntryType Warning -Message '%s'`, strings.Replace(jsonEvent, "\n", "", -1)))
	p.ExecuteString(`Remove-EventLog -Source "TestJsonTest"`)
	time.Sleep(time.Second * 1)
	p.Kill()
}
