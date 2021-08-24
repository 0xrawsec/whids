package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/gorilla/websocket"
)

func doRequest(method, url string) (r AdminAPIResponse) {
	cl := http.Client{Transport: cconf.Transport()}
	key := mconf.AdminAPI.Users[0].Key
	uri := fmt.Sprintf("https://%s:%d%s", mconf.AdminAPI.Host, mconf.AdminAPI.Port, url)
	req, err := http.NewRequest(method, uri, new(bytes.Buffer))
	if err != nil {
		panic(err)
	}
	req.Header.Add("Api-Key", key)
	resp, err := cl.Do(req)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		panic(fmt.Errorf("Unexpected response status: %d", resp.StatusCode))
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		panic(err)
	}
	return
}

func get(url string) (r AdminAPIResponse) {
	return doRequest("GET", url)
}

func put(url string) (r AdminAPIResponse) {
	return doRequest("PUT", url)
}

func post(url string, data []byte) (r AdminAPIResponse) {
	cl := http.Client{Transport: cconf.Transport()}
	key := mconf.AdminAPI.Users[0].Key
	uri := fmt.Sprintf("https://%s:%d%s", mconf.AdminAPI.Host, mconf.AdminAPI.Port, url)
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	req.Header.Add("Api-Key", key)
	resp, err := cl.Do(req)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		panic(fmt.Errorf("Unexpected response status: %d", resp.StatusCode))
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		panic(err)
	}
	return
}

func failOnAdminAPIError(t *testing.T, r AdminAPIResponse) {
	if r.Error != "" {
		t.Errorf("Unexpected API error: %s", r.Error)
		t.FailNow()
	}
}

func getEndpointUUID() string {
	r := get(AdmAPIEndpointsPath)
	a := r.Data.([]interface{})
	m := a[0].(map[string]interface{})
	return m["uuid"].(string)
}

func prepareTest() (m *Manager, c *ManagerClient) {
	var err error

	key := KeyGen(DefaultKeySize)

	if m, err = NewManager(&mconf); err != nil {
		panic(err)
	}
	m.AddEndpoint(cconf.UUID, key)
	m.Run()

	cconf.Key = key
	if c, err = NewManagerClient(&cconf); err != nil {
		panic(err)
	}
	// wait that server is up
	// might generate error message in log
	for !c.IsServerUp() {
		time.Sleep(time.Nanosecond * 500)
	}
	return
}

func prettyJSON(i interface{}) string {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func JSON(i interface{}) []byte {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	return b
}

/////////////////// Test functions

func TestAdminAPIGetEndpoints(t *testing.T) {
	m, _ := prepareTest()
	defer func() {
		m.Shutdown()
		m.Wait()
	}()
	r := get(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)
	t.Logf("received: %s", prettyJSON(r))
}

func TestAdminAPIGetCommand(t *testing.T) {
	m, _ := prepareTest()
	defer func() {
		m.Shutdown()
		m.Wait()
	}()
	euuid := getEndpointUUID()
	r := get(format("%s/%s/command", AdmAPIEndpointsPath, euuid))
	failOnAdminAPIError(t, r)
	t.Logf("received: %s", prettyJSON(r))
}

func TestAdminAPIPostCommand(t *testing.T) {
	m, c := prepareTest()
	defer func() {
		m.Shutdown()
		m.Wait()
	}()
	euuid := getEndpointUUID()
	ca := CommandAPI{
		CommandLine: "/bin/ls",
		FetchFiles:  []string{"/etc/fstab"},
	}
	r := post(format("%s/%s/command", AdmAPIEndpointsPath, euuid), JSON(ca))
	failOnAdminAPIError(t, r)
	if cmd, err := c.FetchCommand(); err != nil {
		t.Errorf("Failed to Fetch command: %s", err)
		t.FailNow()
	} else {
		if err = cmd.Run(); err != nil {
			t.Errorf("Failed to run command: %s", err)
			t.FailNow()
		}

		if err := c.PostCommand(cmd); err != nil {
			t.Errorf("Failed to post command: %s", err)
			t.FailNow()
		}
	}

	r = get(format("%s/%s/command", AdmAPIEndpointsPath, euuid))
	cmd := Command{}
	if err := r.UnmarshalData(&cmd); err != nil {
		t.Errorf("Failed to unmarshal response data")
		t.FailNow()
	}
	t.Logf("stdout: %s", cmd.Stdout)
	t.Logf("received: %s", prettyJSON(r))
}

func TestAdminAPIGetCommandField(t *testing.T) {
	var stdout []byte
	var files map[string]*EndpointFile

	m, c := prepareTest()
	defer func() {
		m.Shutdown()
		m.Wait()
	}()
	euuid := getEndpointUUID()
	ca := CommandAPI{
		CommandLine: "/bin/ls",
		FetchFiles:  []string{"/etc/fstab"},
	}
	r := post(format("%s/%s/command", AdmAPIEndpointsPath, euuid), JSON(ca))
	failOnAdminAPIError(t, r)

	if cmd, err := c.FetchCommand(); err != nil {
		t.Errorf("Failed to Fetch command: %s", err)
		t.FailNow()
	} else {
		if err = cmd.Run(); err != nil {
			t.Errorf("Failed to run command: %s", err)
			t.FailNow()
		}

		if err := c.PostCommand(cmd); err != nil {
			t.Errorf("Failed to post command: %s", err)
			t.FailNow()
		}
	}

	r = get(format("%s/%s/command/stdout", AdmAPIEndpointsPath, euuid))
	failOnAdminAPIError(t, r)

	if err := r.UnmarshalData(&stdout); err != nil {
		t.Errorf("Failed to unmarshal response data")
		t.FailNow()

	}
	t.Logf("stdout: %s", stdout)

	r = get(format("%s/%s/command/files", AdmAPIEndpointsPath, euuid))
	failOnAdminAPIError(t, r)
	t.Logf("files: %s", prettyJSON(r))
	if err := r.UnmarshalData(&files); err != nil {
		t.Errorf("Failed to unmarshal response data")
		t.FailNow()
	}
	for f, ef := range files {
		t.Logf("file: %s\ncontent: %s\n", f, string(ef.Data))
	}
}
func TestAdminAPIGetNewEndpoint(t *testing.T) {
	m, _ := prepareTest()
	mconfBak := mconf
	mconf.SetPath("data/test-config.json")
	defer func() {
		// we added an endpoint so we
		// need to restore configuration
		mconf = mconfBak
		m.Shutdown()
		m.Wait()
	}()

	r := put(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)
	t.Logf("received: %s", prettyJSON(r))

	r = get(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)
	t.Logf("received: %s", prettyJSON(r))
}

func TestAdminAPIGetEndpointReport(t *testing.T) {

	events := []string{
		`{"Event":{"EventData":{"CreationUtcTime":"2018-02-26 16:28:13.169","Image":"C:\\Program Files\\cagent\\cagent.exe","ProcessGuid":"{49F1AF32-11B0-5A90-0000-0010594E0100}","ProcessId":"1216","TargetFilename":"C:\\commander.exe","UtcTime":"2018-02-26 16:28:13.169"},"GeneInfo":{"Criticality":10,"Signature":["ExecutableFileCreated","NewExeCreatedInRoot"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"11","EventRecordID":"1274413","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"11","TimeCreated":{"SystemTime":"2018-02-26T16:28:13.185436300Z"},"Version":"2"}}}`,
		`{"Event":{"EventData":{"CommandLine":"\"powershell\" -command -","Company":"Microsoft Corporation","CurrentDirectory":"C:\\Windows\\system32\\","Description":"Windows PowerShell","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=5330FEDAD485E0E4C23B2ABE1075A1F984FDE9FC,MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","IntegrityLevel":"System","LogonGuid":"{49F1AF32-11AE-5A90-0000-0020E7030000}","LogonId":"0x3e7","ParentCommandLine":"C:\\commander.exe -f","ParentImage":"C:\\commander.exe","ParentProcessGuid":"{49F1AF32-359D-5A94-0000-0010A9530C00}","ParentProcessId":"3068","ProcessGuid":"{49F1AF32-35A0-5A94-0000-0010FE5E0C00}","ProcessId":"1244","Product":"Microsoft® Windows® Operating System","TerminalSessionId":"0","User":"NT AUTHORITY\\SYSTEM","UtcTime":"2018-02-26 16:28:16.514"},"GeneInfo":{"Criticality":10,"Signature":["HeurSpawnShell","PowershellStdin"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"1","EventRecordID":"1274784","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"1","TimeCreated":{"SystemTime":"2018-02-26T16:28:16.530122800Z"},"Version":"5"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"GeneInfo":{"Criticality":10,"Signature":["HeurMaliciousAccess","MaliciousLsassAccess","SuspWriteAccess","SuspiciousLsassAccess"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"2018-02-26T16:43:26.447894800Z"},"Version":"3"}}}`,
	}

	m, mc := prepareTest()
	mconfBak := mconf
	defer func() {
		// we added an endpoint so we
		// need to restore configuration
		mconf = mconfBak
		m.Shutdown()
		m.Wait()
	}()
	euuid := getEndpointUUID()

	// creating a new endpoint
	r := put(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)

	for _, e := range events {
		r, err := mc.PrepareGzip("POST", EptAPIPostLogsPath, bytes.NewBufferString(e))
		if err != nil {
			t.Logf("Failed to prepare request: %s", err)
			t.FailNow()
		}
		mc.HTTPClient.Do(r)
	}

	time.Sleep(1 * time.Second)

	r = get(AdmAPIEndpointsReportsPath)
	failOnAdminAPIError(t, r)
	t.Logf("received: %s", prettyJSON(r))

	r = doRequest("DELETE", AdmAPIEndpointsPath+"/"+euuid+"/report")
	failOnAdminAPIError(t, r)
	t.Logf("received: %s", prettyJSON(r))

	time.Sleep(1 * time.Second)
	r = get(AdmAPIEndpointsReportsPath)
	failOnAdminAPIError(t, r)
	t.Logf("received: %s", prettyJSON(r))
}

func TestAdminAPIGetEndpointLogs(t *testing.T) {

	// cleanup previous data
	clean(&mconf, &fconf)

	events := []string{
		`{"Event":{"EventData":{"CreationUtcTime":"2018-02-26 16:28:13.169","Image":"C:\\Program Files\\cagent\\cagent.exe","ProcessGuid":"{49F1AF32-11B0-5A90-0000-0010594E0100}","ProcessId":"1216","TargetFilename":"C:\\commander.exe","UtcTime":"2018-02-26 16:28:13.169"},"GeneInfo":{"Criticality":10,"Signature":["ExecutableFileCreated","NewExeCreatedInRoot"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"11","EventRecordID":"1274413","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"11","TimeCreated":{"SystemTime":"` + time.Now().Add(-time.Hour).Format(time.RFC3339Nano) + `"},"Version":"2"}}}`,
		`{"Event":{"EventData":{"CommandLine":"\"powershell\" -command -","Company":"Microsoft Corporation","CurrentDirectory":"C:\\Windows\\system32\\","Description":"Windows PowerShell","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=5330FEDAD485E0E4C23B2ABE1075A1F984FDE9FC,MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","IntegrityLevel":"System","LogonGuid":"{49F1AF32-11AE-5A90-0000-0020E7030000}","LogonId":"0x3e7","ParentCommandLine":"C:\\commander.exe -f","ParentImage":"C:\\commander.exe","ParentProcessGuid":"{49F1AF32-359D-5A94-0000-0010A9530C00}","ParentProcessId":"3068","ProcessGuid":"{49F1AF32-35A0-5A94-0000-0010FE5E0C00}","ProcessId":"1244","Product":"Microsoft® Windows® Operating System","TerminalSessionId":"0","User":"NT AUTHORITY\\SYSTEM","UtcTime":"2018-02-26 16:28:16.514"},"GeneInfo":{"Criticality":10,"Signature":["HeurSpawnShell","PowershellStdin"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"1","EventRecordID":"1274784","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"1","TimeCreated":{"SystemTime":"` + time.Now().Add(-4*time.Minute).Format(time.RFC3339Nano) + `"},"Version":"5"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"GeneInfo":{"Criticality":10,"Signature":["HeurMaliciousAccess","MaliciousLsassAccess","SuspWriteAccess","SuspiciousLsassAccess"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
	}

	m, mc := prepareTest()
	mconfBak := mconf
	defer func() {
		// we added an endpoint so we
		// need to restore configuration
		mconf = mconfBak
		m.Shutdown()
		m.Wait()
	}()
	euuid := getEndpointUUID()

	// creating a new endpoint
	r := put(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)

	for _, e := range events {
		r, err := mc.PrepareGzip("POST", EptAPIPostLogsPath, bytes.NewBufferString(e))
		if err != nil {
			t.Logf("Failed to prepare request: %s", err)
			t.FailNow()
		}
		mc.HTTPClient.Do(r)
	}

	time.Sleep(1 * time.Second)

	// test retrieving all the logs
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/logs")
	failOnAdminAPIError(t, r)
	data := make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != len(events) {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}

	// test pivoting
	v := url.Values{}
	v.Set("pivot", time.Now().Format(time.RFC3339))
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/logs?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != 2 {
		t.Errorf("Wrong number of events %d instead of %d", len(data), 2)
		t.FailNow()
	}

	// test pivoting with delta
	v = url.Values{}
	v.Set("pivot", time.Now().Format(time.RFC3339))
	v.Set("delta", "3h")
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/logs?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != len(events) {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}

	// test with start and stop
	v = url.Values{}
	v.Set("start", time.Now().Add(-3*time.Hour).Format(time.RFC3339))
	v.Set("stop", time.Now().Format(time.RFC3339))
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/logs?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != len(events) {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}
}

func TestAdminAPIGetEndpointAlerts(t *testing.T) {

	// cleanup previous data
	clean(&mconf, &fconf)

	alerts := []string{
		`{"Event":{"EventData":{"CreationUtcTime":"2018-02-26 16:28:13.169","Image":"C:\\Program Files\\cagent\\cagent.exe","ProcessGuid":"{49F1AF32-11B0-5A90-0000-0010594E0100}","ProcessId":"1216","TargetFilename":"C:\\commander.exe","UtcTime":"2018-02-26 16:28:13.169"},"GeneInfo":{"Criticality":10,"Signature":["ExecutableFileCreated","NewExeCreatedInRoot"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"11","EventRecordID":"1274413","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"11","TimeCreated":{"SystemTime":"` + time.Now().Add(-time.Hour).Format(time.RFC3339Nano) + `"},"Version":"2"}}}`,
		`{"Event":{"EventData":{"CommandLine":"\"powershell\" -command -","Company":"Microsoft Corporation","CurrentDirectory":"C:\\Windows\\system32\\","Description":"Windows PowerShell","FileVersion":"6.1.7600.16385 (win7_rtm.090713-1255)","Hashes":"SHA1=5330FEDAD485E0E4C23B2ABE1075A1F984FDE9FC,MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","IntegrityLevel":"System","LogonGuid":"{49F1AF32-11AE-5A90-0000-0020E7030000}","LogonId":"0x3e7","ParentCommandLine":"C:\\commander.exe -f","ParentImage":"C:\\commander.exe","ParentProcessGuid":"{49F1AF32-359D-5A94-0000-0010A9530C00}","ParentProcessId":"3068","ProcessGuid":"{49F1AF32-35A0-5A94-0000-0010FE5E0C00}","ProcessId":"1244","Product":"Microsoft® Windows® Operating System","TerminalSessionId":"0","User":"NT AUTHORITY\\SYSTEM","UtcTime":"2018-02-26 16:28:16.514"},"GeneInfo":{"Criticality":10,"Signature":["HeurSpawnShell","PowershellStdin"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"1","EventRecordID":"1274784","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"1","TimeCreated":{"SystemTime":"` + time.Now().Add(-4*time.Minute).Format(time.RFC3339Nano) + `"},"Version":"5"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"GeneInfo":{"Criticality":10,"Signature":["HeurMaliciousAccess","MaliciousLsassAccess","SuspWriteAccess","SuspiciousLsassAccess"]},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
	}

	events := []string{
		// all following should not be in alerts
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+4d61a|C:\\Windows\\system32\\KERNELBASE.dll+19577|UNKNOWN(000000001ABD2A68)","GrantedAccess":"0x143a","SourceImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","SourceProcessGUID":"{49F1AF32-3922-5A94-0000-0010E3581900}","SourceProcessId":"1916","SourceThreadId":"2068","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetProcessGUID":"{49F1AF32-11AD-5A90-0000-00102F6F0000}","TargetProcessId":"472","UtcTime":"2018-02-26 16:43:26.380"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"CALDERA01.caldera.loc","Correlation":{},"EventID":"10","EventRecordID":"1293693","Execution":{"ProcessID":"1408","ThreadID":"1652"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"` + time.Now().Format(time.RFC3339Nano) + `"},"Version":"3"}}}`,
	}

	m, mc := prepareTest()
	mconfBak := mconf
	defer func() {
		// we added an endpoint so we
		// need to restore configuration
		mconf = mconfBak
		m.Shutdown()
		m.Wait()
	}()
	euuid := getEndpointUUID()

	// creating a new endpoint
	r := put(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)

	tmp := make([]string, 0)
	tmp = append(tmp, alerts...)
	tmp = append(tmp, events...)
	for _, e := range tmp {
		r, err := mc.PrepareGzip("POST", EptAPIPostLogsPath, bytes.NewBufferString(e))
		if err != nil {
			t.Logf("Failed to prepare request: %s", err)
			t.FailNow()
		}
		mc.HTTPClient.Do(r)
	}

	time.Sleep(1 * time.Second)

	// test retrieving all the logs
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/alerts")
	failOnAdminAPIError(t, r)
	data := make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != len(alerts) {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}

	// test pivoting
	v := url.Values{}
	v.Set("pivot", time.Now().Format(time.RFC3339))
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/alerts?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != 2 {
		t.Errorf("Wrong number of events %d instead of %d", len(data), 2)
		t.FailNow()
	}

	// test pivoting with delta
	v = url.Values{}
	v.Set("pivot", time.Now().Format(time.RFC3339))
	v.Set("delta", "3h")
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/alerts?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != len(alerts) {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}

	// test with start and stop
	v = url.Values{}
	v.Set("start", time.Now().Add(-3*time.Hour).Format(time.RFC3339))
	v.Set("stop", time.Now().Format(time.RFC3339))
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/alerts?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != len(alerts) {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}
}

func TestEventStream(t *testing.T) {
	// cleanup previous data
	clean(&mconf, &fconf)

	m, mc := prepareTest()
	defer func() {
		m.Shutdown()
		m.Wait()
	}()

	expctd := float64(20000)
	total := float64(0)
	sumEps := float64(0)
	nclients := float64(4)
	slowClients := float64(0)
	wg := sync.WaitGroup{}

	for i := float64(0); i < nclients; i++ {
		u := url.URL{Scheme: "wss", Host: format("localhost:%d", 8001), Path: AdmAPIStreamEvents}
		key := mconf.AdminAPI.Users[0].Key
		dialer := *websocket.DefaultDialer
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		t.Logf("connecting to %s", u.String())
		c, resp, err := dialer.Dial(u.String(), http.Header{"Api-Key": {key}})
		if err != nil {
			if err == websocket.ErrBadHandshake {
				t.Logf("handshake failed with status %d", resp.StatusCode)
			}
			t.Errorf("failed to dial: %s", err)
			t.FailNow()
		}
		defer c.Close()

		wg.Add(1)
		go func() {
			defer wg.Done()
			recvd := float64(0)
			start := time.Now()
			slow := false

			if rand.Int()%2 == 0 {
				slow = true
				slowClients++
			}

			for {
				_, _, err := c.ReadMessage()
				if err != nil {
					break
				}
				recvd++
				if recvd == expctd {
					break
				}
				// simulates a slow client
				if slow {
					time.Sleep(35 * time.Microsecond)
				}
			}
			eps := recvd / float64(time.Since(start).Seconds())
			total += recvd
			// we take into account only normal clients
			if !slow {
				sumEps += eps
				t.Logf("Normal client received %.1f EPS", eps)
			} else {
				t.Logf("Slow client received %.1f EPS", eps)
			}
		}()
	}

	mc.PostLogs(readerFromEvents(int(expctd)))
	tick := time.NewTicker(60 * time.Second)
loop:
	for {
		select {
		case <-tick.C:
			break loop
		default:
		}

		if total == expctd*nclients {
			wg.Wait()
			break
		}
	}

	if total != expctd*nclients {
		t.Errorf("Received less events than expected received=%.0f VS expected=%.0f", total, expctd*nclients)
		t.FailNow()
	}

	t.Logf("Average %.1f EPS/client", sumEps/(nclients-slowClients))

}
