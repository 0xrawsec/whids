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
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/utils"
	"github.com/gorilla/websocket"
)

var (
	testAdminUser = &AdminAPIUser{
		Identifier: "test",
		Key:        KeyGen(DefaultKeySize),
	}
)

func prepare(method, URL string, data []byte, params map[string]string) *http.Request {
	key := testAdminUser.Key
	buf := new(bytes.Buffer)

	// preparing request body
	if data != nil {
		if len(data) > 0 {
			buf.Write(data)
		}
	}

	// preparing parameters to be passed to the query
	if params != nil {
		v := url.Values{}
		for param, value := range params {
			v.Set(param, value)
		}

		if len(params) > 0 {
			URL = fmt.Sprintf("%s?%s", URL, v.Encode())
		}
	}

	uri := fmt.Sprintf("https://%s:%d%s", mconf.AdminAPI.Host, mconf.AdminAPI.Port, URL)
	req, err := http.NewRequest(method, uri, buf)
	if err != nil {
		panic(err)
	}
	req.Header.Add(AuthKeyHeader, key)
	return req
}

func do(req *http.Request) (r AdminAPIResponse) {
	cl := http.Client{Transport: cconf.Transport()}
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
	return do(prepare("GET", url, nil, nil))
}

func put(url string) (r AdminAPIResponse) {
	return do(prepare("PUT", url, nil, nil))
}

func post(url string, data []byte) (r AdminAPIResponse) {
	cl := http.Client{Transport: cconf.Transport()}
	key := testAdminUser.Key
	uri := fmt.Sprintf("https://%s:%d%s", mconf.AdminAPI.Host, mconf.AdminAPI.Port, url)
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	req.Header.Add(AuthKeyHeader, key)
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
	if len(b) > 0 {
		if err := json.Unmarshal(b, &r); err != nil {
			panic(err)
		}
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

	// we don't handle error as we don't care if user
	// already exists
	m.CreateNewAdminAPIUser(testAdminUser)

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
	euuid := c.config.UUID
	ca := CommandAPI{
		CommandLine: "/bin/ls",
		FetchFiles:  []string{"/etc/fstab"},
	}
	r := post(format("%s/%s/command", AdmAPIEndpointsPath, euuid), JSON(ca))
	failOnAdminAPIError(t, r)
	time.Sleep(2 * time.Second)
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
	euuid := c.config.UUID
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
		`{"Event":{"EventData":{"CommandLine":"\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\"","CurrentDirectory":"C:\\Program Files\\Mozilla Firefox\\","Image":"C:\\Program Files\\Mozilla Firefox\\firefox.exe","ImageHashes":"SHA1=6923508844E6FE0C1DEDD684FE299EBC26D778F3,MD5=988976B1058A1DAE198C93A5688142FD,SHA256=28BE8E0485DBA68F6A4B37F6A68D7AE542B0DA00925A69EA12A4E7AA3B477EC6,IMPHASH=AECE7B7E776840D7A7255A31B309B7E4","ImageSignature":"Mozilla Corporation","ImageSignatureStatus":"Valid","ImageSigned":"true","IntegrityLevel":"Medium","ProcessGuid":"{515cd0d1-c09c-615c-6886-000000008b00}","ProcessId":"9472","ProcessThreatScore":"60","QueryName":"analytics-collector-28944298.us-east-1.elb.amazonaws.com","QueryResults":"-","QueryStatus":"9501","RuleName":"-","Services":"N/A","User":"DESKTOP-LJRVE06\\Generic","UtcTime":"2021-10-04 03:47:27.711"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"DESKTOP-LJRVE06","EventID":22,"Execution":{"ProcessID":3188,"ThreadID":1536},"Keywords":{"Value":9223372036854776000,"Name":""},"Level":{"Value":4,"Name":"Information"},"Opcode":{"Value":0,"Name":"Info"},"Task":{"Value":0,"Name":""},"Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"TimeCreated":{"SystemTime":"2021-10-04T03:47:28.7994921Z"}},"EdrData":{"Endpoint":{"UUID":"03e31275-2277-d8e0-bb5f-480fac7ee4ef","IP":"192.168.56.110","Hostname":"DESKTOP-LJRVE06","Group":"HR"},"Event":{"Hash":"107115af9a7ae294b66499d9f24b4da40840f8dc","Detection":true,"ReceiptTime":"2021-10-06T07:00:47.488763072Z"}},"Detection":{"Signature":["HeurSysmonLongDomain"],"Criticality":6,"Actions":["brief","filedump","regdump"]}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+9c524|C:\\Windows\\System32\\wow64.dll+17014|C:\\Windows\\System32\\wow64.dll+16c85|C:\\Windows\\System32\\wow64.dll+1723b|C:\\Windows\\System32\\wow64.dll+1e5b|C:\\Windows\\System32\\wow64.dll+301d|C:\\Windows\\System32\\wow64.dll+67e3|C:\\Windows\\System32\\wow64cpu.dll+1783|C:\\Windows\\System32\\wow64cpu.dll+1199|C:\\Windows\\System32\\wow64.dll+baea|C:\\Windows\\System32\\wow64.dll+b9a7|C:\\Windows\\SYSTEM32\\ntdll.dll+d3fb3|C:\\Windows\\SYSTEM32\\ntdll.dll+c1dbd|C:\\Windows\\SYSTEM32\\ntdll.dll+717f3|C:\\Windows\\SYSTEM32\\ntdll.dll+7179e|C:\\Windows\\SYSTEM32\\ntdll.dll+71ffc(wow64)|C:\\Windows\\System32\\KERNELBASE.dll+110926(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+f614(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+f89d(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12ef1(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12f58(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12e7b(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12fc9(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+aa418(wow64)","GrantedAccess":"0x1010","RuleName":"-","SourceHashes":"SHA1=12950D906FF703F3A1E0BD973FCA2B433E5AB207,MD5=9A66A3DE2589F7108426AF37AB7F6B41,SHA256=A913415626433D5D0F07D3EC4084A67FF6F5138C3C3F64E36DD0C1AE4C423C65,IMPHASH=7DF1816239C5BC855600D41210406C5B","SourceImage":"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe","SourceIntegrityLevel":"System","SourceProcessGUID":"{515cd0d1-421a-615d-e087-000000008b00}","SourceProcessId":"6176","SourceProcessThreatScore":"54","SourceServices":"N/A","SourceThreadId":"5788","SourceUser":"NT AUTHORITY\\SYSTEM","TargetHashes":"?","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetIntegrityLevel":"?","TargetParentProcessGuid":"?","TargetProcessGUID":"{515cd0d1-6dae-6154-0c00-000000008b00}","TargetProcessId":"708","TargetProcessThreatScore":"-1","TargetServices":"KeyIso,SamSs,VaultSvc","TargetUser":"?","UtcTime":"2021-10-06 06:28:43.309"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"DESKTOP-LJRVE06","EventID":10,"Execution":{"ProcessID":3188,"ThreadID":3104},"Keywords":{"Value":9223372036854776000,"Name":""},"Level":{"Value":4,"Name":"Information"},"Opcode":{"Value":0,"Name":"Info"},"Task":{"Value":0,"Name":""},"Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"TimeCreated":{"SystemTime":"2021-10-04T03:15:27.1523337Z"}},"EdrData":{"Endpoint":{"UUID":"03e31275-2277-d8e0-bb5f-480fac7ee4ef","IP":"192.168.56.110","Hostname":"DESKTOP-LJRVE06","Group":"HR"},"Event":{"Hash":"af6ee1bef517b5f2d45205f3fb0cf3b48b8d3851","Detection":true,"ReceiptTime":"2021-10-06T06:28:44.894685897Z"}},"Detection":{"Signature":["SuspiciousLsassAccess"],"Criticality":8,"Actions":["report","filedump","regdump","memdump"]}}}`,
		`{"Event":{"EventData":{"CommandLine":"\"C:\\Program Files (x86)\\Google\\Update\\Install\\{B29ED602-C455-4B82-80D2-A5992C371348}\\CR_C52DD.tmp\\setup.exe\" --install-archive=\"C:\\Program Files (x86)\\Google\\Update\\Install\\{B29ED602-C455-4B82-80D2-A5992C371348}\\CR_C52DD.tmp\\CHROME_PATCH.PACKED.7Z\" --previous-version=\"94.0.4606.61\" --verbose-logging --do-not-launch-chrome --channel=stable --system-level","Count":"104","CountByExt":"9","CreationUtcTime":"2021-10-06 06:28:31.108","CurrentDirectory":"C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\","Extension":".dll","FrequencyEps":"6","Image":"C:\\Program Files (x86)\\Google\\Update\\Install\\{B29ED602-C455-4B82-80D2-A5992C371348}\\CR_C52DD.tmp\\setup.exe","ImageHashes":"SHA1=0019051003B762EBA424E00BA0D34023608D48D6,MD5=46EB8A20A6B5B16C0BC24B907E0AA684,SHA256=C5360313BD1E95409174C03B71AC83FA13FBFFD3D13412A71D38FB451783FC0E,IMPHASH=44B4DFB0DCCA5DE0AA33EAEC613BAC84","ImageSignature":"Google LLC","ImageSignatureStatus":"Valid","ImageSigned":"true","IntegrityLevel":"System","ProcessGuid":"{515cd0d1-41ff-615d-d587-000000008b00}","ProcessId":"400","ProcessThreatScore":"91","RuleName":"-","Services":"N/A","TargetFilename":"C:\\Program Files\\Google\\Chrome\\Temp\\source400_1020262374\\Chrome-bin\\94.0.4606.71\\vk_swiftshader.dll","User":"NT AUTHORITY\\SYSTEM","UtcTime":"2021-10-06 06:28:31.109"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"DESKTOP-LJRVE06","EventID":11,"Execution":{"ProcessID":3188,"ThreadID":3104},"Keywords":{"Value":9223372036854776000,"Name":""},"Level":{"Value":4,"Name":"Information"},"Opcode":{"Value":0,"Name":"Info"},"Task":{"Value":0,"Name":""},"Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"TimeCreated":{"SystemTime":"2021-10-04T03:15:14.9259991Z"}},"EdrData":{"Endpoint":{"UUID":"03e31275-2277-d8e0-bb5f-480fac7ee4ef","IP":"192.168.56.110","Hostname":"DESKTOP-LJRVE06","Group":"HR"},"Event":{"Hash":"7f21f22e69db69f712798574f04baf28c8d44106","Detection":true,"ReceiptTime":"2021-10-06T06:28:32.368300493Z"}},"Detection":{"Signature":["ExecutableFileCreated"],"Criticality":7,"Actions":["brief","filedump","regdump"]}}}`,
		`{"Event":{"EventData":{"CallTrace":"C:\\Windows\\SYSTEM32\\ntdll.dll+9c524|C:\\Windows\\System32\\wow64.dll+17014|C:\\Windows\\System32\\wow64.dll+16c85|C:\\Windows\\System32\\wow64.dll+1723b|C:\\Windows\\System32\\wow64.dll+1e5b|C:\\Windows\\System32\\wow64.dll+301d|C:\\Windows\\System32\\wow64.dll+67e3|C:\\Windows\\System32\\wow64cpu.dll+1783|C:\\Windows\\System32\\wow64cpu.dll+1199|C:\\Windows\\System32\\wow64.dll+baea|C:\\Windows\\System32\\wow64.dll+b9a7|C:\\Windows\\SYSTEM32\\ntdll.dll+7190b|C:\\Windows\\SYSTEM32\\ntdll.dll+717f3|C:\\Windows\\SYSTEM32\\ntdll.dll+7179e|C:\\Windows\\SYSTEM32\\ntdll.dll+71ffc(wow64)|C:\\Windows\\System32\\KERNELBASE.dll+110926(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+f614(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+f89d(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12ef1(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12f58(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12e7b(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+12aa8(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+1cf31(wow64)|C:\\Program Files (x86)\\Google\\Update\\1.3.36.112\\goopdate.dll+1d691(wow64)","GrantedAccess":"0x1010","RuleName":"-","SourceHashes":"SHA1=12950D906FF703F3A1E0BD973FCA2B433E5AB207,MD5=9A66A3DE2589F7108426AF37AB7F6B41,SHA256=A913415626433D5D0F07D3EC4084A67FF6F5138C3C3F64E36DD0C1AE4C423C65,IMPHASH=7DF1816239C5BC855600D41210406C5B","SourceImage":"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe","SourceIntegrityLevel":"System","SourceProcessGUID":"{515cd0d1-41e9-615d-a787-000000008b00}","SourceProcessId":"5368","SourceProcessThreatScore":"50","SourceServices":"gupdate","SourceThreadId":"8284","SourceUser":"NT AUTHORITY\\SYSTEM","TargetHashes":"?","TargetImage":"C:\\Windows\\system32\\lsass.exe","TargetIntegrityLevel":"?","TargetParentProcessGuid":"?","TargetProcessGUID":"{515cd0d1-6dae-6154-0c00-000000008b00}","TargetProcessId":"708","TargetProcessThreatScore":"-1","TargetServices":"KeyIso,SamSs,VaultSvc","TargetUser":"?","UtcTime":"2021-10-06 06:28:42.590"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"DESKTOP-LJRVE06","EventID":10,"Execution":{"ProcessID":3188,"ThreadID":3104},"Keywords":{"Value":9223372036854776000,"Name":""},"Level":{"Value":4,"Name":"Information"},"Opcode":{"Value":0,"Name":"Info"},"Task":{"Value":0,"Name":""},"Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"TimeCreated":{"SystemTime":"2021-10-04T03:15:26.4082567Z"}},"EdrData":{"Endpoint":{"UUID":"03e31275-2277-d8e0-bb5f-480fac7ee4ef","IP":"192.168.56.110","Hostname":"DESKTOP-LJRVE06","Group":"HR"},"Event":{"Hash":"72241c0e9816fca5d44787752e87715db3ada5f4","Detection":true,"ReceiptTime":"2021-10-06T06:28:43.620696097Z"}},"Detection":{"Signature":["SuspiciousLsassAccess"],"Criticality":8,"Actions":["report","filedump","regdump","memdump"]}}}`,
		`{"Event":{"EventData":{"CommandLine":"\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\"","CurrentDirectory":"C:\\Program Files\\Mozilla Firefox\\","Image":"C:\\Program Files\\Mozilla Firefox\\firefox.exe","ImageHashes":"SHA1=6923508844E6FE0C1DEDD684FE299EBC26D778F3,MD5=988976B1058A1DAE198C93A5688142FD,SHA256=28BE8E0485DBA68F6A4B37F6A68D7AE542B0DA00925A69EA12A4E7AA3B477EC6,IMPHASH=AECE7B7E776840D7A7255A31B309B7E4","ImageSignature":"Mozilla Corporation","ImageSignatureStatus":"Valid","ImageSigned":"true","IntegrityLevel":"Medium","ProcessGuid":"{515cd0d1-c09c-615c-6886-000000008b00}","ProcessId":"9472","ProcessThreatScore":"30","QueryName":"analytics-collector-28944298.us-east-1.elb.amazonaws.com","QueryResults":"54.209.192.22;23.21.66.55;54.84.193.129;34.230.149.116;","QueryStatus":"0","RuleName":"-","Services":"N/A","User":"DESKTOP-LJRVE06\\Generic","UtcTime":"2021-10-04 03:46:23.070"},"System":{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"DESKTOP-LJRVE06","EventID":22,"Execution":{"ProcessID":3188,"ThreadID":1536},"Keywords":{"Value":9223372036854776000,"Name":""},"Level":{"Value":4,"Name":"Information"},"Opcode":{"Value":0,"Name":"Info"},"Task":{"Value":0,"Name":""},"Provider":{"Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","Name":"Microsoft-Windows-Sysmon"},"TimeCreated":{"SystemTime":"2021-10-04T03:46:23.342471Z"}},"EdrData":{"Endpoint":{"UUID":"03e31275-2277-d8e0-bb5f-480fac7ee4ef","IP":"192.168.56.110","Hostname":"DESKTOP-LJRVE06","Group":"HR"},"Event":{"Hash":"5b74a882fba6a5a762d6e9cabfa1d3a9883ba203","Detection":true,"ReceiptTime":"2021-10-06T06:59:46.487128874Z"}},"Detection":{"Signature":["HeurSysmonLongDomain"],"Criticality":6,"Actions":["brief","filedump","regdump"]}}}`,
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
	euuid := mc.config.UUID
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

	r = do(prepare("DELETE", AdmAPIEndpointsPath+"/"+euuid+"/report", nil, nil))
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

	n := 1000
	m, mc := prepareTest()
	mconfBak := mconf
	defer func() {
		// we added an endpoint so we
		// need to restore configuration
		mconf = mconfBak
		m.Shutdown()
		m.Wait()
	}()
	euuid := mc.config.UUID

	// creating a new endpoint
	r := put(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)

	npivot := 0
	for e := range emitEvents(n, false) {
		switch rand.Int() % 3 {
		case 0:
			e.Event.System.TimeCreated.SystemTime = e.Event.System.TimeCreated.SystemTime.Add(-time.Hour)
		case 1:
			e.Event.System.TimeCreated.SystemTime = e.Event.System.TimeCreated.SystemTime.Add(time.Hour)
		default:
			npivot++
		}
		r, err := mc.PrepareGzip("POST", EptAPIPostLogsPath, bytes.NewBuffer(utils.Json(e)))
		if err != nil {
			t.Logf("Failed to prepare request: %s", err)
			t.FailNow()
		}
		mc.HTTPClient.Do(r)
	}

	time.Sleep(1 * time.Second)

	// test pivoting
	v := url.Values{}
	v.Set(qpPivot, time.Now().Format(time.RFC3339))
	v.Set(qpDelta, "1m")
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/logs?" + v.Encode())
	failOnAdminAPIError(t, r)
	data := make([]event.EdrEvent, 0)
	r.UnmarshalData(&data)
	if len(data) != npivot {
		t.Errorf("Wrong number of events %d instead of %d", len(data), npivot)
		t.FailNow()
	}

	// test pivoting with delta
	v = url.Values{}
	v.Set(qpPivot, time.Now().Format(time.RFC3339))
	v.Set(qpDelta, "3h")
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/logs?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]event.EdrEvent, 0)
	r.UnmarshalData(&data)
	if len(data) != n {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}

	// test with start and stop
	v = url.Values{}
	v.Set(qpSince, time.Now().Add(-3*time.Hour).Format(time.RFC3339))
	v.Set(qpUntil, time.Now().Add(3*time.Hour).Format(time.RFC3339))
	r = get(AdmAPIEndpointsPath + "/" + euuid + "/logs?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]event.EdrEvent, 0)
	r.UnmarshalData(&data)
	if len(data) != n {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}
}

func TestAdminAPIGetEndpointAlerts(t *testing.T) {

	// cleanup previous data
	clean(&mconf, &fconf)

	m, mc := prepareTest()
	mconfBak := mconf
	defer func() {
		// we added an endpoint so we
		// need to restore configuration
		mconf = mconfBak
		m.Shutdown()
		m.Wait()
	}()
	euuid := mc.config.UUID

	// creating a new endpoint
	r := put(AdmAPIEndpointsPath)
	failOnAdminAPIError(t, r)

	npivot := 0
	n, ndet := 1000, 100
	for e := range emitMixedEvents(n, ndet) {
		if e.IsDetection() {
			switch rand.Int() % 3 {
			case 0:
				e.Event.System.TimeCreated.SystemTime = e.Event.System.TimeCreated.SystemTime.Add(-time.Hour)
			case 1:
				e.Event.System.TimeCreated.SystemTime = e.Event.System.TimeCreated.SystemTime.Add(time.Hour)
			default:
				npivot++
			}
		}
		r, err := mc.PrepareGzip("POST", EptAPIPostLogsPath, bytes.NewBuffer(utils.Json(e)))
		if err != nil {
			t.Logf("Failed to prepare request: %s", err)
			t.FailNow()
		}
		mc.HTTPClient.Do(r)
	}

	time.Sleep(1 * time.Second)

	// test pivoting
	v := url.Values{}
	v.Set(qpPivot, time.Now().Format(time.RFC3339))
	r = get(AdmAPIEndpointsPath + "/" + euuid + AdmAPIDetectionSuffix + "?" + v.Encode())
	failOnAdminAPIError(t, r)
	data := make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != npivot {
		t.Errorf("Wrong number of events %d instead of %d", len(data), npivot)
		t.FailNow()
	}

	// test pivoting with delta
	v = url.Values{}
	v.Set(qpPivot, time.Now().Format(time.RFC3339))
	v.Set(qpDelta, "3h")
	r = get(AdmAPIEndpointsPath + "/" + euuid + AdmAPIDetectionSuffix + "?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != ndet {
		t.Errorf("Wrong number of events %d instead of %d", len(data), len(events))
		t.FailNow()
	}

	// test with start and stop
	v = url.Values{}
	v.Set(qpSince, time.Now().Add(-3*time.Hour).Format(time.RFC3339))
	v.Set(qpUntil, time.Now().Add(3*time.Hour).Format(time.RFC3339))
	r = get(AdmAPIEndpointsPath + "/" + euuid + AdmAPIDetectionSuffix + "?" + v.Encode())
	failOnAdminAPIError(t, r)
	data = make([]evtx.GoEvtxMap, 0)
	r.UnmarshalData(&data)
	if len(data) != ndet {
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

		u := url.URL{
			Scheme: "wss",
			Host:   format("%s:%d", mconf.AdminAPI.Host, mconf.AdminAPI.Port),
			Path:   AdmAPIStreamEvents}
		key := testAdminUser.Key
		dialer := *websocket.DefaultDialer
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		t.Logf("connecting to %s", u.String())
		c, resp, err := dialer.Dial(u.String(), http.Header{AuthKeyHeader: {key}})
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
