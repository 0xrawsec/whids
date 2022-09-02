package agent

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/agent/config"
	"github.com/0xrawsec/whids/api"
	cconfig "github.com/0xrawsec/whids/api/client/config"
	"github.com/0xrawsec/whids/api/server"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/ioc"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/sysmon"
	"github.com/0xrawsec/whids/tools"
	"github.com/0xrawsec/whids/utils"
)

var (
	sysmonInstalled bool

	sysmonConfig = `<Sysmon schemaversion="4.70">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude"></ProcessCreate>
    <FileCreateTime onmatch="exclude"></FileCreateTime>
    <NetworkConnect onmatch="exclude"></NetworkConnect>
    <ProcessTerminate onmatch="exclude"></ProcessTerminate>
    <DriverLoad onmatch="exclude"></DriverLoad>
    <CreateRemoteThread onmatch="exclude"></CreateRemoteThread>
    <RawAccessRead onmatch="exclude"></RawAccessRead>
    <FileCreate onmatch="exclude"></FileCreate>
    <FileCreateStreamHash onmatch="exclude"></FileCreateStreamHash>
    <PipeEvent onmatch="exclude"></PipeEvent>
    <WmiEvent onmatch="exclude"></WmiEvent>
    <FileDelete onmatch="exclude"></FileDelete>
    <ClipboardChange onmatch="exclude"></ClipboardChange>
    <ProcessTampering onmatch="exclude"></ProcessTampering>
    <FileDeleteDetected onmatch="exclude"></FileDeleteDetected>
    <RuleGroup groupRelation="or">
      <ImageLoad onmatch="exclude">
      </ImageLoad>
    </RuleGroup>
    <RuleGroup groupRelation="or">
      <ProcessAccess onmatch="exclude">
        <SourceImage condition="is">C:\Windows\system32\wbem\wmiprvse.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\System32\VBoxService.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\taskmgr.exe</SourceImage>
        <GrantedAccess condition="is">0x1000</GrantedAccess>
        <GrantedAccess condition="is">0x2000</GrantedAccess>
        <GrantedAccess condition="is">0x3000</GrantedAccess>
        <GrantedAccess condition="is">0x100000</GrantedAccess>
        <GrantedAccess condition="is">0x101000</GrantedAccess>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup groupRelation="or">
      <RegistryEvent onmatch="exclude">
        <EventType condition="is not">SetValue</EventType>
        <Image condition="is">C:\Windows\Sysmon.exe</Image>
        <Image condition="is">C:\Windows\Sysmon64.exe</Image>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup groupRelation="or">
      <DnsQuery onmatch="exclude">
        <Image condition="is">C:\Windows\Sysmon.exe</Image>
        <Image condition="is">C:\Windows\Sysmon64.exe</Image>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>`

	testAdminUser = &server.AdminAPIUser{
		Identifier: "test",
		Key:        utils.UnsafeKeyGen(api.DefaultKeySize),
	}

	mroot = filepath.Join(os.TempDir(), utils.UnsafeUUIDGen().String(), "data")
	mconf = server.ManagerConfig{
		AdminAPI: server.AdminAPIConfig{
			Host: "localhost",
			Port: randport(),
		},
		EndpointAPI: server.EndpointAPIConfig{
			Host: "localhost",
			Port: randport(),
		},
		Logging: server.ManagerLogConfig{
			Root:        filepath.Join(mroot, "logs"),
			LogBasename: "alerts",
		},
		Database: filepath.Join(mroot, "database"),
		DumpDir:  filepath.Join(mroot, "uploads"),
		TLS: server.TLSConfig{
			Cert: filepath.Join(mroot, "cert.pem"),
			Key:  filepath.Join(mroot, "key.pem"),
		},
	}

	// tools deployment
	osqueryBin         []byte
	osqueryTestBinPath = filepath.Join("data", fmt.Sprintf("%s.%s%s", los.OS, tools.ToolOSQueryi, los.ExecExt))
)

func init() {
	var err error

	if osqueryBin, err = os.ReadFile(osqueryTestBinPath); err != nil {
		panic(err)
	}

}

func testingRule() (r engine.Rule) {
	r = engine.NewRule()
	r.Name = "Testing:MatchAllSysmon"
	// FileCreate, FileDeleted and FileDeletedDetected
	r.Meta.Events = map[string][]int64{"Microsoft-Windows-Sysmon/Operational": {}}
	r.Meta.Criticality = 10
	return r
}

func generateCert(c server.ManagerConfig) {
	hosts := []string{c.AdminAPI.Host, c.EndpointAPI.Host}
	key, cert, err := utils.GenerateCert("Test", hosts, time.Hour*24*365)
	if err != nil {
		panic(err)
	}
	if err = os.MkdirAll(mroot, 0777); err != nil {
		panic(err)
	}
	if err = utils.HidsWriteData(c.TLS.Cert, cert); err != nil {
		panic(err)
	}
	if err = utils.HidsWriteData(c.TLS.Key, key); err != nil {
		panic(err)
	}
}

func randport() (port int) {
	for ; port <= 10000; port = rand.Intn(65535) {
	}
	return
}

func randomIoCs(n int) (iocs []*ioc.IOC) {
	for ; n > 0; n-- {
		iocs = append(iocs, &ioc.IOC{
			Uuid:      utils.UnsafeUUIDGen().String(),
			GroupUuid: utils.UnsafeUUIDGen().String(),
			Source:    "Xyz",
			Value:     fmt.Sprintf("%d.some.random.domain", rand.Intn(10000)),
			Type:      "domain",
		})
	}
	return
}

func makeClientConfig(mc *server.ManagerConfig) (c cconfig.Client) {
	var err error

	c = cconfig.Client{
		Proto:  "https",
		Host:   "localhost",
		Port:   mc.EndpointAPI.Port,
		UUID:   utils.UnsafeUUIDGen().String(),
		Key:    utils.UnsafeUUIDGen().String(),
		Unsafe: true,
	}

	if c.ServerFingerprint, err = utils.CertFileSha256(mc.TLS.Cert); err != nil {
		panic(err)
	}

	return
}

func prepareManager() (m *server.Manager, cconf cconfig.Client) {
	var err error

	mconf := mconf
	generateCert(mconf)
	cconf = makeClientConfig(&mconf)

	if m, err = server.NewManager(&mconf); err != nil {
		panic(err)
	}

	// we don't handle error as we don't care if user
	// already exists
	m.CreateNewAdminAPIUser(testAdminUser)

	osquery := tools.New(los.OS, tools.ToolOSQueryi, "osquery", osqueryBin)
	m.TestAddTool(osquery)

	m.AddEndpoint(cconf.UUID, cconf.Key)
	if err := m.AddIoCs(randomIoCs(1000)); err != nil {
		panic(err)
	}
	m.Run()

	return
}

func cleanup() {
	os.RemoveAll(mroot)
}

func installSysmon() {
	var i *sysmon.Info
	var c *sysmon.Config
	var err error

	sysmon.DefaultTimeout = time.Second * 60

	if sysmonInstalled {
		return
	}

	if i, err = sysmon.NewSysmonInfo(); errors.Is(err, sysmon.ErrSysmonNotInstalled) {
		if err = sysmon.InstallOrUpdate("../sysmon/data/Sysmon64.exe"); err != nil {
			panic(err)
		}

		if i, err = sysmon.NewSysmonInfo(); err != nil {
			panic(err)
		}
	}

	if err != nil {
		panic(err)
	}

	// we deserialize config
	if err = xml.Unmarshal([]byte(sysmonConfig), &c); err != nil {
		panic(err)
	}
	// we force the good schema version to be the one of sysmon installed
	c.SchemaVersion = i.Config.Version.Schema
	if sha256, err := c.Sha256(); err != nil {
		panic(err)
	} else if sha256 == i.Config.Hash {
		return
	}

	if xmlConfig, err := c.XML(); err != nil {
		panic(err)
	} else {
		// configuring Sysmon
		if err = sysmon.Configure(bytes.NewBuffer(xmlConfig)); err != nil {
			panic(err)
		}
	}

	sysmonInstalled = true
}

func testHook(h *Agent, e *event.EdrEvent) {
	fmt.Println(utils.PrettyJsonOrPanic(e))
}

func TestAgent(t *testing.T) {
	tt := toast.FromT(t)
	defer cleanup()

	manager, clConf := prepareManager()
	manager.Logger.ErrorHandler = tt.CheckErr

	installSysmon()

	var gotSysmonEvent bool
	var gotProcessTermination bool

	tmp, err := utils.HidsMkTmpDir()
	tt.CheckErr(err)
	defer os.RemoveAll(tmp)

	c := BuildDefaultConfig(tmp)
	// make logger log to stdout
	c.Logfile = ""
	c.FwdConfig.Local = false
	c.FwdConfig.Client = clConf
	// enable audit policy to trigger FileSystem events hooks
	c.AuditConfig.Enable = true
	c.AuditConfig.AuditDirs = []string{`C:\Windows`, `C:\Users`}
	// empty all actions
	c.Actions = config.Actions{
		AvailableActions: AvailableActions,
		Low:              []string{},
		Medium:           []string{},
		High:             []string{},
		Critical:         []string{},
	}

	// creating new agent
	a, err := NewAgent(c)
	tt.CheckErr(err)

	// loading testing rule
	r := testingRule()
	tt.CheckErr(a.Engine.LoadRule(&r))

	a.logger.ErrorHandler = tt.CheckErr
	// reduce scheduled task ticker
	for _, t := range a.scheduler.Tasks() {
		if t.Tick() > 0 {
			t.Ticker(time.Second * 5)
		}
	}

	// add a final hook to catch all events after enrichment
	a.preHooks.Hook(func(h *Agent, e *event.EdrEvent) {
		if e.Channel() == sysmonChannel {
			gotSysmonEvent = true
		}
		if isSysmonProcessTerminate(e) {
			gotProcessTermination = true
		}
		// create fake detection to cover action
		d := engine.NewDetection(true, true)
		// enable all actions
		//d.Actions = datastructs.NewInitSet(datastructs.ToInterfaceSlice(AvailableActions)...)
		d.Actions = datastructs.NewInitSet(ActionFiledump, ActionRegdump, ActionBrief, ActionReport)
		d.Criticality = 6
		e.SetDetection(d)
	}, fltAnyEvent)

	tt.TimeIt(
		"configuring autologgers",
		func() { tt.CheckErr(a.config.EtwConfig.ConfigureAutologger()) },
	)

	tt.CheckErr(err)
	a.Run()
	time.Sleep(20 * time.Second)
	a.Stop()

	tt.Assert(gotSysmonEvent, "failed to monitor Sysmon events")
	tt.Assert(gotProcessTermination, "failed to get Sysmon process termination event")

	report := a.Report(false)
	for _, c := range report.Commands {
		// control that we did not get any error
		tt.Assert(c.Error == "")
	}

	a.WaitWithTimeout(time.Second * 15)

	a.LogStats()
}
