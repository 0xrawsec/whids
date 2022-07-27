package agent

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/agent/config"
	"github.com/0xrawsec/whids/event"
	"github.com/0xrawsec/whids/sysmon"
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
)

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
	fmt.Println(utils.PrettyJson(e))
}

func TestHooks(t *testing.T) {

	installSysmon()

	tt := toast.FromT(t)
	var gotSysmonEvent bool

	tmp, err := utils.HidsMkTmpDir()
	tt.CheckErr(err)
	defer os.RemoveAll(tmp)

	c := BuildDefaultConfig(tmp)
	c.Actions = config.Actions{
		AvailableActions: AvailableActions,
		Low:              []string{},
		Medium:           []string{},
		High:             []string{},
		Critical:         []string{},
	}

	h, err := NewAgent(c)
	// show EDR logs in console
	log.SetOutput(os.Stdout)

	// add a final hook to catch all events after enrichment
	h.preHooks.Hook(func(h *Agent, e *event.EdrEvent) {
		if e.Channel() == sysmonChannel {
			gotSysmonEvent = true
		}
		// create fake detection to cover action
		d := engine.NewDetection(true, true)
		// enable all actions
		//d.Actions = datastructs.NewInitSet(datastructs.ToInterfaceSlice(AvailableActions)...)
		d.Actions = datastructs.NewInitSet(ActionFiledump, ActionRegdump, ActionBlacklist, ActionBrief, ActionReport)
		d.Criticality = 6
		e.SetDetection(d)
	}, fltAnyEvent)

	tt.TimeIt(
		"configuring autologgers",
		func() { tt.CheckErr(h.config.EtwConfig.ConfigureAutologger()) },
	)

	tt.CheckErr(err)
	h.Run()
	time.Sleep(20 * time.Second)
	h.Stop()

	tt.Assert(gotSysmonEvent, "failed to monitor Sysmon events")

	t.Log(utils.PrettyJson(h.tracker.Modules()))
}
