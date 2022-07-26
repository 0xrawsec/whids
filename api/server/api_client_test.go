package server

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/crypto/file"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/api"
	"github.com/0xrawsec/whids/api/client"
	"github.com/0xrawsec/whids/ioc"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/sysmon"
	"github.com/0xrawsec/whids/utils"
)

func TestClientGetRules(t *testing.T) {

	tt := toast.FromT(t)
	m, c := prep()
	defer cleanup(m)

	rules, err := c.GetRules()
	tt.CheckErr(err)

	sha256, err := c.GetRulesSha256()
	tt.CheckErr(err)
	tt.Assert(sha256 == data.Sha256([]byte(rules)))
}

func TestClientPostDump(t *testing.T) {
	var err error

	tt := toast.FromT(t)
	m, c := prep()
	defer cleanup(m)

	for wi := range fswalker.Walk("./dumps") {
		for _, fi := range wi.Files {
			var shrink *client.UploadShrinker
			sp := strings.Split(wi.Dirpath, "/")
			guid := sp[len(sp)-2]
			ehash := sp[len(sp)-1]
			path := filepath.Join(wi.Dirpath, fi.Name())

			shrink, err = client.NewUploadShrinker(path, guid, ehash)
			tt.CheckErr(err)

			for fu := shrink.Next(); fu != nil; fu = shrink.Next() {
				tt.CheckErr(c.PostDump(fu))
			}

			tt.CheckErr(shrink.Err())
		}
	}
}
func TestClientContainer(t *testing.T) {

	tt := toast.FromT(t)
	m, c := prep()
	defer cleanup(m)

	niocs := 1000
	iocs := make([]ioc.IOC, 0, niocs)
	del := 0
	guuid := utils.UnsafeUUIDGen().String()
	toDelGuuid := utils.UnsafeUUIDGen().String()
	for i := 0; i < niocs; i++ {
		key := guuid
		if rand.Int()%3 == 0 {
			key = toDelGuuid
			del++
		}

		iocs = append(iocs, ioc.IOC{
			Uuid:      utils.UnsafeUUIDGen().String(),
			GroupUuid: key,
			Source:    "Test",
			Value:     fmt.Sprintf("%d.random.com", i),
			Type:      "domain",
		})
	}

	// posting IOCs to manager
	r := post(api.AdmAPIIocsPath, JSON(iocs))
	tt.CheckErr(r.Err())

	// getting IOCs on client
	strIocs, err := c.GetIoCs()
	tt.CheckErr(err)
	// we must have the same number of iocs
	tt.Assert(len(strIocs) == niocs)
	// we control that the integrity of what we received
	rsha256, _ := c.GetIoCsSha256()
	tt.Assert(rsha256 == utils.Sha256StringArray(strIocs))

	// deleting iocs from admin API
	req := prepare("DELETE",
		api.AdmAPIIocsPath,
		nil,
		map[string]string{api.QpGroupUuid: toDelGuuid})
	r = do(req)
	tt.CheckErr(r.Err())

	strIocs, err = c.GetIoCs()
	tt.CheckErr(err)
	tt.Assert(len(strIocs) == niocs-del)
	rsha256, _ = c.GetIoCsSha256()
	// control integrity of what we downloaded
	tt.Assert(rsha256 == utils.Sha256StringArray(strIocs))
}

func TestClientExecuteCommand(t *testing.T) {
	var cmdline string
	var cmd *api.EndpointCommand
	var err error

	tt := toast.FromT(t)
	m, c := prep()
	defer cleanup(m)

	cmd = api.NewEndpointCommand()

	switch runtime.GOOS {
	case "windows":
		cmdline = "cmd /c dir"
	default:
		cmdline = "/usr/bin/ls -hail ./"
	}

	tt.CheckErr(cmd.SetCommandLine(cmdline))
	tt.CheckErr(m.AddCommand(cconf.UUID, cmd))

	// client fetching command to execute
	cmd, err = c.FetchCommand()
	tt.CheckErr(err)
	// running command
	tt.CheckErr(cmd.Run())
	// posting back command to manager
	tt.CheckErr(c.PostCommand(cmd))

	// manager fetching command
	cmd, err = m.GetCommand(cconf.UUID)
	tt.CheckErr(err)
	// we expect some output
	tt.Assert(len(cmd.Stdout) > 0)

	t.Logf("Stdout of command executed: %s", string(cmd.Stdout))

}
func TestClientExecuteDroppedCommand(t *testing.T) {
	var cmd *api.EndpointCommand
	var err error
	var dropname, dropfile, fetchfile, cmdline string

	tt := toast.FromT(t)
	m, c := prep()
	defer cleanup(m)

	switch runtime.GOOS {
	case "windows":
		dropname = `./dropped.exe`
		dropfile = `C:\Windows\System32\cmd.exe`
		fetchfile = `C:\Windows\System32\reg.exe`
		cmdline = format("%s /c dir C:", dropname)

	default:
		dropname = "./dropped"
		dropfile = "/usr/bin/ls"
		fetchfile = "/usr/bin/true"
		cmdline = format("%s -hail", dropname)
	}

	cmd = api.NewEndpointCommand()
	// adding files to drop
	tt.CheckErr(cmd.AddDropFile(dropname, dropfile))

	// adding files to fetch
	cmd.AddFetchFile(fetchfile)
	cmd.AddFetchFile("/nonexistingfile")

	// setting up the command line to be executed
	tt.CheckErr(cmd.SetCommandLine(cmdline))
	// create the command on manager's side
	tt.CheckErr(m.AddCommand(cconf.UUID, cmd))

	// fetching the command on client side
	cmd, err = c.FetchCommand()
	tt.CheckErr(err)
	// running command
	tt.CheckErr(cmd.Run())
	tt.CheckErr(cmd.Err())
	// posting back command to manager
	tt.CheckErr(c.PostCommand(cmd))

	// getting command on manager's side
	cmd, err = m.GetCommand(cconf.UUID)
	tt.CheckErr(err)
	// expecting some output on stdout
	tt.Assert(len(cmd.Stdout) != 0)

	t.Logf("Stdout of command executed: %s", string(cmd.Stdout))

	expMD5, err := file.Md5(fetchfile)
	tt.CheckErr(err)
	// checking that the file we fetched corresponds to the one on disk
	tt.Assert(data.Md5(cmd.Fetch[fetchfile].Data) == expMD5)
	// we must get an error for non existing file
	tt.Assert(cmd.Fetch["/nonexistingfile"].Error != "")

	t.Logf(cmd.Fetch["/nonexistingfile"].Error)
}

func TestClientSysmonConfig(t *testing.T) {
	var err error

	sversion := "4.70"
	tt := toast.FromT(t)
	m, c := prep()
	defer cleanup(m)

	// test emptyness
	sha256, err := c.GetSysmonConfigSha256(sversion)
	tt.ExpectErr(err, client.ErrNoSysmonConfig)
	tt.Assert(sha256 == "")

	_, err = c.GetSysmonConfig(sversion)
	tt.ExpectErr(err, client.ErrNoSysmonConfig)

	// preparing sysmon config structure
	cfg := &sysmon.Config{}
	tt.CheckErr(xml.Unmarshal([]byte(sysmonXMLConfig), &cfg))
	cfg.OS = los.OS
	cfgSha256, err := cfg.Sha256()
	tt.CheckErr(err)

	// adding sysmon config and testing sha256
	tt.CheckErr(m.db.InsertOrUpdate(cfg))
	sha256, err = c.GetSysmonConfigSha256(sversion)
	tt.CheckErr(err)
	tt.Assert(sha256 == cfgSha256)

	remoteCfg, err := c.GetSysmonConfig(sversion)
	tt.CheckErr(err)
	tt.Assert(remoteCfg.XmlSha256 == sha256)

	b, err := json.MarshalIndent(remoteCfg, "", "  ")
	tt.CheckErr(err)
	t.Log(string(b))
}
