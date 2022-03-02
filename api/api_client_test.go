package api

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/crypto/file"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/ioc"
	"github.com/0xrawsec/whids/utils"
)

var (
	cconf = ClientConfig{
		Proto:             "https",
		Host:              "localhost",
		Port:              mconf.EndpointAPI.Port,
		UUID:              "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
		Key:               "don'tcomplain",
		ServerFingerprint: "511dc40cb2363974a97dfd47437feb8307cbd9d938645e1442775aa97ec14227",
		Unsafe:            true,
	}
)

func TestClientGetRules(t *testing.T) {

	tt := toast.FromT(t)
	m, c := prep()
	defer m.Shutdown()

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
	defer m.Shutdown()

	for wi := range fswalker.Walk("./dumps") {
		for _, fi := range wi.Files {
			var shrink *UploadShrinker
			sp := strings.Split(wi.Dirpath, "/")
			guid := sp[len(sp)-2]
			ehash := sp[len(sp)-1]
			path := filepath.Join(wi.Dirpath, fi.Name())

			shrink, err = NewUploadShrinker(path, guid, ehash)
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
	defer m.Shutdown()

	niocs := 1000
	iocs := make([]ioc.IOC, 0, niocs)
	del := 0
	guuid := UUIDGen().String()
	toDelGuuid := UUIDGen().String()
	for i := 0; i < niocs; i++ {
		key := guuid
		if rand.Int()%3 == 0 {
			key = toDelGuuid
			del++
		}

		iocs = append(iocs, ioc.IOC{
			Uuid:      UUIDGen().String(),
			GroupUuid: key,
			Source:    "Test",
			Value:     fmt.Sprintf("%d.random.com", i),
			Type:      "domain",
		})
	}

	// posting IOCs to manager
	r := post(AdmAPIIocsPath, JSON(iocs))
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
		AdmAPIIocsPath,
		nil,
		map[string]string{qpGroupUuid: toDelGuuid})
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
	var cmd *Command
	var err error

	tt := toast.FromT(t)
	m, c := prep()
	defer m.Shutdown()

	cmd = NewCommand()

	tt.CheckErr(cmd.SetCommandLine("/usr/bin/ls -hail ./"))
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
	var cmd *Command
	var err error

	tt := toast.FromT(t)
	m, c := prep()
	defer m.Shutdown()

	cmd = NewCommand()
	// adding files to drop
	tt.CheckErr(cmd.AddDropFile("droppedls", "/usr/bin/ls"))

	// adding files to fetch
	cmd.AddFetchFile("/usr/bin/ls")
	cmd.AddFetchFile("/nonexistingfile")

	// setting up the command line to be executed
	tt.CheckErr(cmd.SetCommandLine("./droppedls -hail ./"))
	// create the command on manager's side
	tt.CheckErr(m.AddCommand(cconf.UUID, cmd))

	// fetching the command on client side
	cmd, err = c.FetchCommand()
	tt.CheckErr(err)
	// running command
	tt.CheckErr(cmd.Run())
	// posting back command to manager
	tt.CheckErr(c.PostCommand(cmd))

	// getting command on manager's side
	cmd, err = m.GetCommand(cconf.UUID)
	tt.CheckErr(err)
	// expecting some output on stdout
	tt.Assert(len(cmd.Stdout) != 0)

	t.Logf("Stdout of command executed: %s", string(cmd.Stdout))

	expMD5, err := file.Md5("/usr/bin/ls")
	tt.CheckErr(err)
	// checking that the file we fetched corresponds to the one on disk
	tt.Assert(data.Md5(cmd.Fetch["/usr/bin/ls"].Data) == expMD5)
	// we must get an error for non existing file
	tt.Assert(cmd.Fetch["/nonexistingfile"].Error != "")

	t.Logf(cmd.Fetch["/nonexistingfile"].Error)
}
