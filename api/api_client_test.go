package api

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/crypto/file"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/whids/utils"
)

var (
	cconf = ClientConfig{
		Proto:             "https",
		Host:              "localhost",
		Port:              8000,
		UUID:              "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
		Key:               "don'tcomplain",
		ServerFingerprint: "511dc40cb2363974a97dfd47437feb8307cbd9d938645e1442775aa97ec14227",
		Unsafe:            true,
	}
)

func TestClientGetRules(t *testing.T) {
	key := KeyGen(DefaultKeySize)

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()

	cconf.Key = key
	c, err := NewManagerClient(&cconf)
	if err != nil {
		panic(err)
	}
	rules, err := c.GetRules()
	if err != nil {
		t.Errorf("%s", err)
	}

	sha256, err := c.GetRulesSha256()
	if err != nil {
		t.Errorf("%s", err)
	}
	if sha256 != data.Sha256([]byte(rules)) {
		t.Errorf("Rules integrity cannot be verified")
	}

	r.Shutdown()

}

func TestClientPostDump(t *testing.T) {
	key := KeyGen(DefaultKeySize)

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()
	defer r.Shutdown()

	cconf.Key = key
	c, err := NewManagerClient(&cconf)
	if err != nil {
		panic(err)
	}

	for wi := range fswalker.Walk("./dumps") {
		for _, fi := range wi.Files {
			sp := strings.Split(wi.Dirpath, "/")
			path := filepath.Join(wi.Dirpath, fi.Name())
			fu, err := c.PrepareFileUpload(path, sp[len(sp)-2], sp[len(sp)-1], fi.Name())
			if err != nil {
				t.Errorf("Failed to prepare dump: %s", path)
			}
			c.PostDump(fu)
		}
	}
}
func TestClientContainer(t *testing.T) {

	key := KeyGen(DefaultKeySize)

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()
	defer r.Shutdown()

	cconf.Key = key
	c, err := NewManagerClient(&cconf)
	if err != nil {
		panic(err)
	}

	containers, err := c.GetContainersList()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	verif := datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(containers)...)
	if !verif.Contains("blacklist") || !verif.Contains("whitelist") {
		t.Error("Missing containers")
		t.FailNow()
	}

	for _, cont := range containers {
		bl, err := c.GetContainer(cont)
		if err != nil {
			t.Error(err)
		}

		if sha256, err := c.GetContainerSha256(cont); sha256 != utils.Sha256StringArray(bl) || err != nil {
			if err != nil {
				t.Error(err)
			} else {
				t.Errorf("Failed to verify container integrity")
			}
		}
		t.Logf("%v", bl)
	}
}

func TestClientExecuteCommand(t *testing.T) {
	var cmd *Command
	var err error

	key := KeyGen(DefaultKeySize)

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()
	defer r.Shutdown()

	cconf.Key = key
	c, err := NewManagerClient(&cconf)
	if err != nil {
		panic(err)
	}

	cmd = NewCommand()

	if err = cmd.SetCommandLine("/usr/bin/ls -hail ./"); err != nil {
		t.Errorf("Failed at setting command line: %s", err)
		t.Fail()
	}

	if err := r.AddCommand(cconf.UUID, cmd); err != nil {
		t.Errorf("Failed to add command")
		t.Fail()
	}

	if _, err := c.ExecuteCommand(); err != nil {
		t.Errorf("Client failed to execute command")
		t.Fail()
	}

	cmd, err = r.GetCommand(cconf.UUID)
	if err != nil {
		t.Errorf("Client failed to get back command")
		t.Fail()
	}

	if cmd.Stdout == nil {
		t.Errorf("Expected output on stdout")
		t.Fail()
	}

	if len(cmd.Stdout) == 0 {
		t.Errorf("Expected output on stdout")
		t.Fail()
	}

	t.Logf("Stdout of command executed: %s", string(cmd.Stdout))

}
func TestClientExecuteDroppedCommand(t *testing.T) {
	var cmd *Command
	var err error

	key := KeyGen(DefaultKeySize)

	r, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddEndpoint(cconf.UUID, key)
	r.Run()
	defer r.Shutdown()

	// let the time to the server to start
	time.Sleep(1 * time.Second)

	cconf.Key = key
	c, err := NewManagerClient(&cconf)
	if err != nil {
		panic(err)
	}

	cmd = NewCommand()

	if err = cmd.AddDropFile("droppedls", "/usr/bin/ls"); err != nil {
		t.Errorf("Failed at preparing file to drop: %s", err)
		t.FailNow()
	}

	cmd.AddFetchFile("/usr/bin/ls")
	cmd.AddFetchFile("/nonexistingfile")

	if err = cmd.SetCommandLine("./droppedls -hail ./"); err != nil {
		t.Errorf("Failed at setting command line: %s", err)
		t.FailNow()
	}

	if err := r.AddCommand(cconf.UUID, cmd); err != nil {
		t.Errorf("Failed to add command")
		t.FailNow()
	}

	if _, err := c.ExecuteCommand(); err != nil {
		t.Errorf("Client failed to execute command")
		t.FailNow()
	}

	cmd, err = r.GetCommand(cconf.UUID)
	if err != nil {
		t.Errorf("Client failed to get back command")
		t.FailNow()
	}

	if len(cmd.Stdout) == 0 {
		t.Errorf("Expected output on stdout")
		t.FailNow()
	}

	t.Logf("Stdout of command executed: %s", string(cmd.Stdout))

	expMD5, err := file.Md5("/usr/bin/ls")
	if err != nil {
		t.Logf("Failed to compute expected MD5: %s", err)
		t.Fail()
	}

	if data.Md5(cmd.Fetch["/usr/bin/ls"].Data) != expMD5 {
		t.Logf("Bad integrity check")
		t.Fail()
	}

	if cmd.Fetch["/nonexistingfile"].Error == "" {
		t.Logf("Failed to retrieve error")
		t.Fail()
	}
	t.Logf(cmd.Fetch["/nonexistingfile"].Error)
}
