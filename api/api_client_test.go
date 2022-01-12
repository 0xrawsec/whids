package api

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/crypto/file"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
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
			var shrink *UploadShrinker
			sp := strings.Split(wi.Dirpath, "/")
			guid := sp[len(sp)-2]
			ehash := sp[len(sp)-1]
			path := filepath.Join(wi.Dirpath, fi.Name())

			if shrink, err = NewUploadShrinker(path, guid, ehash); err != nil {
				t.Errorf("Failed to prepare dump: %s", path)
			}
			for fu := shrink.Next(); fu != nil; fu = shrink.Next() {
				if err = c.PostDump(fu); err != nil {
					t.Error(err)
				}
			}
			if shrink.Err() != nil {
				t.Error(shrink.Err())
			}
		}
	}
}
func TestClientContainer(t *testing.T) {

	key := KeyGen(DefaultKeySize)

	m, err := NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	m.AddEndpoint(cconf.UUID, key)
	m.Run()
	defer m.Shutdown()

	cconf.Key = key
	c, err := NewManagerClient(&cconf)
	if err != nil {
		panic(err)
	}

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

	if r := post(AdmAPIIocsPath, JSON(iocs)); r.Err() != nil {
		t.Error(r.Err())
		t.FailNow()
	}

	if iocs, err := c.GetIoCs(); err != nil {
		t.Error(err)
	} else {
		if len(iocs) != niocs {
			t.Error("Unexpected IOC length")
		}
		if rsha256, _ := c.GetIoCsSha256(); rsha256 != utils.Sha256StringArray(m.iocs.StringSlice()) {
			t.Error("IOC container hash is not correct")
		}
	}

	// deleting iocs from admin API
	r := prepare("DELETE",
		AdmAPIIocsPath,
		nil,
		map[string]string{qpGroupUuid: toDelGuuid})
	do(r)

	if iocs, err := c.GetIoCs(); err != nil {
		t.Error(err)
	} else {
		if len(iocs) != niocs-del {
			t.Errorf("Unexpected IOC length expected %d, got %d", niocs-del, len(iocs))
		}
		if rsha256, _ := c.GetIoCsSha256(); rsha256 != utils.Sha256StringArray(m.iocs.StringSlice()) {
			t.Error("IOC container hash is not correct")
		}
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

	if cmd, err := c.FetchCommand(); err != nil {
		t.Errorf("Client failed to fetch command: %s", err)
		t.FailNow()
	} else {
		if err := cmd.Run(); err != nil {
			t.Errorf("Failed to run command: %s", err)
			t.FailNow()
		}
		if err := c.PostCommand(cmd); err != nil {
			t.Errorf("Failed to post command: %s", err)
			t.FailNow()
		}
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

	t.Logf("%v", cmd.Stdout)
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

	if cmd, err := c.FetchCommand(); err != nil {
		t.Errorf("Client failed to fetch command: %s", err)
		t.FailNow()
	} else {
		if err := cmd.Run(); err != nil {
			t.Errorf("Failed to run command: %s", err)
			t.FailNow()
		}
		if err := c.PostCommand(cmd); err != nil {
			t.Errorf("Failed to post command: %s", err)
			t.FailNow()
		}
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
