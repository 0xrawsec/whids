package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/whids/collector"
)

var (
	cconf = collector.ClientConfig{
		Proto: "http",
		Host:  "localhost",
		Port:  8000,
		Key:   "don'tcomplain",
	}
)

func TestClientGetRules(t *testing.T) {
	key := collector.KeyGen(collector.DefaultKeySize)

	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()

	cconf.Key = key
	c, err := collector.NewManagerClient(&cconf)
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
	key := collector.KeyGen(collector.DefaultKeySize)

	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()
	defer r.Shutdown()

	cconf.Key = key
	c, err := collector.NewManagerClient(&cconf)
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

	key := collector.KeyGen(collector.DefaultKeySize)

	r, err := collector.NewManager(&mconf)
	if err != nil {
		panic(err)
	}
	r.AddAuthKey(key)
	r.Run()
	defer r.Shutdown()

	cconf.Key = key
	c, err := collector.NewManagerClient(&cconf)
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

		if sha256, err := c.GetContainerSha256(cont); sha256 != collector.Sha256StringArray(bl) || err != nil {
			if err != nil {
				t.Error(err)
			} else {
				t.Errorf("Failed to verify container integrity")
			}
		}
		t.Logf("%v", bl)
	}
}
