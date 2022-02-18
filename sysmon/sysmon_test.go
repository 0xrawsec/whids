package sysmon

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/os"
)

var (
	config = `<Sysmon schemaversion="4.70">
  <CheckRevocation>false</CheckRevocation>
  <CopyOnDeletePE>false</CopyOnDeletePE>
  <DnsLookup>false</DnsLookup>
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
        <Image condition="is">C:\Windows\Sysmon.exe</Image>
        <Image condition="is">C:\Windows\Sysmon64.exe</Image>
        <Signature condition="is">Microsoft Windows Publisher</Signature>
        <Signature condition="is">Microsoft Corporation</Signature>
        <Signature condition="is">Microsoft Windows</Signature>
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

func TestConfig(t *testing.T) {
	var sha256 string
	tt := toast.FromT(t)
	c := Config{}
	c.OS = os.OS

	if err := xml.Unmarshal([]byte(config), &c); err != nil {
		t.Error(err)
	} else {
		sha256, err = c.Sha256()
		tt.CheckErr(err)

		xml, err := c.XML()
		tt.CheckErr(err)
		tt.Assert(string(xml) == config, "xml marshaling is not stable")
		t.Log(string(xml))

		// we marshal config to json
		js, err := json.MarshalIndent(c, "", "  ")
		tt.CheckErr(err)
		t.Log(string(js))
		new, _ := c.Sha256()
		tt.Assert(new == sha256, "bad sha256")

		same := Config{}
		tt.CheckErr(json.Unmarshal(js, &same))

		sameSha256, err := same.Sha256()
		tt.CheckErr(err)
		tt.Assert(sameSha256 == sha256, "JSON marshaling is not stable")

		tt.CheckErr(same.Validate())
	}
}

func TestValidation(t *testing.T) {
	tt := toast.FromT(t)

	c := Config{}

	// should return non nil error as os is not correct
	tt.ExpectErr(c.Validate(), ErrUnknownOS)
	c.OS = os.OS
	tt.ExpectErr(c.Validate(), ErrInvalidSchemaVersion)

	// testing onmatch validity
	tt.CheckErr(xml.Unmarshal([]byte(config), &c))
	c.EventFiltering.ProcessCreate = &ProcessCreate{}
	c.EventFiltering.ProcessCreate.OnMatch = "reject"
	tt.ExpectErr(c.Validate(), ErrInvalidOnMatch)
	c.EventFiltering.ProcessCreate.OnMatch = "exclude"
	tt.CheckErr(c.Validate())
	c.EventFiltering.ProcessCreate.OnMatch = "include"
	tt.CheckErr(c.Validate())

	// testing hash algorithm validity
	c.HashAlgorithms = []string{"SHA512"}
	tt.ExpectErr(c.Validate(), ErrInvalidHashAlgorithm)
	for _, ha := range ValidHashAlgorithm {
		c.HashAlgorithms = []string{ha}
		tt.CheckErr(c.Validate())
	}

	// testing condition validity
	c.EventFiltering.ProcessCreate.CommandLine = make([]Filter, 1)
	filter := &c.EventFiltering.ProcessCreate.CommandLine[0]
	filter.Condition = "has"
	tt.ExpectErr(c.Validate(), ErrInvalidCondition)
	for _, cdt := range Conditions {
		filter.Condition = cdt
		tt.CheckErr(c.Validate())
	}

	// testing rule group validity
	rg := &c.EventFiltering.RuleGroup[0]
	rg.Relation = "not and"
	tt.ExpectErr(c.Validate(), ErrInvalidGroupRelation)
	for _, rel := range ValidGroupRelation {
		rg.Relation = rel
		tt.CheckErr(c.Validate())
	}
}
