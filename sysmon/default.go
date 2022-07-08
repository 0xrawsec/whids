package sysmon

import (
	"encoding/xml"
	"fmt"

	"github.com/0xrawsec/whids/los"
)

var (
	agnosticConfig = `<Sysmon schemaversion="%s">
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

	  <ImageLoad onmatch="exclude"></ImageLoad>

    <ProcessAccess onmatch="exclude">
      <GrantedAccess condition="is">0x1000</GrantedAccess>
      <GrantedAccess condition="is">0x1400</GrantedAccess>
      <GrantedAccess condition="is">0x2000</GrantedAccess>
      <GrantedAccess condition="is">0x3000</GrantedAccess>
      <GrantedAccess condition="is">0x100000</GrantedAccess>
      <GrantedAccess condition="is">0x101000</GrantedAccess>
    </ProcessAccess>

	  <RegistryEvent onmatch="exclude">
		  <EventType condition="is not">SetValue</EventType>
	  </RegistryEvent>

	  <DnsQuery onmatch="exclude"></DnsQuery>
  </EventFiltering>
</Sysmon>`
)

func AgnosticConfig(schemaversion string) (c *Config, err error) {

	config := []byte(fmt.Sprintf(agnosticConfig, schemaversion))

	if err = xml.Unmarshal(config, &c); err != nil {
		return
	}

	// set sha256 of config structure
	if c.XmlSha256, err = c.Sha256(); err != nil {
		return
	}

	// Config struct needs a valid OS to be validated
	c.OS = los.OS
	err = c.Validate()
	return
}
