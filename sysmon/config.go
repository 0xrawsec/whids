package sysmon

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/los"
)

var (
	ValidOnMatch = []string{
		"include",
		"exclude",
		"",
	}

	ValidGroupRelation = []string{
		"and",
		"or",
		"",
	}

	ValidHashAlgorithm = []string{
		"IMPHASH",
		"MD5",
		"SHA1",
		"SHA256",
		"*",
		"",
	}

	ErrUnknownOS            = fmt.Errorf("unknown OS")
	ErrInvalidSchemaVersion = fmt.Errorf("invalid schema version")
	ErrInvalidGroupRelation = fmt.Errorf("invalid group relation")
	ErrInvalidCondition     = fmt.Errorf("invalid condition")
	ErrInvalidOnMatch       = fmt.Errorf("invalid onmatch")
	ErrInvalidHashAlgorithm = fmt.Errorf("invalid hash algorithm")

	schemaVersionRe = regexp.MustCompile(`\d+\.\d+`)
)

func validate(value string, in ...string) bool {
	for _, check := range in {
		if value == check {
			return true
		}
	}
	return false
}

type EventFilter struct {
	OnMatch string `xml:"onmatch,attr,omitempty" json:"onmatch,omitempty"`
}

func (e *EventFilter) Validate() error {
	if !validate(e.OnMatch, ValidOnMatch...) {
		return fmt.Errorf("%w %s", ErrInvalidOnMatch, e.OnMatch)
	}
	return nil
}

type Filter struct {
	Name      string `xml:"name,attr,omitempty" json:"name,omitempty"`
	Condition string `xml:"condition,attr,omitempty" json:"condition,omitempty"`
	Value     string `xml:",innerxml" json:"value"`
}

func (f *Filter) Validate() error {
	if !validate(f.Condition, Conditions...) {
		return fmt.Errorf("%w %s on value %s", ErrInvalidCondition, f.Condition, f.Value)
	}
	return nil
}

// Method of Filters structure not wanted to be overwritten by auto generation

func (f *Filters) Validate() error {
	// we get the value of the struct and not of the pointer
	v := reflect.ValueOf(f).Elem()
	for i := 0; i < v.NumField(); i++ {
		evtFilter := v.Field(i)
		if evtFilter.IsNil() {
			continue
		}
		filterName := v.Type().Field(i).Name
		method := evtFilter.MethodByName("Validate")
		res := method.Call([]reflect.Value{})
		if !res[0].IsNil() {
			return fmt.Errorf("%s %s", filterName, res[0].Interface().(error))
		}

		evtFilter = evtFilter.Elem()
		for k := 0; k < evtFilter.NumField(); k++ {
			field := evtFilter.Field(k)
			i := field.Interface()
			if filters, ok := i.([]Filter); ok {
				for _, f := range filters {
					if err := f.Validate(); err != nil {
						return fmt.Errorf("%s bad %s filter: %w", filterName, evtFilter.Type().Field(k).Name, err)
					}
				}
			}
		}
	}
	return nil
}

type RuleGroup struct {
	Filters
	Name     string `xml:"name,attr,omitempty" json:",omitempty"`
	Relation string `xml:"groupRelation,attr,omitempty" json:"groupRelation,omitempty"`
}

func (g *RuleGroup) Validate() error {
	if !validate(g.Relation, ValidGroupRelation...) {
		return fmt.Errorf("%w %s", ErrInvalidGroupRelation, g.Relation)
	}

	return g.Filters.Validate()
}

type EventFiltering struct {
	Filters
	RuleGroup []RuleGroup
}

type InnerConfig struct {
	XMLName                xml.Name  `xml:"Sysmon" json:"-"`
	SchemaVersion          string    `xml:"schemaversion,attr" json:"schemaversion"`
	ArchiveDirectory       string    `xml:",omitempty" json:",omitempty"`
	CheckRevocation        bool      `xml:",omitempty"`
	CopyOnDeletePE         bool      `xml:",omitempty"`
	CopyOnDeleteSIDs       csstrings `xml:",omitempty" json:",omitempty"`
	CopyOnDeleteExtensions csstrings `xml:",omitempty" json:",omitempty"`
	CopyOnDeleteProcesses  csstrings `xml:",omitempty" json:",omitempty"`
	DriverName             string    `xml:",omitempty" json:",omitempty"`
	DnsLookup              bool      `xml:",omitempty"`
	HashAlgorithms         csstrings `xml:",omitempty" json:",omitempty"`
	EventFiltering         EventFiltering
	// Don't validate Sysmon XML DTD
	XmlSha256 string `xml:"-"`
	OS        string `xml:"-"`
}

type Config struct {
	sod.Item
	InnerConfig
}

func (c Config) MarshalJSON() (b []byte, err error) {
	if c.XmlSha256, err = c.Sha256(); err != nil {
		return
	}
	return json.MarshalIndent(c.InnerConfig, "", "  ")
}

func (c *Config) Validate() (err error) {
	if !schemaVersionRe.MatchString(c.SchemaVersion) {
		return fmt.Errorf("%w %s", ErrInvalidSchemaVersion, c.SchemaVersion)
	}

	if !los.IsKnownOS(c.OS) {
		return fmt.Errorf("%w %s", ErrUnknownOS, c.OS)
	}

	for _, ha := range c.HashAlgorithms {
		if !validate(ha, ValidHashAlgorithm...) {
			return fmt.Errorf("%w %s", ErrInvalidHashAlgorithm, ha)
		}
	}

	if err = c.EventFiltering.Validate(); err != nil {
		return
	}

	for _, rg := range c.EventFiltering.RuleGroup {
		if err = rg.Validate(); err != nil {
			return
		}
	}

	return
}

func (c *Config) XML() (b []byte, err error) {
	return xml.MarshalIndent(c, "", "  ")
}

func (c *Config) Sha256() (sha256 string, err error) {
	var b []byte

	if b, err = c.XML(); err != nil {
		return
	}

	sha256 = data.Sha256(b)

	return
}

// to manage comma separated strings used by some Sysmon config fields
type csstrings []string

func (s csstrings) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(strings.Join(s, ","), start)
}

func (s *csstrings) UnmarshalXML(d *xml.Decoder, start xml.StartElement) (err error) {
	var csstring string
	if err = d.DecodeElement(&csstring, &start); err != nil {
		return
	}
	*s = strings.Split(csstring, ",")
	return
}
