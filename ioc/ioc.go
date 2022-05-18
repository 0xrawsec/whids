package ioc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"strings"
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/utils"
)

var (
	reMd5    = regexp.MustCompile("(?i:[a-f0-9]{32})")
	reSha1   = regexp.MustCompile("(?i:[a-f0-9]{40})")
	reSha256 = regexp.MustCompile("(?i:[a-f0-9]{64})")
	reAny    = regexp.MustCompile(".*")
)

func FromObjects(obs ...sod.Object) (out []*IOC) {
	out = make([]*IOC, len(obs))

	for i, o := range obs {
		out[i] = o.(*IOC)
	}
	return
}

const (
	TypeMd5      = "md5"
	TypeSha1     = "sha1"
	TypeSha256   = "sha256"
	TypeImphash  = "imphash"
	TypeDomain   = "domain"
	TypeHostname = "hostname"
	TypeIpDst    = "ip-dst"
)

type IOC struct {
	sod.Item
	Uuid string `json:"uuid" sod:"unique,lower"`
	// GroupUuid can be used to group IoCs
	GroupUuid string `json:"guuid" sod:"index,lower"`
	Source    string `json:"source" sod:"index"`
	Value     string `json:"value" sod:"index"`
	Type      string `json:"type" sod:"index,lower"`
}

func HasValidType(ioc *IOC) bool {
	switch ioc.Type {
	case TypeMd5,
		TypeSha1, TypeSha256,
		TypeImphash,
		TypeDomain,
		TypeHostname,
		TypeIpDst:
		return true
	default:
		return false
	}
}

func (ioc *IOC) Transform() {
	ioc.Type = strings.ToLower(ioc.Type)
	ioc.GroupUuid = strings.ToLower(ioc.GroupUuid)

	switch ioc.Type {
	case TypeMd5, TypeSha1, TypeSha256, TypeImphash:
		ioc.Value = strings.ToLower(ioc.Value)
	}
}

func (ioc *IOC) Validate() error {
	if !utils.IsValidUUID(ioc.Uuid) {
		return fmt.Errorf("uuid field is not properly formatted")
	}
	if !utils.IsValidUUID(ioc.GroupUuid) {
		return fmt.Errorf("group uuid field is not properly formatted")
	}
	if ioc.Source == "" {
		return fmt.Errorf("source must not be empty")
	}
	if ioc.Value == "" {
		return fmt.Errorf("value must not be empty")
	}

	// validating IoC types
	if !HasValidType(ioc) {
		return fmt.Errorf("unknown IoC type %s", ioc.Type)
	} else {
		validRe := reAny

		switch ioc.Type {
		case TypeMd5, TypeImphash:
			validRe = reMd5
		case TypeSha1:
			validRe = reSha1
		case TypeSha256:
			validRe = reSha256
		}
		if !validRe.MatchString(ioc.Value) {
			return fmt.Errorf("%s not valid", ioc.Type)
		}
	}
	return nil
}

type IoCs struct {
	sync.Mutex
	iocs   *datastructs.Set
	sha256 hash.Hash
}

func NewIocs() *IoCs {
	return &IoCs{
		iocs:   datastructs.NewSet(),
		sha256: sha256.New(),
	}
}

func (i *IoCs) reHash() {
	i.sha256 = sha256.New()
	for _, ii := range i.iocs.SortSlice() {
		ioc := ii.(string)
		i.sha256.Write([]byte(ioc))
	}
}

func (i *IoCs) FromDB(db *sod.DB) error {
	if objects, err := db.All(&IOC{}); err != nil {
		return err
	} else {
		for _, o := range objects {
			ioc := o.(*IOC)
			i.Add(ioc)
		}
	}
	return nil
}

func (i *IoCs) StringSlice() (s []string) {
	i.Lock()
	defer i.Unlock()
	s = make([]string, 0, i.iocs.Len())
	for _, ii := range i.iocs.SortSlice() {
		s = append(s, ii.(string))
	}
	return
}

func (i *IoCs) Add(iocs ...*IOC) {
	i.Lock()
	defer i.Unlock()
	for _, ioc := range iocs {
		// if we don't make this check Add method
		// changes the order of insertion which is not
		// in line anymore with sha256 computation
		if !i.iocs.Contains(ioc.Value) {
			i.iocs.Add(ioc.Value)
			i.sha256.Write([]byte(ioc.Value))
		}
	}
}

func (i *IoCs) Del(iocs ...*IOC) {
	i.Lock()
	defer i.Unlock()
	for _, ioc := range iocs {
		i.iocs.Del(ioc.Value)
	}
	i.reHash()
}

func (i *IoCs) Hash() string {
	i.Lock()
	defer i.Unlock()
	return hex.EncodeToString(i.sha256.Sum(nil))
}
