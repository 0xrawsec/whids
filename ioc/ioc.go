package ioc

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/sod"
)

func FromObjects(obs ...sod.Object) (out []*IoC) {
	out = make([]*IoC, len(obs))

	for i, o := range obs {
		out[i] = o.(*IoC)
	}
	return
}

type IoC struct {
	sod.Item
	Source string `json:"source" sod:"index"`
	// Key can be used to group IoCs
	Key   string `json:"key" sod:"index"`
	Value string `json:"value" sod:"index"`
	Type  string `json:"type" sod:"index"`
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
	if objects, err := db.All(&IoC{}); err != nil {
		return err
	} else {
		for _, o := range objects {
			ioc := o.(*IoC)
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

func (i *IoCs) Add(iocs ...*IoC) {
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

func (i *IoCs) Del(iocs ...*IoC) {
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
