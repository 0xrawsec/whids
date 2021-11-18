package ioc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/whids/utils"
)

const (
	dbpath = "data/database"
)

func createIocDB(t *testing.T, size int) (db *sod.DB) {

	db = sod.Open(dbpath)

	schema := sod.DefaultSchema
	schema.Cache = true
	if err := db.Create(&IoC{}, sod.DefaultSchema); err != nil {
		t.Error(err)
	}

	if n, err := db.Count(&IoC{}); err != nil {
		t.Error(err)
		return
	} else if n != size {
		t.Logf("Dropping db n=%d size=%d", n, size)
		db.DeleteAll(&IoC{})
	} else {
		t.Logf("Db size n=%d", n)
		return
	}

	iocs := make([]sod.Object, 0)
	for i := 0; i < size; i++ {
		var ioc *IoC
		switch rand.Int() % 3 {
		case 0:
			ioc = &IoC{
				Source: "Whatever",
				Value:  fmt.Sprintf("%d.some.domain", i),
				Type:   "domain",
			}
		case 1:
			mod := i % 256
			ioc = &IoC{
				Source: "Whatever",
				Value:  fmt.Sprintf("%d.%d.%d.%d", mod, mod, mod, mod),
				Type:   "ip",
			}
		case 2:
			s := sha256.New()
			v := fmt.Sprintf("random-value-%d", i)
			s.Write([]byte(v))
			ioc = &IoC{
				Source: "Whatever",
				Value:  hex.EncodeToString(s.Sum(nil)),
				Type:   "domain",
			}
		}
		iocs = append(iocs, ioc)
	}

	if err := db.InsertOrUpdateMany(iocs...); err != nil {
		t.Error(err)
		t.FailNow()
	}

	return db
}

func TestIocs(t *testing.T) {
	iocs := NewIocs()
	db := createIocDB(t, 100000)
	if err := iocs.FromDB(db); err != nil {
		t.Error(err)
	}

	t.Logf("len(iocs)=%d", iocs.iocs.Len())
	hashSlice := utils.Sha256StringArray(iocs.StringSlice())
	if iocs.Hash() != hashSlice {
		t.Errorf("hash is not stable: iocs.Hash=%s hashSlice=%s", iocs.Hash(), hashSlice)
	}

	del := make([]*IoC, 0)
	for _, v := range iocs.StringSlice() {
		if rand.Int()%2 == 0 {
			del = append(del, &IoC{Value: v})
		}
	}
	iocs.Del(del...)

	t.Logf("len(iocs)=%d", iocs.iocs.Len())
	hashSlice = utils.Sha256StringArray(iocs.StringSlice())
	if iocs.Hash() != hashSlice {
		t.Errorf("hash is not stable after deletion: iocs.Hash=%s hashSlice=%s", iocs.Hash(), hashSlice)
	}
}
