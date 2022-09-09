package ioc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/0xrawsec/sod"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/utils"
)

const (
	dbpath = "data/database"
)

var (
	format = fmt.Sprintf
)

func uuidGen() string {
	return utils.UUIDOrPanic().String()
}

func createIocDB(t *testing.T, size int) (db *sod.DB) {

	tt := toast.FromT(t)

	db = sod.Open(dbpath)

	schema := sod.DefaultSchema
	schema.Cache = true
	tt.CheckErr(db.Create(&IOC{}, sod.DefaultSchema))

	n, err := db.Count(&IOC{})
	tt.CheckErr(err)
	if n != size {
		t.Logf("Dropping db n=%d size=%d", n, size)
		db.DeleteAll(&IOC{})
	} else {
		t.Logf("Db size n=%d", n)
		return
	}

	iocs := make([]sod.Object, 0)
	for i := 0; i < size; i++ {
		var ioc *IOC
		switch rand.Int() % 3 {
		case 0:
			ioc = &IOC{
				Uuid:      uuidGen(),
				GroupUuid: uuidGen(),
				Source:    "Whatever",
				Value:     fmt.Sprintf("%d.some.domain", i),
				Type:      "domain",
			}
		case 1:
			mod := i % 256
			ioc = &IOC{
				Uuid:      uuidGen(),
				GroupUuid: uuidGen(),
				Source:    "Whatever",
				Value:     fmt.Sprintf("%d.%d.%d.%d", mod, mod, mod, mod),
				Type:      "ip-dst",
			}
		case 2:
			s := sha256.New()
			v := fmt.Sprintf("random-value-%d", i)
			s.Write([]byte(v))
			ioc = &IOC{
				Uuid:      uuidGen(),
				GroupUuid: uuidGen(),
				Source:    "Whatever",
				Value:     hex.EncodeToString(s.Sum(nil)),
				Type:      "domain",
			}
		}
		iocs = append(iocs, ioc)
	}

	_, err = db.InsertOrUpdateMany(iocs...)
	tt.CheckErr(err)

	return db
}

func TestIocs(t *testing.T) {
	var db *sod.DB
	tt := toast.FromT(t)

	iocs := NewIocs()

	tt.TimeIt("creating DB", func() { db = createIocDB(t, 5000) })
	defer db.Drop()
	tt.CheckErr(iocs.FromDB(db))

	t.Logf("len(iocs)=%d", iocs.iocs.Len())
	hashSlice := utils.Sha256StringArray(iocs.StringSlice())
	tt.Assert(iocs.Hash() == hashSlice, format("hash is not stable: iocs.Hash=%s hashSlice=%s", iocs.Hash(), hashSlice))

	del := make([]*IOC, 0)
	for _, v := range iocs.StringSlice() {
		if rand.Int()%2 == 0 {
			del = append(del, &IOC{Value: v})
		}
	}
	iocs.Del(del...)

	t.Logf("len(iocs)=%d", iocs.iocs.Len())
	hashSlice = utils.Sha256StringArray(iocs.StringSlice())
	tt.Assert(iocs.Hash() == hashSlice, format("hash is not stable: iocs.Hash=%s hashSlice=%s", iocs.Hash(), hashSlice))
}
