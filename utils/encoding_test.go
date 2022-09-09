package utils

import (
	"testing"

	"github.com/0xrawsec/toast"
)

func TestEncoding(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	ts := testStruct{}

	tt.Assert(PrettyJsonOrPanic(ts) != "")
	tt.Assert(JsonOrPanic(ts) != nil)
	tt.Assert(JsonStringOrPanic(ts) != "")
	js, err := JsonString(ts)
	tt.CheckErr(err)
	tt.Assert(js != "")
	toml, err := Toml(ts)
	tt.CheckErr(err)
	tt.Assert(toml != nil)
	tomls, err := TomlString(ts)
	tt.CheckErr(err)
	tt.Assert(tomls != "")
}
