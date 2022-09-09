package utils

import (
	"bytes"
	"encoding/json"

	"github.com/pelletier/go-toml/v2"
)

// PrettyJsonOrPanic returns a JSON pretty string out of i
func PrettyJsonOrPanic(i interface{}) string {
	b, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func JsonOrPanic(i interface{}) []byte {
	b, err := Json(i)
	if err != nil {
		panic(err)
	}
	return b
}

// JsonStringOrPanic returns a Json string out of i
func JsonStringOrPanic(i interface{}) string {
	return string(JsonOrPanic(i))
}

func Json(i any) ([]byte, error) {
	return json.Marshal(i)
}

func JsonString(i any) (s string, err error) {
	var b []byte
	if b, err = Json(i); err != nil {
		return
	}
	s = string(b)
	return
}

func Toml(i interface{}) (b []byte, err error) {
	buf := new(bytes.Buffer)
	enc := toml.NewEncoder(buf)

	if err = enc.Encode(i); err != nil {
		return
	}

	b = buf.Bytes()
	return
}

func TomlString(i any) (s string, err error) {
	var b []byte
	b, err = Toml(i)
	s = string(b)
	return
}
