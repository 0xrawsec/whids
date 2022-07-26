package client

import (
	"io/ioutil"
	"net/http"
)

func requestAddURLParam(r *http.Request, key, value string) {
	q := r.URL.Query()
	q.Add(key, value)
	r.URL.RawQuery = q.Encode()
}

func respBodyToString(r *http.Response) string {
	defer r.Body.Close()
	if b, err := ioutil.ReadAll(r.Body); err != nil {
		return "failed to read response body"
	} else {
		return string(b)
	}
}
