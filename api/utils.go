package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
)

func respBodyToString(r *http.Response) string {
	defer r.Body.Close()
	if b, err := ioutil.ReadAll(r.Body); err != nil {
		return "failed to read response body"
	} else {
		return string(b)
	}
}

func muxGetVar(rq *http.Request, name string) (string, error) {
	vars := mux.Vars(rq)
	if value, ok := vars[name]; ok {
		return value, nil
	}
	return "", fmt.Errorf("unknown mux variable")
}

func format(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

// read posted data and unseriablize it from JSON
func readPostAsJSON(rq *http.Request, i interface{}) error {
	defer rq.Body.Close()
	b, err := ioutil.ReadAll(rq.Body)
	if err != nil {
		return fmt.Errorf("failed to read POST body: %w", err)
	}
	return json.Unmarshal(b, i)
}
