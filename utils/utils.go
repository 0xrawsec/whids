package utils

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/0xrawsec/golang-utils/log"
)

// HTTPGet helper function to issue a simple HTTP GET method
func HTTPGet(client *http.Client, url, outPath string) (err error) {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Building new request
	req, err := http.NewRequest("GET", url, new(bytes.Buffer))
	if err != nil {
		return err
	}

	//  Issuing the query
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Bad status code: %d", resp.StatusCode)
	}

	// Dumping the content of the response
	log.Debugf("Dumping the content of the response -> %s", outPath)
	r := -1
	buf := make([]byte, 4096)
	for err == nil && r != 0 {
		r, err = resp.Body.Read(buf)
		out.Write(buf[:r])
	}
	return nil
}

// Unzip helper function to unzip a file to a destination folder
// source code from : https://stackoverflow.com/questions/20357223/easy-way-to-unzip-file-with-golang
func Unzip(zipfile, dest string) (err error) {
	r, err := zip.OpenReader(zipfile)
	if err != nil {
		return err
	}
	defer r.Close()

	// Creating directory
	os.MkdirAll(dest, 0700)

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		path := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			f, err := os.OpenFile(
				path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer f.Close()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
