package utils

import (
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
)

const (
	// DefaultPerms default permissions for output files
	DefaultPerms = 0740
)

// CountFiles counts files in a directory
func CountFiles(directory string) (cnt int) {
	for wi := range fswalker.Walk(directory) {
		cnt += len(wi.Files)
	}
	return
}

// GzipFileBestSpeed compresses a file to gzip and deletes the original file
func GzipFileBestSpeed(path string) (err error) {
	fname := fmt.Sprintf("%s.gz", path)
	partname := fmt.Sprintf("%s.part", fname)

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	of, err := os.Create(partname)
	if err != nil {
		return
	}
	defer of.Close()

	// if valid level error returned is nil so no need to handle it
	w, _ := gzip.NewWriterLevel(of, gzip.BestSpeed)
	defer w.Close()
	if _, err := io.Copy(w, f); err != nil {
		return err
	}

	// gzip writer
	w.Flush()
	w.Close()
	// original file
	f.Close()
	// part file
	of.Close()
	log.Infof("Removing original dumpfile: %s", path)
	if err := os.Remove(path); err != nil {
		log.Errorf("Cannot remove original dumpfile: %s", err)
	}
	// rename the file to its final name
	return os.Rename(partname, fname)
}

// HidsCreateFile creates a file with the good permissions
func HidsCreateFile(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_CREATE|os.O_RDWR, DefaultPerms)
}

// HidsWriteFile is a wrapper around ioutil.WriteFile to write a file
// with the good permissions
func HidsWriteFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, DefaultPerms)
}

// IsPipePath checks whether the argument path is a pipe
func IsPipePath(path string) bool {
	return strings.HasPrefix(path, `\\.\`)
}

// ReadFileString reads bytes from a file
func ReadFileString(path string) (string, error) {
	b, err := ioutil.ReadFile(path)
	return string(b), err
}

// StdDir makes a directory ending with os separator
func StdDir(dir string) string {
	sep := string(os.PathSeparator)
	return fmt.Sprintf("%s%s", strings.TrimSuffix(dir, sep), sep)
}

// StdDirs makes a directories are ending with os separator
func StdDirs(directories ...string) (o []string) {
	o = make([]string, len(directories))
	for i, d := range directories {
		o[i] = StdDir(d)
	}
	return
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
