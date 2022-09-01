package utils

import (
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/google/uuid"
)

const (
	// DefaultFileModeFile default permissions for output files
	DefaultFileModeFile = 0740
)

// CountFiles counts files in a directory
func CountFiles(directory string) (cnt int) {
	for wi := range fswalker.Walk(directory) {
		cnt += len(wi.Files)
	}
	return
}

// GzipFileBestSpeed compresses a file to gzip and deletes the original file
func GzipFileBestSpeed(path string) (last error) {
	var src, dst *os.File

	fname := fmt.Sprintf("%s.gz", path)
	partname := fmt.Sprintf("%s.part", fname)

	if src, last = os.Open(path); last != nil {
		return
	}
	defer src.Close()

	if dst, last = os.Create(partname); last != nil {
		return
	}
	defer dst.Close()

	// if valid level error returned is nil so no need to handle it
	w, _ := gzip.NewWriterLevel(dst, gzip.BestSpeed)
	defer w.Close()
	if _, err := io.Copy(w, src); err != nil {
		return err
	}

	// gzip writer
	w.Flush()
	w.Close()
	// original file
	src.Close()
	// part file
	dst.Close()

	if err := os.Remove(path); err != nil {
		last = fmt.Errorf("cannot remove original dumpfile: %w", err)
	}

	if err := os.Rename(partname, fname); err != nil {
		last = err
	}

	// rename the file to its final name
	return last
}

// HidsMkdirAll is a wrapper around os.MkdirAll with appropriate
// permissions
func HidsMkdirAll(dir string) error {
	return os.MkdirAll(dir, DefaultFileModeFile)
}

func HidsMkTmpDir() (dir string, err error) {
	// genererating random uuid to drop binary in
	randDir, err := uuid.NewRandom()
	if err != nil {
		err = fmt.Errorf("failed to create random directory: %w", err)
		return
	}

	// creating temporary directory
	dir = filepath.Join(os.TempDir(), randDir.String())
	err = os.MkdirAll(dir, 0700)

	return
}

// HidsCreateFile creates a file with the good permissions
func HidsCreateFile(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_RDWR, DefaultFileModeFile)
}

// HidsWriteData is a wrapper around ioutil.WriteFile to write a file
// with the good permissions
func HidsWriteData(dest string, data []byte) error {
	return ioutil.WriteFile(dest, data, DefaultFileModeFile)
}

// HidsWriteReader writes the content of a reader to a destination file. If
// compress is true .gz extension is added to destination file name.
func HidsWriteReader(dst string, content io.Reader, compress bool) (err error) {
	var out *os.File
	var w io.WriteCloser

	if compress && !strings.HasSuffix(dst, ".gz") {
		dst = fmt.Sprintf("%s.gz", dst)
	}

	if out, err = HidsCreateFile(dst); err != nil {
		return
	}
	defer out.Close()

	// default value for writer
	w = out
	if compress {
		if w, err = gzip.NewWriterLevel(out, gzip.BestSpeed); err != nil {
			return
		}
		defer w.Close()
	}

	if _, err = io.Copy(w, content); err != nil {
		return
	}

	return w.Close()
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

func RelativePath(path string) string {
	return filepath.Join(filepath.Dir(os.Args[0]), path)
}

func IsDirEmpty(dir string) (empty bool, err error) {
	var fd *os.File
	var entries []fs.DirEntry

	if fd, err = os.Open(dir); err != nil {
		return
	}

	defer fd.Close()

	if entries, err = fd.ReadDir(1); err != nil && err != io.EOF {
		return
	}

	return len(entries) == 0, nil
}
