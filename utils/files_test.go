package utils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/toast"
	"github.com/0xrawsec/whids/los"
)

func TestIsDirEmpty(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tmp := t.TempDir()
	ok, err := IsDirEmpty(tmp)
	tt.CheckErr(err)
	tt.Assert(ok)

	newFile := filepath.Join(tmp, "new_file")
	tt.CheckErr(os.WriteFile(newFile, []byte{}, 0777))
	ok, err = IsDirEmpty(tmp)
	tt.CheckErr(err)
	tt.Assert(!ok)

	// removing the file we've just created
	tt.CheckErr(os.Remove(newFile))

	newDir := filepath.Join(tmp, "new_dir")
	tt.CheckErr(os.Mkdir(newDir, 0777))
	ok, err = IsDirEmpty(tmp)
	tt.CheckErr(err)
	tt.Assert(!ok)
}

func createFiles(dir string, n int) {
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%d", i)), []byte{}, 0700); err != nil {
			panic(err)
		}
	}
}

func TestCountFiles(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tmp := t.TempDir()
	subTmp := filepath.Join(tmp, "subdir")
	tt.CheckErr(os.Mkdir(subTmp, 0777))

	createFiles(tmp, 100)
	tt.Assert(CountFiles(tmp) == 100)
	createFiles(subTmp, 200)
	tt.Assert(CountFiles(subTmp) == 200)
	tt.Assert(CountFiles(tmp) == 300)
}

func TestGzipFileBestSpeed(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tmp := t.TempDir()
	fp := filepath.Join(tmp, "togzip.txt")
	tt.CheckErr(os.WriteFile(fp, []byte{}, 0700))

	tt.Assert(fsutil.IsFile(fp))
	tt.CheckErr(GzipFileBestSpeed(fp))
	tt.Assert(!fsutil.IsFile(fp))
	// file with .gz must have been created
	tt.Assert(fsutil.IsFile(fmt.Sprintf("%s.gz", fp)))
}

func TestHidsMkdirAll(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "directory")
	tt.CheckErr(HidsMkdirAll(dir))

	fi, err := os.Stat(dir)
	tt.CheckErr(err)
	if los.OS != "windows" {
		tt.Assert(fi.Mode().Perm() == DefaultFilePerm)
	}
}

func TestHidsMkTmpDir(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tmp, err := HidsMkTmpDir()
	tt.CheckErr(err)

	tt.Assert(strings.HasPrefix(tmp, os.TempDir()))

	fi, err := os.Stat(tmp)
	tt.Assert(fi.IsDir())
	tt.CheckErr(err)
	if los.OS != "windows" {
		tt.Assert(fi.Mode().Perm() == permUserFullAccess)
	}
}

func TestHidsCreateFile(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	fp := filepath.Join(t.TempDir(), "testfile")
	fd, err := HidsCreateFile(fp)
	tt.CheckErr(err)
	fd.WriteString("testing")
	tt.CheckErr(fd.Close())

	fi, err := os.Stat(fp)
	tt.CheckErr(err)
	tt.Assert(fi.Mode().IsRegular())
	if los.OS != "windows" {
		tt.Assert(fi.Mode().Perm() == DefaultFilePerm)
	}
}

func TestHidsWriteData(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	fp := filepath.Join(t.TempDir(), "testfile")
	tt.CheckErr(HidsWriteData(fp, []byte("testing")))

	fi, err := os.Stat(fp)
	tt.CheckErr(err)
	tt.Assert(fi.Mode().IsRegular())
	if los.OS != "windows" {
		tt.Assert(fi.Mode().Perm() == DefaultFilePerm)
	}
}

func TestHidsWriteReader(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	fp := filepath.Join(t.TempDir(), "testfile")
	tt.CheckErr(HidsWriteReader(fp, bytes.NewBufferString("testing"), false))

	fi, err := os.Stat(fp)
	tt.CheckErr(err)
	tt.Assert(fi.Mode().IsRegular())
	if los.OS != "windows" {
		tt.Assert(fi.Mode().Perm() == DefaultFilePerm)
	}

	read, err := ReadFileAsString(fp)
	tt.CheckErr(err)
	tt.Assert(read == "testing")

	fpgz := fmt.Sprintf("%s.gz", fp)
	tt.CheckErr(HidsWriteReader(fp, bytes.NewBufferString("testing"), true))
	fi, err = os.Stat(fpgz)
	tt.CheckErr(err)
	tt.Assert(fi.Mode().IsRegular())
	if los.OS != "windows" {
		tt.Assert(fi.Mode().Perm() == DefaultFilePerm)
	}

	read, err = ReadGzipFileAsString(fpgz)
	tt.CheckErr(err)
	tt.Assert(read == "testing")
}

func TestStDirs(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tmp := t.TempDir()
	ps := string(os.PathSeparator)

	tt.Assert(!strings.HasSuffix(tmp, ps))

	testDirs := []string{
		tmp,
		"/this/is/sometest",
		"/this/is/another/test////",
	}

	for _, d := range StdDirs(testDirs...) {
		// check that path ends with path sep
		tt.Assert(strings.HasSuffix(d, ps))
		// check that path ends does not end with several path sep
		tt.Assert(!strings.HasSuffix(d, ps+ps))
	}
}

func TestRelativePath(t *testing.T) {
	t.Parallel()

	tt := toast.FromT(t)

	fp := BinRelativePath("testfile")
	t.Log(fp)
	tt.Assert(strings.HasPrefix(fp, filepath.Dir(os.Args[0])))
}

func TestIsPipePath(t *testing.T) {
	t.Parallel()
	tt := toast.FromT(t)

	tt.Assert(IsPipePath(`\\.\WindowsPipe`))
	tt.Assert(!IsPipePath(`WindowsPipe`))
}
