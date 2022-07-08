package hids

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/whids/los"
	"github.com/0xrawsec/whids/utils"
)

type FileInfo struct {
	Dir     string            `json:"dir"`
	Name    string            `json:"name"`
	Size    int64             `json:"size"`
	ModTime time.Time         `json:"modtime"`
	Type    string            `json:"type"`
	Hashes  map[string]string `json:"hashes,omitempty"`
	Err     error             `json:"error"`
}

func (fi *FileInfo) Path() string {
	return filepath.Join(fi.Dir, fi.Name)
}

func (fi *FileInfo) Hash() error {
	var buffer [4 * utils.Mega]byte

	file, err := os.Open(fi.Path())
	if err != nil {
		return err
	}
	defer file.Close()

	fi.Hashes = make(map[string]string)

	md5 := md5.New()
	sha1 := sha1.New()
	sha256 := sha256.New()
	sha512 := sha512.New()

	for read, err := file.Read(buffer[:]); err != io.EOF && read != 0; read, err = file.Read(buffer[:]) {
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		md5.Write(buffer[:read])
		sha1.Write(buffer[:read])
		sha256.Write(buffer[:read])
		sha512.Write(buffer[:read])
	}

	fi.Hashes["md5"] = hex.EncodeToString(md5.Sum(nil))
	fi.Hashes["sha1"] = hex.EncodeToString(sha1.Sum(nil))
	fi.Hashes["sha256"] = hex.EncodeToString(sha256.Sum(nil))
	fi.Hashes["sha512"] = hex.EncodeToString(sha512.Sum(nil))

	return nil
}

func (fi *FileInfo) FromFSFileInfo(fsfi fs.FileInfo) {
	fi.Name = fsfi.Name()
	fi.Size = fsfi.Size()
	fi.ModTime = fsfi.ModTime()
	switch {
	case fsfi.IsDir():
		fi.Type = "dir"
	case fsfi.Mode().IsRegular():
		fi.Type = "file"
	case fsfi.Mode()&os.ModeSymlink == os.ModeSymlink:
		fi.Type = "link"
	}
}

type WalkItem struct {
	Dirs  []FileInfo `json:"dirs"`
	Files []FileInfo `json:"files"`
	Err   string     `json:"err"`
}

func (wi *WalkItem) FromWalkerWalkItem(o fswalker.WalkItem) {
	wi.Dirs = make([]FileInfo, len(o.Dirs))
	for i, fi := range o.Dirs {
		wi.Dirs[i].Dir = o.Dirpath
		wi.Dirs[i].FromFSFileInfo(fi)
	}

	wi.Files = make([]FileInfo, len(o.Files))
	for i, fi := range o.Files {
		wi.Files[i].Dir = o.Dirpath
		wi.Files[i].FromFSFileInfo(fi)
	}

	if o.Err != nil {
		wi.Err = o.Err.Error()
	}
}
  
func cmdHash(path string) (nfi FileInfo, err error) {
	var fi fs.FileInfo

	if fi, err = os.Stat(path); err != nil {
		return
	}

	if !fi.Mode().IsRegular() {
		err = fmt.Errorf("no such file: %s", path)
		return
	}

	nfi.Dir = filepath.Dir(path)
	nfi.FromFSFileInfo(fi)
	err = nfi.Hash()
	return
}

func cmdDir(path string) (sfi []FileInfo, err error) {
	var ofi []fs.FileInfo

	if ofi, err = ioutil.ReadDir(path); err != nil {
		return
	}

	sfi = make([]FileInfo, len(ofi))
	for i, fi := range ofi {
		sfi[i].Dir = path
		sfi[i].FromFSFileInfo(fi)
	}

	return
}

func cmdWalk(path string) []WalkItem {
	out := make([]WalkItem, 0)

	for wi := range fswalker.Walk(path) {
		new := WalkItem{}
		new.FromWalkerWalkItem(wi)
		out = append(out, new)
	}

	return out
}

func cmdFind(path string, pattern string, hash bool) (out []FileInfo, err error) {
	var pr *regexp.Regexp

	out = make([]FileInfo, 0)

	if pr, err = regexp.Compile(pattern); err != nil {
		return
	}

	for wi := range fswalker.Walk(path) {
		for _, fi := range wi.Files {
			path := filepath.Join(wi.Dirpath, fi.Name())
			if pr.MatchString(path) {
				nfi := FileInfo{Dir: wi.Dirpath}
				nfi.FromFSFileInfo(fi)
				// we need to hash file
				if hash {
					nfi.Err = nfi.Hash()
				}
				out = append(out, nfi)
			}

		}
	}

	return
}

func cmdStat(path string) (nfi FileInfo, err error) {
	var fi fs.FileInfo

	if fi, err = os.Stat(path); err != nil {
		return
	}

	nfi.Dir = filepath.Dir(los.TrimPathSep(path))
	nfi.FromFSFileInfo(fi)
	return
}
