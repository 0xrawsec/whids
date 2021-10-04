package api

import (
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/whids/utils"
)

var (
	UploadShrinkerBufferSize = int64(3 * utils.Mega)
)

type UploadShrinker struct {
	name  string
	f     *os.File
	fu    *FileUpload
	buff  []byte
	chunk int
	total int
	size  int64
	err   error
}

// NewUploadShrinker creates a new object to shrink files to be uploaded to the manager
func NewUploadShrinker(path, guid, ehash string) (it *UploadShrinker, err error) {
	var fd *os.File
	var stat fs.FileInfo

	if fd, err = os.Open(path); err != nil {
		return
	}

	if stat, err = fd.Stat(); err != nil {
		return
	}

	size := stat.Size()
	total := int(size/UploadShrinkerBufferSize) + 1

	it = &UploadShrinker{
		name: filepath.Base(path),
		f:    fd,
		fu: &FileUpload{
			Name:      filepath.Base(path),
			GUID:      guid,
			EventHash: ehash,
			Total:     total,
		},
		buff:  make([]byte, UploadShrinkerBufferSize),
		chunk: 1,
		total: total,
		size:  size,
	}

	return
}

// Size returns the size of the file to be shrinked
func (i *UploadShrinker) Size() int64 {
	return i.size
}

// Next returns the next FileUpload or nil if finished
func (i *UploadShrinker) Next() *FileUpload {
	var n int
	var err error

	if i.Done() {
		return nil
	}

	if n, err = i.f.Read(i.buff); err != nil && err != io.EOF {
		i.err = err
		return nil
	}

	i.fu.Chunk = i.chunk
	i.fu.Content = i.buff[:n]
	i.chunk++

	return i.fu
}

// Done returns true when all files have been sent
func (i *UploadShrinker) Done() bool {
	return i.chunk > i.total
}

// Err report any error encountered while iterating over Next
func (i *UploadShrinker) Err() error {
	return i.err
}

// Close closes the underlying file
func (i *UploadShrinker) Close() error {
	return i.f.Close()
}

//////////////////////// FileUpload

// FileUpload structure used to forward files from the client to the manager
type FileUpload struct {
	Name      string `json:"filename"`
	GUID      string `json:"guid"`
	EventHash string `json:"event-hash"`
	Content   []byte `json:"content"`
	Chunk     int    `json:"chunk"` // identify the chunk number
	Total     int    `json:"total"` // total number of chunks needed to reconstruct the file
}

// Validate that the file upload follows the expected format
func (f *FileUpload) Validate() error {
	if !filenameRe.MatchString(f.Name) {
		return fmt.Errorf("bad filename")
	}
	if !guidRe.MatchString(f.GUID) {
		return fmt.Errorf("bad guid")
	}
	if !eventHashRe.MatchString(f.EventHash) {
		return fmt.Errorf("bad event hash")
	}
	return nil
}

// Implode returns the full path of the FileUpload
func (f *FileUpload) Implode() string {
	return filepath.Join(f.GUID, f.EventHash, f.Name)
}

// Dump dumps the FileUpload into the given root directory dir
func (f *FileUpload) Dump(root string) (err error) {
	// Return error if cannot dump file
	if err = f.Validate(); err != nil {
		return
	}

	dirpath := filepath.Join(root, f.GUID, f.EventHash)

	// Create directory if doesn't exist
	if !fsutil.IsDir(dirpath) {
		if err = os.MkdirAll(dirpath, utils.DefaultPerms); err != nil {
			return
		}
	}

	return f.write(root)
}

func (f *FileUpload) write(root string) (err error) {
	var out *os.File
	var content []byte

	path := filepath.Join(root, f.Implode())
	if f.Chunk < f.Total {
		return utils.HidsWriteData(fmt.Sprintf("%s.%d", path, f.Chunk), f.Content)
	} else {
		// special case where we have only one chunk
		if f.Total == 1 {
			return utils.HidsWriteData(path, f.Content)
		}

		// we reassemble chunks
		if out, err = utils.HidsCreateFile(path); err != nil {
			return
		}

		for i := 1; i < f.Total; i++ {
			chunkPath := fmt.Sprintf("%s.%d", path, i)
			if content, err = ioutil.ReadFile(chunkPath); err != nil {
				return
			}

			if _, err = out.Write(content); err != nil {
				return
			}

			os.Remove(chunkPath)
		}

		if _, err = out.Write(f.Content); err != nil {
			return
		}

		return out.Close()
	}
}
