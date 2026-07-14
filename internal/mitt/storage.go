package mitt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type saveResult struct {
	path  string
	bytes uint64
}

// save creates the destination exclusively. Collision selection and creation
// are one operation, so concurrent transfers cannot truncate each other.
func save(dir, filename string, reader io.Reader) (result saveResult, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return saveResult{}, err
	}
	base, extension := splitExtension(filename)
	for counter := 0; counter < 10000; counter++ {
		candidate := filename
		if counter > 0 {
			candidate = fmt.Sprintf("%s_%d%s", base, counter, extension)
		}
		path := filepath.Join(dir, candidate)
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(openErr, os.ErrExist) {
			continue
		}
		if openErr != nil {
			return saveResult{}, openErr
		}
		keep := false
		defer func() {
			closeErr := file.Close()
			if err == nil && closeErr != nil {
				err = closeErr
			}
			if !keep || err != nil {
				_ = os.Remove(path)
			}
		}()
		written, copyErr := io.Copy(file, reader)
		if copyErr != nil {
			return saveResult{}, copyErr
		}
		if syncErr := file.Sync(); syncErr != nil {
			return saveResult{}, syncErr
		}
		keep = true
		return saveResult{path: path, bytes: uint64(written)}, nil
	}
	return saveResult{}, errors.New("mitt: too many filename collisions")
}

func splitExtension(filename string) (string, string) {
	index := strings.LastIndexByte(filename, '.')
	if index < 0 {
		return filename, ""
	}
	return filename[:index], filename[index:]
}
