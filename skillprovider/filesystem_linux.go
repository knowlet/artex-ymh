//go:build linux

package skillprovider

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// safeDir pins a directory descriptor. Path components are opened with
// O_NOFOLLOW; publication also pins the source parent of the renamed entry.
// This does not isolate files from other processes with the same UID: such
// processes can still mutate files they own inside any opened directory.
type safeDir struct{ fd int }

func openDirectory(name string) (*safeDir, error) {
	if name == "" || len(name) > 4096 || strings.ContainsAny(name, "\\\x00") {
		return nil, fmt.Errorf("invalid directory path")
	}
	for _, p := range strings.Split(name, "/") {
		if p == ".." {
			return nil, fmt.Errorf("directory traversal is forbidden")
		}
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	d := &safeDir{fd: fd}
	for _, p := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if p == "" {
			continue
		}
		next, err := d.child(p)
		d.Close()
		if err != nil {
			return nil, err
		}
		d = next
	}
	return d, nil
}

func (d *safeDir) Close() error { return unix.Close(d.fd) }
func (d *safeDir) child(name string) (*safeDir, error) {
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open directory without symlinks", Path: name, Err: err}
	}
	return &safeDir{fd: fd}, nil
}
func (d *safeDir) mkdir(name string) error { return unix.Mkdirat(d.fd, name, 0700) }
func (d *safeDir) sync() error             { return unix.Fsync(d.fd) }
func (d *safeDir) requirePrivate() error {
	var st unix.Stat_t
	if err := unix.Fstat(d.fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700 {
		return fmt.Errorf("staging directory must be owned by the current user with mode 0700")
	}
	return nil
}
func (d *safeDir) requireAbsent(name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("destination already exists: %w", os.ErrExist)
}
func (d *safeDir) renameNoReplace(old, new string) error {
	return d.renameNoReplaceTo(old, d, new)
}
func (d *safeDir) renameNoReplaceTo(old string, target *safeDir, new string) error {
	return unix.Renameat2(d.fd, old, target.fd, new, unix.RENAME_NOREPLACE)
}

// removeEmptyIfSame never recursively opens a pathname which may have been
// replaced. AT_REMOVEDIR additionally refuses nonempty replacement directories.
func (d *safeDir) removeEmptyIfSame(name string, expected *safeDir) error {
	var pinned, named unix.Stat_t
	if err := unix.Fstat(expected.fd, &pinned); err != nil {
		return err
	}
	if err := unix.Fstatat(d.fd, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	if named.Dev != pinned.Dev || named.Ino != pinned.Ino || named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil
	}
	return unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR)
}

func (d *safeDir) readFile(rel string, limit int64) ([]byte, error) {
	if !validSourcePath(rel) || limit < 0 {
		return nil, fmt.Errorf("invalid relative file path")
	}
	parts := strings.Split(rel, "/")
	current := d
	for _, part := range parts[:len(parts)-1] {
		next, err := current.child(part)
		if current != d {
			current.Close()
		}
		if err != nil {
			return nil, err
		}
		current = next
	}
	if current != d {
		defer current.Close()
	}
	fd, err := unix.Openat(current.fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open file without symlinks", Path: rel, Err: err}
	}
	f := os.NewFile(uintptr(fd), rel)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("source must be a regular file within byte limit: %s", rel)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("source exceeds byte limit: %s", rel)
	}
	return b, nil
}

func (d *safeDir) writeFile(name string, b []byte) error {
	fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (d *safeDir) removeTree(name string) error {
	dir, err := d.child(name)
	if err != nil {
		if err := unix.Unlinkat(d.fd, name, 0); err != unix.ENOENT {
			return err
		}
		return nil
	}
	defer dir.Close()
	dup, err := unix.Dup(dir.fd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), name)
	entries, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if err := dir.removeTree(entry.Name()); err != nil {
				return err
			}
		} else if err := unix.Unlinkat(dir.fd, entry.Name(), 0); err != nil {
			return err
		}
	}
	return unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR)
}
