//go:build linux

package skillprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
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
	anchor := "."
	if filepath.IsAbs(name) {
		anchor = "/"
	}
	// Relative paths start at the kernel's current directory, not Getwd/PWD.
	// Expanding a logical cwd through filepath.Abs would introduce symlink
	// components which the caller never supplied, then incorrectly reject them.
	fd, err := unix.Open(anchor, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	d := &safeDir{fd: fd}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." {
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

func (d *safeDir) lockStage() error {
	if err := unix.Flock(d.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("staging directory is active or cannot be locked: %w", err)
	}
	return nil
}

func (d *safeDir) writeStageRecord(name string, files []stagedFile) error {
	var st unix.Stat_t
	if err := unix.Fstat(d.fd, &st); err != nil {
		return err
	}
	data, err := json.Marshal(stageRecord{1, name, uint64(st.Dev), st.Ino, files})
	if err != nil {
		return err
	}
	if len(data) > maxStageRecordBytes {
		return fmt.Errorf("staging inventory exceeds byte limit")
	}
	if err := d.writeFile(stageRecordFilename, data); err != nil {
		return err
	}
	return d.sync()
}

func (d *safeDir) unlinkStageRecord() error {
	err := unix.Unlinkat(d.fd, stageRecordFilename, 0)
	if err == unix.ENOENT {
		return nil
	}
	return err
}

type recoveryNode struct {
	parent *safeDir
	name   string
	stat   unix.Stat_t
	dir    *safeDir
}

func recoverStage(ctx context.Context, parentPath, name string) error {
	parent, err := openDirectory(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	outer, err := parent.child(name)
	if err != nil {
		return err
	}
	defer outer.Close()
	if err := outer.requirePrivate(); err != nil {
		return err
	}
	if err := outer.lockStage(); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(outer.fd, &st); err != nil {
		return err
	}
	var markerStat unix.Stat_t
	if err := unix.Fstatat(outer.fd, stageRecordFilename, &markerStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := privateRecoveryFile(outer, stageRecordFilename, &markerStat); err != nil {
		return fmt.Errorf("unrecognized staging inventory: %w", err)
	}
	data, err := outer.readFile(stageRecordFilename, maxStageRecordBytes)
	if err != nil {
		return err
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var record stageRecord
	if err := dec.Decode(&record); err != nil {
		return err
	}
	if record.Version != 1 || record.Name != name || record.Device != uint64(st.Dev) || record.Inode != st.Ino || len(record.Files) == 0 || len(record.Files) > MaxSkills*3+2 {
		return fmt.Errorf("staging inventory identity mismatch")
	}
	expected := map[string]stagedFile{}
	dirs := map[string]bool{"library": true}
	var total int64
	for _, file := range record.Files {
		if !validStagedFile(file) {
			return fmt.Errorf("invalid staging inventory path, size or hash")
		}
		if _, exists := expected[file.Path]; exists {
			return fmt.Errorf("duplicate staging inventory path")
		}
		expected[file.Path] = file
		total += file.Bytes
		for dir := path.Dir(file.Path); dir != "."; dir = path.Dir(dir) {
			dirs[dir] = true
		}
	}
	if total > MaxTotalBytes {
		return fmt.Errorf("staging inventory exceeds output limit")
	}
	// Pin every directory and validate the complete tree before deleting any
	// content. Unknown additions and edited/partial files require manual review.
	var nodes []recoveryNode
	defer func() {
		for _, node := range nodes {
			if node.dir != nil {
				node.dir.Close()
			}
		}
	}()
	var walk func(*safeDir, string) error
	walk = func(dir *safeDir, prefix string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// A separately opened descriptor gives each scan its own directory offset.
		fd, err := unix.Openat(dir.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), ".")
		entries, err := f.ReadDir(MaxSkills*6 + 10)
		f.Close()
		if err != nil && err != io.EOF {
			return err
		}
		if len(entries) >= MaxSkills*6+10 {
			return fmt.Errorf("staging entry count exceeds limit")
		}
		for _, entry := range entries {
			rel := path.Join(prefix, entry.Name())
			var named unix.Stat_t
			if err := unix.Fstatat(dir.fd, entry.Name(), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if prefix == "" && entry.Name() == stageRecordFilename {
				continue
			}
			if named.Mode&unix.S_IFMT == unix.S_IFDIR && dirs[rel] {
				child, err := dir.child(entry.Name())
				if err != nil {
					return err
				}
				nodes = append(nodes, recoveryNode{dir, entry.Name(), named, child})
				if err := child.requirePrivate(); err != nil {
					return err
				}
				var pinned unix.Stat_t
				if err := unix.Fstat(child.fd, &pinned); err != nil {
					return err
				}
				if pinned.Dev != named.Dev || pinned.Ino != named.Ino {
					return fmt.Errorf("staging directory changed during inspection; preserved")
				}
				if err := walk(child, rel); err != nil {
					return err
				}
				continue
			}
			file, ok := expected[rel]
			if !ok {
				return fmt.Errorf("unrecognized staging content %q; preserved", rel)
			}
			if err := privateRecoveryFile(dir, entry.Name(), &named); err != nil {
				return err
			}
			content, err := dir.readFile(entry.Name(), file.Bytes)
			if err != nil || int64(len(content)) != file.Bytes || hashBytes(content) != file.SHA256 {
				return fmt.Errorf("staging content %q changed or incomplete; preserved", rel)
			}
			nodes = append(nodes, recoveryNode{dir, entry.Name(), named, nil})
		}
		return nil
	}
	if err := walk(outer, ""); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sameRecoveryStage(parent, name, &st); err != nil {
		return err
	}
	for i := len(nodes) - 1; i >= 0; i-- {
		node := nodes[i]
		if node.dir != nil {
			if err := node.parent.removeEmptyIfSame(node.name, node.dir); err != nil {
				return err
			}
		} else {
			var now unix.Stat_t
			if err := unix.Fstatat(node.parent.fd, node.name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if now.Dev != node.stat.Dev || now.Ino != node.stat.Ino || now.Size != node.stat.Size || now.Mtim != node.stat.Mtim || now.Mode != node.stat.Mode || now.Nlink != node.stat.Nlink || now.Uid != node.stat.Uid {
				return fmt.Errorf("staging content changed during recovery; preserved")
			}
			if err := unix.Unlinkat(node.parent.fd, node.name, 0); err != nil {
				return err
			}
		}
	}
	var currentMarker unix.Stat_t
	if err := unix.Fstatat(outer.fd, stageRecordFilename, &currentMarker, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if currentMarker.Dev != markerStat.Dev || currentMarker.Ino != markerStat.Ino || currentMarker.Mtim != markerStat.Mtim || currentMarker.Mode != markerStat.Mode || currentMarker.Size != markerStat.Size {
		return fmt.Errorf("staging inventory changed during recovery; preserved")
	}
	if err := outer.unlinkStageRecord(); err != nil {
		return err
	}
	if err := sameRecoveryStage(parent, name, &st); err != nil {
		return err
	}
	if err := parent.removeEmptyIfSame(name, outer); err != nil {
		return err
	}
	// Removing the selected stage is the commit point. A later sync failure
	// cannot truthfully report that cleanup was unapplied.
	_ = parent.sync()
	return nil
}

func sameRecoveryStage(parent *safeDir, name string, expected *unix.Stat_t) error {
	var current unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if current.Dev != expected.Dev || current.Ino != expected.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("selected staging pathname was replaced; preserved")
	}
	return nil
}

func privateRecoveryFile(dir *safeDir, name string, stat *unix.Stat_t) error {
	var st unix.Stat_t
	if stat == nil {
		if err := unix.Fstatat(dir.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
	} else {
		st = *stat
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o777 != 0o600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return fmt.Errorf("staging file %q must be private, owned and unlinked elsewhere", name)
	}
	return nil
}
