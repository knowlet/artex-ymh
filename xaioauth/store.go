package xaioauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func privateFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, ErrUnsafeStore
	}
	return info, nil
}

func (m *Manager) withLock(ctx context.Context, action func(*os.File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(m.path) == "" {
		return ErrUnsafeStore
	}
	dir, err := os.Lstat(filepath.Dir(m.path))
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && dir.Mode().Perm()&0077 != 0) {
		return ErrUnsafeStore
	}
	lockPath := m.path + ".lock"
	if _, err := privateFile(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	before, err := privateFile(lockPath)
	if err != nil {
		return err
	}
	opened, err := lock.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) {
		return ErrUnsafeStore
	}
	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := lockContext(lockCtx, lock); err != nil {
		return err
	}
	defer unlockFile(lock)
	if err := ctx.Err(); err != nil {
		return err
	}
	return action(lock)
}

func (m *Manager) load() (tokenState, error) {
	info, err := privateFile(m.path)
	if err != nil {
		return tokenState{}, err
	}
	f, err := os.Open(m.path)
	if err != nil {
		return tokenState{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return tokenState{}, err
	}
	if !os.SameFile(info, opened) {
		return tokenState{}, ErrUnsafeStore
	}
	body, err := io.ReadAll(io.LimitReader(f, maxAuthBody+1))
	if err != nil || len(body) > maxAuthBody {
		return tokenState{}, errors.New("could not read xAI credential store")
	}
	var state tokenState
	if err := json.Unmarshal(body, &state); err != nil || state.Version != 1 {
		return tokenState{}, errors.New("xAI credential store is invalid; sign in again")
	}
	if state.ReauthRequired {
		if state.AccessToken != "" || state.RefreshToken != "" {
			return tokenState{}, errors.New("xAI credential store is invalid; sign in again")
		}
		return state, nil
	}
	if !validSecret(state.AccessToken) || !validSecret(state.RefreshToken) || state.ExpiresAt.IsZero() {
		return tokenState{}, errors.New("xAI credential store is incomplete; sign in again")
	}
	return state, nil
}

// save writes a same-directory 0600 temporary file, fsyncs it, then atomically
// replaces the destination. The OS lock remains held over refresh and save.
func (m *Manager) save(ctx context.Context, state tokenState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := privateFile(m.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	body, err := json.Marshal(state)
	if err != nil {
		return errors.New("could not encode xAI credential store")
	}
	f, err := os.CreateTemp(filepath.Dir(m.path), ".xai-session-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := privateFile(m.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replaceFile(tmp, m.path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(m.path))
}
