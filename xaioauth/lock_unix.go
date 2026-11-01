//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package xaioauth

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

func lockContext(ctx context.Context, f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		if err := sleepContext(ctx, 20*time.Millisecond); err != nil {
			return err
		}
	}
}
func unlockFile(f *os.File)             { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
func replaceFile(old, new string) error { return os.Rename(old, new) }
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
