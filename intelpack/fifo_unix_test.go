//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package intelpack

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadRegularRejectsFIFOBeforeOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readRegular(path, 1024); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO was accepted as a regular file")
		}
	case <-time.After(time.Second):
		// Unblock a regressed reader so a failed assertion never hangs the suite.
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			defer syscall.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("regular-file validation blocked opening a FIFO")
	}
}
