//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package xaioauth

import (
	"context"
	"errors"
	"os"
)

func lockContext(context.Context, *os.File) error {
	return errors.New("xAI OAuth secure file locking is unsupported on this platform")
}
func unlockFile(*os.File) {}
func replaceFile(string, string) error {
	return errors.New("xAI OAuth secure storage is unsupported on this platform")
}
func syncDirectory(string) error {
	return errors.New("xAI OAuth secure storage is unsupported on this platform")
}
