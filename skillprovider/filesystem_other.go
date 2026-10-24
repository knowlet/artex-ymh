//go:build !linux

package skillprovider

import "fmt"

// Filesystem commands fail closed without a no-follow/no-replace implementation.
type safeDir struct{}

func (*safeDir) requirePrivate() error { return unsupportedFS() }

func unsupportedFS() error {
	return fmt.Errorf("provider filesystem commands require Linux no-follow/no-replace filesystem support")
}
func openDirectory(string) (*safeDir, error)                      { return nil, unsupportedFS() }
func (*safeDir) Close() error                                     { return nil }
func (*safeDir) child(string) (*safeDir, error)                   { return nil, unsupportedFS() }
func (*safeDir) mkdir(string) error                               { return unsupportedFS() }
func (*safeDir) sync() error                                      { return unsupportedFS() }
func (*safeDir) requireAbsent(string) error                       { return unsupportedFS() }
func (*safeDir) renameNoReplace(string, string) error             { return unsupportedFS() }
func (*safeDir) renameNoReplaceTo(string, *safeDir, string) error { return unsupportedFS() }
func (*safeDir) removeEmptyIfSame(string, *safeDir) error         { return unsupportedFS() }
func (*safeDir) readFile(string, int64) ([]byte, error)           { return nil, unsupportedFS() }
func (*safeDir) writeFile(string, []byte) error                   { return unsupportedFS() }
func (*safeDir) removeTree(string) error                          { return unsupportedFS() }
