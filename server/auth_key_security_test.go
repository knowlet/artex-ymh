package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistedKeySurvivesContainerRecreation(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	secrets := filepath.Join(base, "secrets")
	os.Mkdir(data, 0700)
	os.Mkdir(secrets, 0700)
	t.Setenv("ARTEX_KEY_DIR", secrets)
	key, err := loadOrCreateJWTKey(filepath.Join(base, "container-one"), data)
	if err != nil {
		t.Fatal(err)
	}
	next, err := loadOrCreateJWTKey(filepath.Join(base, "container-two"), data)
	if err != nil || !bytes.Equal(key, next) {
		t.Fatalf("key changed: %v", err)
	}
}
func TestInvalidKeyNeverReplaced(t *testing.T) {
	t.Setenv("ARTEX_KEY_DIR", "")
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "legacy"}[legacy], func(t *testing.T) {
			base := t.TempDir()
			keyDir := filepath.Join(base, "private")
			data := filepath.Join(base, "data")
			os.Mkdir(keyDir, 0700)
			os.Mkdir(data, 0700)
			path := filepath.Join(keyDir, jwtKeyFilename)
			if legacy {
				path = filepath.Join(data, jwtKeyFilename)
			}
			os.WriteFile(path, []byte("broken"), 0600)
			if _, err := loadOrCreateJWTKey(keyDir, data); err == nil {
				t.Fatal("invalid key accepted or replaced")
			}
			got, _ := os.ReadFile(path)
			if string(got) != "broken" {
				t.Fatal("invalid key was modified")
			}
		})
	}
}
func TestKeyOverrideMigratesPriorContainerKey(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	old := filepath.Join(base, "old")
	os.Mkdir(data, 0700)
	os.Mkdir(old, 0700)
	key := bytes.Repeat([]byte("k"), 32)
	os.WriteFile(filepath.Join(old, jwtKeyFilename), key, 0600)
	os.Mkdir(filepath.Join(base, "secrets"), 0700)
	t.Setenv("ARTEX_KEY_DIR", filepath.Join(base, "secrets"))
	got, err := loadOrCreateJWTKey(old, data)
	if err != nil || !bytes.Equal(key, got) {
		t.Fatalf("legacy migration: %v", err)
	}
}

func TestKeyDirectorySymlinkIntoWorkspaceRejected(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "secrets")
	if err := os.Symlink(data, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_KEY_DIR", alias)
	if _, err := loadOrCreateJWTKey(base, data); err == nil {
		t.Fatal("key directory resolves into browsable workspace")
	}
	if _, err := os.Stat(filepath.Join(data, jwtKeyFilename)); !os.IsNotExist(err) {
		t.Fatal("created key in workspace")
	}
}
func TestMissingKeyOverrideFailsWithoutGenerating(t *testing.T) {
	base := t.TempDir()
	t.Setenv("ARTEX_KEY_DIR", filepath.Join(base, "missing"))
	if _, err := loadOrCreateJWTKey(base, filepath.Join(base, "data")); err == nil {
		t.Fatal("missing persistent mount accepted")
	}
}
