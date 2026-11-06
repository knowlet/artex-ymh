package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func deploymentFixture(t *testing.T, script string, commands ...string) (string, string, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", script))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, script), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range commands {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s unavailable", name)
		}
		if err := os.Symlink(path, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir, bin, bash
}

func deploymentRun(t *testing.T, dir, bin, bash, script, input string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, append([]string{filepath.Join(dir, script)}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+bin, "ARTEX_PG_DSN=", "PGPASSWORD=", "ARTEX_TEST_SQL_CAPTURE="+filepath.Join(dir, "sql"), "ARTEX_TEST_PASSWORD_CAPTURE="+filepath.Join(dir, "password"))
	cmd.Stdin = strings.NewReader(input)
	return cmd.CombinedOutput()
}

func TestInstallerMissingDockerDoesNotFetchOrExecute(t *testing.T) {
	dir, bin, bash := deploymentFixture(t, "install.sh", "dirname")
	marker := filepath.Join(dir, "remote-code-ran")
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\n: > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	out, err := deploymentRun(t, dir, bin, bash, "install.sh", "1\n")
	if err == nil || !strings.Contains(string(out), "https://docs.docker.com/engine/install/") {
		t.Fatalf("missing Docker did not fail with manual installation instructions: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("installer fetched remote code")
	}
}

func TestInstallerCreatesPrivateConfigOverExistingPublicFile(t *testing.T) {
	dir, bin, bash := deploymentFixture(t, "install.sh", "dirname", "mktemp", "cat", "chmod", "mv")
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := deploymentRun(t, dir, bin, bash, "install.sh", "2\n1\ndb\n5432\nfixture\nsynthetic-db-password\nfixture\ndisable\n")
	if err == nil {
		t.Fatal("fixture deliberately has no Go compiler")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("config permissions: %v %v", st, err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "synthetic-db-password") {
		t.Fatal("installer did not write fixture config")
	}
}

func TestInstallerCreatesPrivateDotEnv(t *testing.T) {
	dir, bin, bash := deploymentFixture(t, "install.sh", "dirname", "cp", "chmod", "head", "base64", "tr", "sed", "rm")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("POSTGRES_PASSWORD=\nANTHROPIC_API_KEY=\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := deploymentRun(t, dir, bin, bash, "install.sh", "1\nsynthetic-db-password\nsynthetic-api-key\n"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, ".env"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("env permissions: %v %v", st, err)
	}
}

func TestInstallerTightensExistingDotEnv(t *testing.T) {
	dir, bin, bash := deploymentFixture(t, "install.sh", "dirname", "chmod")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("POSTGRES_PASSWORD=synthetic-secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := deploymentRun(t, dir, bin, bash, "install.sh", "1\n"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("existing env permissions: %v %v", st, err)
	}
}

func TestResetReadsDotEnvAsLiteralAllowlistedData(t *testing.T) {
	dir, bin, bash := deploymentFixture(t, "reset-password.sh", "cat", "wc")
	docker := "#!/bin/sh\nprintf '%s' \"$PGPASSWORD\" > \"$ARTEX_TEST_PASSWORD_CAPTURE\"\ncat > \"$ARTEX_TEST_SQL_CAPTURE\"\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(docker), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "evaluated")
	password := "literal $(touch " + marker + ") # not code"
	env := "POSTGRES_USER='fixture user'\nPOSTGRES_DB=fixture\nPOSTGRES_PASSWORD='" + password + "'\nSQL=attacker-replacement\nPATH=/missing\ntouch " + marker + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := deploymentRun(t, dir, bin, bash, "reset-password.sh", "", "-m", "docker", "--exec", "docker", "-p", "synthetic-new-password", "-y"); err != nil {
		t.Fatalf("reset: %v: %s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("dotenv content executed as shell")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "password"))
	if string(got) != password {
		t.Fatal("literal quoted password changed")
	}
	sql, _ := os.ReadFile(filepath.Join(dir, "sql"))
	if strings.Contains(string(sql), "attacker-replacement") || !strings.Contains(string(sql), "BEGIN;") || !strings.Contains(string(sql), "auth.key_version") {
		t.Fatal("dotenv overrode reset SQL")
	}
}

func TestResetRejectsDotEnvExpansionWithoutExecutingIt(t *testing.T) {
	dir, bin, bash := deploymentFixture(t, "reset-password.sh", "cat", "wc")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "evaluated")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("POSTGRES_PASSWORD=$(touch "+marker+")\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := deploymentRun(t, dir, bin, bash, "reset-password.sh", "", "-m", "docker", "--exec", "docker", "-p", "synthetic-new-password", "-y"); err == nil {
		t.Fatal("unsupported dotenv expansion accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("dotenv expansion executed")
	}
}

func TestResetDoesNotLogDSNPassword(t *testing.T) {
	dir, bin, bash := deploymentFixture(t, "reset-password.sh", "cat")
	if err := os.WriteFile(filepath.Join(bin, "psql"), []byte("#!/bin/sh\ncat >/dev/null\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, dsn := range []string{"postgres://fixture:synthetic-secret@localhost/fixture", "host=localhost password='synthetic-secret' dbname=fixture", "postgres://u:synthetic-secret%zz@localhost/fixture"} {
		out, err := deploymentRun(t, dir, bin, bash, "reset-password.sh", "", "-m", "local", "--dsn", dsn, "-p", "synthetic-new-password", "-y")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "synthetic-secret") {
			t.Fatal("reset script logged DSN credential")
		}
	}
}
