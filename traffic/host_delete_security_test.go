package traffic

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func protectedTrafficPaths(t *testing.T, root string) map[string]os.FileInfo {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "_delete_staging"), 0o700); err != nil {
		t.Fatal(err)
	}
	paths := map[string]os.FileInfo{}
	for _, name := range []string{"_index", "_blobs", "_ca", "_auth", "_delete_staging"} {
		path := filepath.Join(root, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		paths[path] = info
	}
	return paths
}

func assertTrafficPathsPreserved(t *testing.T, paths map[string]os.FileInfo) {
	t.Helper()
	for path, before := range paths {
		after, err := os.Stat(path)
		if err != nil || !os.SameFile(before, after) {
			t.Errorf("store path was moved/replaced: %s: %v", path, err)
		}
	}
}

func TestHostDeletionPreservesStoreOwnedPaths(t *testing.T) {
	for _, mode := range []string{"exact", "substring", "archive"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ARTEX_PROXY_AUTH", "")
			tr, root := openTraffic(t)
			paths := protectedTrafficPaths(t, root)
			auth, err := os.ReadFile(filepath.Join(root, "_auth"))
			if err != nil {
				t.Fatal(err)
			}
			hosts := []string{"_index", "_blobs", "_ca", "_auth", "_delete_staging", ".", "..", "/index"}
			for i, host := range hosts {
				if _, err := tr.DB().Exec("INSERT INTO exchanges(id,host,path) VALUES(?,?,?)", fmt.Sprint(i), host, ""); err != nil {
					t.Fatal(err)
				}
			}
			var deleted int64
			switch mode {
			case "exact":
				deleted, err = tr.DeleteHostsExact(hosts)
			case "substring":
				deleted, err = tr.DeleteHost("%")
			case "archive":
				var staged *HostDeleteStage
				staged, err = tr.StageDeleteHostsExactForArchive(hosts, 1, 2)
				if err == nil {
					deleted, err = staged.Deleted(), staged.Commit()
				}
			}
			if err != nil || deleted != int64(len(hosts)) {
				t.Fatalf("delete = %d, %v", deleted, err)
			}
			tr.reaping.Wait()
			assertTrafficPathsPreserved(t, paths)
			if got, err := os.ReadFile(filepath.Join(root, "_auth")); err != nil || string(got) != string(auth) {
				t.Fatalf("proxy credentials changed: %v", err)
			}
			if n, err := tr.Count(); err != nil || n != 0 {
				t.Fatalf("unsafe host rows were not removed: %d, %v", n, err)
			}
			// Missing rows must not make a second exact delete unsafe.
			if _, err := tr.DeleteHostsExact(hosts); err != nil {
				t.Fatal(err)
			}
			tr.reaping.Wait()
			assertTrafficPathsPreserved(t, paths)
		})
	}
}

func TestHostDeletionMixedRollbackPreservesStore(t *testing.T) {
	t.Setenv("ARTEX_PROXY_AUTH", "")
	tr, root := openTraffic(t)
	paths := protectedTrafficPaths(t, root)
	host := "normal.example"
	tree := filepath.Join(root, host)
	if err := os.Mkdir(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(tree, "evidence")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{host, "_auth"} {
		if _, err := tr.DB().Exec("INSERT INTO exchanges(id,host,path) VALUES(?,?,?)", h, h, ""); err != nil {
			t.Fatal(err)
		}
	}
	staged, err := tr.StageDeleteHostsExact([]string{host, "_auth"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tree); !os.IsNotExist(err) {
		t.Fatalf("normal host was not staged: %v", err)
	}
	assertTrafficPathsPreserved(t, paths)
	if err := staged.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "keep" {
		t.Fatalf("normal evidence not restored: %q, %v", got, err)
	}
	if n, err := tr.Count(); err != nil || n != 2 {
		t.Fatalf("rows not restored: %d, %v", n, err)
	}
	assertTrafficPathsPreserved(t, paths)
}

func TestHostStagingRejectsRootOutsideAndReservedPaths(t *testing.T) {
	t.Setenv("ARTEX_PROXY_AUTH", "")
	tr, root := openTraffic(t)
	paths := protectedTrafficPaths(t, root)
	outside := t.TempDir()
	outsideInfo, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	paths[outside] = outsideInfo
	paths[root], _ = os.Stat(root)
	stageDir, moves, err := tr.stageTrees([]string{root, root + "/.", filepath.Dir(root), outside, filepath.Join(root, "_index"), filepath.Join(root, "_auth")})
	if err != nil || stageDir != "" || len(moves) != 0 {
		t.Fatalf("unsafe staging = %q, %v, %v", stageDir, moves, err)
	}
	assertTrafficPathsPreserved(t, paths)
}
