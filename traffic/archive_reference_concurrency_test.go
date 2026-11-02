package traffic

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestArchiveUnlistedReferenceVerificationConcurrency(t *testing.T) {
	for _, layout := range []string{"current", "legacy"} {
		for _, action := range []string{"record", "remove", "replace", "shadow_legacy", "current_row_wins"} {
			t.Run(layout+"/"+action, func(t *testing.T) {
				tr, root := openTraffic(t)
				body := []byte("unlisted local reference")
				hash := archiveReferenceHash(body)
				path := archiveReferenceLocalPath(root, hash, layout)
				writeArchiveReferenceFile(t, path, body)
				before, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				item := archiveReferenceExchange("unlisted-concurrent")
				item.RespBlob = hash
				arc := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{item}}, nil)
				good := archiveReferenceExchange(item.ID)
				good.RespBody = []byte("winner")
				seed := writeArchiveReferenceFixture(t, ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{good}}, nil)
				entered, release := make(chan struct{}), make(chan struct{})
				done := make(chan error, 1)
				go func() { _, err := tr.importArchive(arc, pausedArchiveVerifier(entered, release)); done <- err }()
				select {
				case <-entered:
				case err := <-done:
					close(release)
					t.Fatalf("import returned before reference verification: %v", err)
				case <-time.After(5 * time.Second):
					close(release)
					t.Fatal("reference verification was not entered")
				}
				concurrent := make(chan error, 1)
				go func() {
					if action == "record" {
						tr.record(newFlow("capture.invalid", "GET", "/", nil, []byte("live")))
						concurrent <- nil
						return
					}
					if action == "current_row_wins" {
						_, err := tr.ImportArchive(seed)
						concurrent <- err
						return
					}
					tr.wmu.Lock()
					defer tr.wmu.Unlock()
					if action == "shadow_legacy" {
						err := os.WriteFile(archiveReferenceLocalPath(root, hash, "current"), body, 0600)
						if err == nil && layout == "current" {
							err = os.Chtimes(path, before.ModTime().Add(time.Hour), before.ModTime().Add(time.Hour))
						}
						concurrent <- err
						return
					}
					var err error
					if action == "replace" {
						err = os.WriteFile(path+".replacement", body, 0600)
						if err == nil {
							err = os.Rename(path+".replacement", path)
						}
					} else {
						err = os.Remove(path)
					}
					concurrent <- err
				}()
				select {
				case err := <-concurrent:
					if err != nil {
						close(release)
						<-done
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					close(release)
					<-done
					t.Fatal("unlisted hash blocked writer")
				}
				close(release)
				err = <-done
				fail := action == "remove" || action == "replace" || action == "shadow_legacy"
				// Writing the same current path in place is an adversarial test too:
				// changed mtime must be rejected, even though supported writers do not do it.
				if fail && err == nil {
					t.Fatal("changed reference accepted")
				}
				if !fail && err != nil {
					t.Fatal(err)
				}
				if action == "record" {
					var n int
					if e := tr.DB().QueryRow("SELECT count(*) FROM exchanges WHERE host='capture.invalid'").Scan(&n); e != nil || n != 1 {
						t.Fatalf("capture missing: n=%d err=%v", n, e)
					}
				}
				if action == "current_row_wins" {
					_, response, e := tr.Get(item.ID)
					if e != nil || !strings.Contains(response, "winner") {
						t.Fatalf("current row lost: %q err=%v", response, e)
					}
				}
				if fail {
					var n int
					if e := tr.DB().QueryRow("SELECT count(*) FROM exchanges WHERE id=?", item.ID).Scan(&n); e != nil || n != 0 {
						t.Fatalf("partial commit n=%d err=%v", n, e)
					}
				}
			})
		}
	}
}
