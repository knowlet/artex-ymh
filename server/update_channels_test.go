package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

const updateTestSHA = "0123456789abcdef0123456789abcdef01234567"

func TestReleaseCacheStableFetchDoesNotBlockOtherChannels(t *testing.T) {
	stableStarted := make(chan struct{})
	stableRelease := make(chan struct{})
	cache := &releaseCache{
		fetch: func(context.Context, *http.Client) (*selfupdate.Release, error) {
			close(stableStarted)
			<-stableRelease
			return &selfupdate.Release{TagName: "v1.0.0"}, nil
		},
		fetchChannel: func(_ context.Context, _ *http.Client, channel selfupdate.Channel) (*selfupdate.Release, error) {
			return &selfupdate.Release{TagName: string(channel)}, nil
		},
	}
	if _, err := cache.getChannel(t.Context(), nil, false, selfupdate.ChannelNightly); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = cache.getChannel(t.Context(), nil, false, selfupdate.ChannelStable)
	}()
	select {
	case <-stableStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("stable fetch did not start")
	}
	start := time.Now()
	if _, err := cache.getChannel(t.Context(), nil, false, selfupdate.ChannelNightly); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited > 200*time.Millisecond {
		t.Fatalf("nightly blocked on stable fetch for %v", waited)
	}
	close(stableRelease)
}

func TestReleaseCacheIsolatesChannels(t *testing.T) {
	var mu sync.Mutex
	calls := map[selfupdate.Channel]int{}
	cache := &releaseCache{
		fetch: func(context.Context, *http.Client) (*selfupdate.Release, error) {
			mu.Lock()
			defer mu.Unlock()
			calls[selfupdate.ChannelStable]++
			return &selfupdate.Release{TagName: "v1.0.0"}, nil
		},
		fetchChannel: func(_ context.Context, _ *http.Client, channel selfupdate.Channel) (*selfupdate.Release, error) {
			mu.Lock()
			defer mu.Unlock()
			calls[channel]++
			return &selfupdate.Release{TagName: string(channel)}, nil
		},
	}
	var wg sync.WaitGroup
	for _, channel := range []selfupdate.Channel{selfupdate.ChannelStable, selfupdate.ChannelNightly, selfupdate.ChannelMain} {
		for range 5 {
			wg.Go(func() {
				rel, err := cache.getChannel(t.Context(), nil, false, channel)
				want := string(channel)
				if channel == selfupdate.ChannelStable {
					want = "v1.0.0"
				}
				if err != nil || rel == nil || rel.TagName != want {
					t.Errorf("channel=%s rel=%+v err=%v", channel, rel, err)
				}
			})
		}
	}
	wg.Wait()
	for channel, count := range calls {
		if count != 1 {
			t.Fatalf("%s fetched %d times", channel, count)
		}
	}
	if len(calls) != 3 {
		t.Fatalf("missing channels: %+v", calls)
	}
	if _, err := cache.getChannel(t.Context(), nil, true, selfupdate.ChannelMain); err != nil {
		t.Fatal(err)
	}
	if calls[selfupdate.ChannelMain] != 2 || calls[selfupdate.ChannelStable] != 1 || calls[selfupdate.ChannelNightly] != 1 {
		t.Fatalf("force crossed channel boundary: %+v", calls)
	}
}

func TestReleaseCacheNoReleaseUsesNormalTTL(t *testing.T) {
	calls := 0
	cache := newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		calls++
		if calls == 1 {
			return nil, &selfupdate.CheckError{Code: "no_release", Err: errors.New("no release")}
		}
		return &selfupdate.Release{TagName: "v1.0.0"}, nil
	})
	if _, err := cache.get(t.Context(), nil, false); selfupdate.CheckErrorCode(err) != "no_release" {
		t.Fatal(err)
	}
	cache.at = time.Now().Add(-releaseErrTTL - time.Second)
	if _, err := cache.get(t.Context(), nil, false); selfupdate.CheckErrorCode(err) != "no_release" || calls != 1 {
		t.Fatalf("empty result incorrectly used error TTL: calls=%d err=%v", calls, err)
	}
	if rel, err := cache.get(t.Context(), nil, true); err != nil || rel == nil || calls != 2 {
		t.Fatalf("manual refresh: %+v %v", rel, err)
	}
}

func TestUpdateCheckSourceChannelsAndBuildIdentity(t *testing.T) {
	originalCache, originalRead := relCache, readUpdateBuildInfo
	t.Cleanup(func() { relCache, readUpdateBuildInfo = originalCache, originalRead })
	relCache = &releaseCache{fetchChannel: func(_ context.Context, _ *http.Client, channel selfupdate.Channel) (*selfupdate.Release, error) {
		return &selfupdate.Release{TagName: string(channel) + "@0123456789ab", CommitSHA: updateTestSHA}, nil
	}}
	for _, channel := range []string{"main", "nightly"} {
		for _, state := range []string{"same", "different", "missing", "dirty"} {
			t.Run(channel+"/"+state, func(t *testing.T) {
				revision := updateTestSHA
				if state == "different" {
					revision = strings.Repeat("a", 40)
				}
				if state == "missing" {
					revision = ""
				}
				readUpdateBuildInfo = func() (*debug.BuildInfo, bool) {
					settings := []debug.BuildSetting{{Key: "vcs.revision", Value: revision}, {Key: "vcs.modified", Value: "false"}}
					if state == "dirty" {
						settings[1].Value = "true"
					}
					return &debug.BuildInfo{Settings: settings}, true
				}
				w := httptest.NewRecorder()
				(&Server{m: &Manager{}}).updateCheck(w, httptest.NewRequest(http.MethodGet, "/api/update/check?channel="+channel, nil))
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || body["channel"] != channel || body["source_only"] != true || body["install_enabled"] != false || body["error"] != nil {
					t.Fatalf("unsafe channel response: %d %+v", w.Code, body)
				}
				if body["target_commit"] != updateTestSHA || body["source_url"] != "https://github.com/knowlet/artex-ymh/archive/"+updateTestSHA+".zip" || body["asset"] != nil {
					t.Fatalf("source not pinned: %+v", body)
				}
				if body["comparable"] != (state == "same" || state == "different") || body["has_update"] != (state == "different") {
					t.Fatalf("incorrect build comparison: %+v", body)
				}
			})
		}
	}
}

func TestUpdateCheckNoReleaseIsInformational(t *testing.T) {
	original := relCache
	t.Cleanup(func() { relCache = original })
	relCache = newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		return nil, &selfupdate.CheckError{Code: "no_release", Err: errors.New("choose main")}
	})
	w := httptest.NewRecorder()
	(&Server{m: &Manager{}}).updateCheck(w, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != nil || body["message"] != "choose main" || body["release_status"] != "no_release" || body["has_update"] != false || body["comparable"] != false || body["channel"] != "stable" {
		t.Fatalf("no-release is not a failure or latest: %+v", body)
	}
}

func TestUpdateCheckInvalidChannelBeforeManager(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).updateCheck(w, httptest.NewRequest(http.MethodGet, "/api/update/check?channel=arbitrary", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
