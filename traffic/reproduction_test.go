package traffic

import (
	"net/url"
	"strings"
	"testing"
)

func insertReproExchange(t *testing.T, tr *Traffic, id string, ts int64, host, method, rawURL, reqB, respB string, status int) {
	t.Helper()
	if status == 0 {
		status = 200
	}
	tmpl := "/"
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		tmpl = normalizeReqPath(u.Path)
	}
	if _, err := tr.db.Exec(`INSERT OR REPLACE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`,
		id, ts, host, method, tmpl, rawURL, status, "text/html", len(reqB), len(respB)); err != nil {
		t.Fatal(err)
	}
	var rowid int64
	if err := tr.db.QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, id).Scan(&rowid); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.db.Exec(`INSERT OR REPLACE INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body)
VALUES(?,?,?,?,?)`, id, "", reqB, "", respB); err != nil {
		t.Fatal(err)
	}
	if tr.fts {
		idx := rawURL + "\n" + reqB + "\n" + respB
		if _, err := tr.db.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveStepExchange(t *testing.T) {
	tr, _ := openTraffic(t)
	insertReproExchange(t, tr, "1-0001", 100, "h", "POST", "https://h/api/users/authenticate",
		`{"username":"qqwwzz124","captchaAnswer":"95284","loginMethod":"E"}`, `{"body":"ANF"}`, 200)
	insertReproExchange(t, tr, "1-0002", 101, "h", "POST", "https://h/api/users/authenticate",
		`{"username":"taiman","captchaAnswer":"11111","loginMethod":"E"}`, `{"body":"N"}`, 200)
	step := "POST /api/users/authenticate?language=zh_HK HTTP/1.1\n" +
		"Host: h\nContent-Type: application/json\n\n" +
		`{"username":"qqwwzz124","captchaAnswer":"95284","loginMethod":"E"}`
	if id, ok := tr.ResolveStepExchange(step, ""); !ok || id != "1-0001" {
		t.Fatalf("resolve by body: want 1-0001/true, got %q/%v", id, ok)
	}
}

func TestResolveSteps(t *testing.T) {
	tr, _ := openTraffic(t)
	ins := func(id string, ts int64, method, rawURL, reqB, respB string) {
		insertReproExchange(t, tr, id, ts, "h", method, rawURL, reqB, respB, 200)
	}
	ins("g1", 110, "GET", "http://h/upload.php", "", "<form action=/upload.php version=1>")
	ins("g2", 120, "GET", "http://h/upload.php", "", "<form action=/upload.php version=2>")
	ins("p1", 140, "POST", "http://h/upload.php", `filename="avatar.png"`, "<div>头像上传成功</div>")
	ins("e1", 150, "GET", "http://h/uploads/avatar.png", "", "OK")
	steps := []StepRef{
		{Request: "GET /upload.php HTTP/1.1\nHost: h\n\n", Response: "<form action=/upload.php version=1>"},
		{Request: "POST /upload.php HTTP/1.1\nHost: h\n\nfilename=\"avatar.png\"", Response: "<div>头像上传成功</div>"},
		{Request: "GET /uploads/avatar.png HTTP/1.1\nHost: h\n\n", Response: "OK"},
	}
	ids := tr.ResolveSteps(100, 200, steps)
	want := []string{"g1", "p1", "e1"}
	for i, w := range want {
		if ids[i] != w {
			t.Errorf("step%d: want %s, got %q", i+1, w, ids[i])
		}
	}
}

func TestResolveStepsOutOfWindow(t *testing.T) {
	tr, _ := openTraffic(t)
	insertReproExchange(t, tr, "out", 90, "h", "GET", "http://h/nope", "", "", 200)
	insertReproExchange(t, tr, "in", 150, "h", "GET", "http://h/nope", "", "", 200)
	ids := tr.ResolveSteps(100, 200, []StepRef{{Request: "GET /nope HTTP/1.1\nHost: h\n\n", Response: ""}})
	if ids[0] != "in" {
		t.Fatalf("in-window: want in, got %q", ids[0])
	}
	ids = tr.ResolveSteps(100, 200, []StepRef{{Request: "GET /missing HTTP/1.1\nHost: h\n\n", Response: ""}})
	if ids[0] != "" {
		t.Errorf("no match: want empty, got %q", ids[0])
	}
}

func TestResolveStepHostMismatch(t *testing.T) {
	tr, _ := openTraffic(t)
	insertReproExchange(t, tr, "a", 100, "evil.example", "GET", "http://evil.example/api", "", "", 200)
	step := "GET /api HTTP/1.1\nHost: good.example\n\n"
	if id, ok := tr.ResolveStepExchange(step, ""); ok {
		t.Fatalf("want abstain on host mismatch, got %q", id)
	}
}

func TestResolveStepPathExact(t *testing.T) {
	tr, _ := openTraffic(t)
	insertReproExchange(t, tr, "long", 100, "h", "GET", "http://h/api/users/authenticate", "", "", 200)
	step := "GET /api HTTP/1.1\nHost: h\n\n"
	if id, ok := tr.ResolveStepExchange(step, ""); ok {
		t.Fatalf("short path must not match longer endpoint: got %q", id)
	}
}

func TestResolveStepStatusReject(t *testing.T) {
	tr, _ := openTraffic(t)
	insertReproExchange(t, tr, "fail", 100, "h", "GET", "http://h/vuln", "", "not found", 404)
	step := "GET /vuln HTTP/1.1\nHost: h\n\n"
	if id, ok := tr.ResolveStepExchange(step, "HTTP/1.1 200 OK\nok"); ok {
		t.Fatalf("contradicting status must not link: got %q", id)
	}
}

func TestResolveStepsDedupeSameSecond(t *testing.T) {
	tr, _ := openTraffic(t)
	ts := int64(120)
	insertReproExchange(t, tr, "a", ts, "h", "GET", "http://h/ping", "", "one", 200)
	insertReproExchange(t, tr, "b", ts, "h", "GET", "http://h/ping", "", "two", 200)
	steps := []StepRef{
		{Request: "GET /ping HTTP/1.1\nHost: h\n\n", Response: "one"},
		{Request: "GET /ping HTTP/1.1\nHost: h\n\n", Response: "two"},
	}
	ids := tr.ResolveSteps(100, 200, steps)
	if ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
		t.Fatalf("want two distinct exchanges at same ts, got %v", ids)
	}
}

func TestParseStepRequestCRLF(t *testing.T) {
	pkt := "POST /x HTTP/1.1\r\nHost: h\r\n\r\nuniquebody"
	_, _, _, _, body := parseStepRequest(pkt)
	if !strings.Contains(body, "uniquebody") {
		t.Fatalf("CRLF body not parsed, body token=%q", body)
	}
}

func TestParseCurlMethodCompact(t *testing.T) {
	cases := map[string]string{
		`curl -XPOST http://h/x`:              "POST",
		`curl -X POST http://h/x`:               "POST",
		`curl --request=DELETE http://h/x`:      "DELETE",
		`curl --request PUT http://h/x`:         "PUT",
	}
	for cmd, want := range cases {
		got, _, _, _, _ := parseStepRequest(cmd)
		if got != want {
			t.Fatalf("%q: want %s, got %s", cmd, want, got)
		}
	}
}

func TestResolveStepAmbiguousAbstains(t *testing.T) {
	tr, _ := openTraffic(t)
	insertReproExchange(t, tr, "x1", 100, "h", "GET", "http://h/ambig", "", "same", 200)
	insertReproExchange(t, tr, "x2", 101, "h", "GET", "http://h/ambig", "", "same", 200)
	step := "GET /ambig HTTP/1.1\nHost: h\n\n"
	if id, ok := tr.ResolveStepExchange(step, "same"); ok {
		t.Fatalf("ambiguous identical responses should abstain, got %q", id)
	}
}
