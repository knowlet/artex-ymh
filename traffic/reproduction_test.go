package traffic

import (
	"fmt"
	"testing"
)

func insertReproExchange(t *testing.T, tr *Traffic, id string, ts int64, method, url, reqB, respB string) {
	t.Helper()
	status := 200
	if _, err := tr.db.Exec(`INSERT OR REPLACE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`,
		id, ts, "h", method, "/t", url, status, "text/html", len(reqB), len(respB)); err != nil {
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
		idx := url + "\n" + reqB + "\n" + respB
		if _, err := tr.db.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveStepExchange(t *testing.T) {
	tr, _ := openTraffic(t)
	insertReproExchange(t, tr, "1-0001", 100, "POST", "https://h/api/users/authenticate",
		`{"username":"qqwwzz124","captchaAnswer":"95284","loginMethod":"E"}`, `{"body":"ANF"}`)
	insertReproExchange(t, tr, "1-0002", 101, "POST", "https://h/api/users/authenticate",
		`{"username":"taiman","captchaAnswer":"11111","loginMethod":"E"}`, `{"body":"N"}`)
	step := "POST /api/users/authenticate?language=zh_HK HTTP/1.1\n" +
		"Host: h\nContent-Type: application/json\n\n" +
		`{"username":"qqwwzz124","captchaAnswer":"95284","loginMethod":"E"}`
	if id, ok := tr.ResolveStepExchange(step, ""); !ok || id != "1-0001" {
		t.Fatalf("resolve by body: want 1-0001/true, got %q/%v", id, ok)
	}
}

func TestResolveSteps(t *testing.T) {
	tr, _ := openTraffic(t)
	ins := func(id string, ts int64, method, url, reqB, respB string) {
		insertReproExchange(t, tr, id, ts, method, url, reqB, respB)
	}
	ins("g1", 110, "GET", "http://h/upload.php", "", "<form action=/upload.php enctype=multipart/form-data>")
	ins("g2", 120, "GET", "http://h/upload.php", "", "<form action=/upload.php enctype=multipart/form-data>")
	ins("p1", 140, "POST", "http://h/upload.php", `filename="avatar.png"`, "<div>头像上传成功</div>")
	ins("e1", 150, "GET", "http://h/uploads/avatar.png", "", "OK")
	steps := []StepRef{
		{Request: "GET /upload.php HTTP/1.1\nHost: h\n\n", Response: "<form action=/upload.php enctype=multipart/form-data>"},
		{Request: "POST /upload.php HTTP/1.1\n\nfilename=\"avatar.png\"", Response: "<div>头像上传成功</div>"},
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
	ids := tr.ResolveSteps(100, 200, []StepRef{{Request: "GET /nope HTTP/1.1\n\n", Response: ""}})
	if ids[0] != "" {
		t.Errorf("out of window: want empty, got %q", ids[0])
	}
	_ = fmt.Sprintf("%v", ids)
}
