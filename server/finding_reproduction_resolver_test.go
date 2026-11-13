package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/traffic"
)

func TestResolveFindingTrafficNoTaskStoreAbstains(t *testing.T) {
	s := &Server{}
	raw := json.RawMessage(`{"steps":[{"request":"GET /x HTTP/1.1\nHost: h\n\n","response":""}]}`)
	out := s.resolveFindingTraffic(0, raw)
	if string(out) != string(raw) {
		t.Fatalf("expected unchanged repro without task")
	}
}

func TestLinkReproductionStepsPartial(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	_, err = tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path,req_path)
VALUES ('b1',120,'h','GET','/b','http://h/b',200,'text/plain',0,0,'','/b')`)
	if err != nil {
		t.Fatal(err)
	}
	rp := report.Reproduction{Steps: []report.ReproStep{
		{Request: "GET /a HTTP/1.1\nHost: h\n\n", ExchangeID: "keep"},
		{Request: "GET /b HTTP/1.1\nHost: h\n\n", Response: "HTTP/1.1 200 OK"},
	}}
	linkReproductionSteps(tr, 100, 200, &rp)
	if rp.Steps[0].ExchangeID != "keep" {
		t.Fatalf("step0 preserved: got %q", rp.Steps[0].ExchangeID)
	}
	if rp.Steps[1].ExchangeID != "b1" {
		t.Fatalf("step1 linked: want b1, got %q", rp.Steps[1].ExchangeID)
	}
	_ = time.Now()
}
