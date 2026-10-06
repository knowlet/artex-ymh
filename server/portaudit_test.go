package server

import (
	"reflect"
	"testing"
)

// /proc/net/tcp fixture:header + 已知端口(8787 loopback)+ 台账外 0.0.0.0:9999
// + 非 loopback 10.0.0.5:8080 + 非 LISTEN 行。
const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2217 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:270F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0500000A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0
   3: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12348 1 0000000000000000 100 0 0 10 0
   4: 0100007F:2217 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 12349 1 0000000000000000 100 0 0 10 0
`

// /proc/net/tcp6 fixture:::1:8787(loopback,跳过)+ :::8081(全接口,台账外)。
const procNetTCP6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:2217 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22345 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22346 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCP(t *testing.T) {
	socks := parseProcNetTCP(procNetTCPFixture)
	if len(socks) != 4 { // 只有 0A(LISTEN)行,established(01)被跳过
		t.Fatalf("listeners = %d, want 4: %+v", len(socks), socks)
	}
	// 0100007F:2217 → 127.0.0.1:8727? 0x2217 = 8727... 用断言锚定真实换算。
	if got := socks[0]; got.IP.String() != "127.0.0.1" || got.Port != 0x2217 {
		t.Fatalf("sock[0] = %s:%d", got.IP, got.Port)
	}
	if got := socks[1]; !got.IP.IsUnspecified() || got.Port != 9999 {
		t.Fatalf("sock[1] = %s:%d, want 0.0.0.0:9999", got.IP, got.Port)
	}
	if got := socks[2]; got.IP.String() != "10.0.0.5" || got.Port != 8080 {
		t.Fatalf("sock[2] = %s:%d, want 10.0.0.5:8080", got.IP, got.Port)
	}
}

func TestParseProcNetTCP6(t *testing.T) {
	socks := parseProcNetTCP(procNetTCP6Fixture)
	if len(socks) != 2 {
		t.Fatalf("listeners = %d, want 2: %+v", len(socks), socks)
	}
	if got := socks[0]; !got.IP.IsLoopback() {
		t.Fatalf("sock[0] = %s, want ::1", got.IP)
	}
	if got := socks[1]; !got.IP.IsUnspecified() || got.Port != 8081 {
		t.Fatalf("sock[1] = %s:%d, want :::8081", got.IP, got.Port)
	}
}

func TestKnownManagedPortsCoversPlatform(t *testing.T) {
	known := knownManagedPorts()
	for _, p := range []int{8787, 8788, 22} {
		if !known[p] {
			t.Fatalf("port %d should be on the platform ledger", p)
		}
	}
	if known[9999] {
		t.Fatal("9999 should NOT be on the ledger")
	}
}

// portAuditClassify 两级处置:首次 WARN、连续两轮仍在升级一次、消失即清零重计。
func TestPortAuditClassify(t *testing.T) {
	seen := map[string]int{}
	esc := map[string]bool{}

	// 轮 1:首次发现 → WARN,不升级。
	warned, escalated := portAuditClassify(seen, esc, []string{"0.0.0.0:8000"})
	if !reflect.DeepEqual(warned, []string{"0.0.0.0:8000"}) || len(escalated) != 0 {
		t.Fatalf("轮1: warned=%v escalated=%v", warned, escalated)
	}

	// 轮 2:仍在 → 升级(且不再 WARN)。
	warned, escalated = portAuditClassify(seen, esc, []string{"0.0.0.0:8000"})
	if len(warned) != 0 || !reflect.DeepEqual(escalated, []string{"0.0.0.0:8000"}) {
		t.Fatalf("轮2: warned=%v escalated=%v", warned, escalated)
	}

	// 轮 3:仍在 → 不重复升级(hint 不刷屏)。
	warned, escalated = portAuditClassify(seen, esc, []string{"0.0.0.0:8000"})
	if len(warned) != 0 || len(escalated) != 0 {
		t.Fatalf("轮3: warned=%v escalated=%v", warned, escalated)
	}

	// 轮 4:消失 → 清零;轮 5 复活 → 重新走两级(先 WARN)。
	if warned, escalated = portAuditClassify(seen, esc, nil); len(warned) != 0 || len(escalated) != 0 {
		t.Fatalf("轮4: warned=%v escalated=%v", warned, escalated)
	}
	warned, escalated = portAuditClassify(seen, esc, []string{"0.0.0.0:8000"})
	if !reflect.DeepEqual(warned, []string{"0.0.0.0:8000"}) || len(escalated) != 0 {
		t.Fatalf("轮5(复活): warned=%v escalated=%v", warned, escalated)
	}

	// 多个监听者各自独立计轮。
	warned, escalated = portAuditClassify(seen, esc, []string{"0.0.0.0:8000", "10.0.0.2:9999"})
	if len(warned) != 1 || warned[0] != "10.0.0.2:9999" { // 8000 是第二轮,9999 是首轮
		t.Fatalf("多监听者: warned=%v", warned)
	}
	if !reflect.DeepEqual(escalated, []string{"0.0.0.0:8000"}) {
		t.Fatalf("多监听者: escalated=%v", escalated)
	}
}

// isOrphanPenelopeCmdline 双特征防误杀:本平台脚本路径 + --mcp 缺一不可。
func TestIsOrphanPenelopeCmdline(t *testing.T) {
	const bin = "/opt/artex/data/tools/penelope.py"
	hits := []string{
		"python3 /opt/artex/data/tools/penelope.py --mcp --mcp-host 127.0.0.1 --mcp-port 21001 --mcp-token ab -p 4444 -i 127.0.0.1 -C ",
		"/usr/bin/python3 /opt/artex/data/tools/penelope.py --mcp -p 20001 -i 0.0.0.0 -C ",
	}
	misses := []string{
		"", // 空
		"python3 /opt/artex/data/tools/penelope.py -p 4444",        // 无 --mcp(用户手工交互式)
		"python3 /other/deploy/tools/penelope.py --mcp -p 4444 -C", // 别的部署(别的 dataDir)
		"python3 /opt/artex/data/tools/other.py --mcp",             // 同目录别的脚本
		"grep penelope",                                            // 诊断命令
	}
	for _, cl := range hits {
		if !isOrphanPenelopeCmdline(cl, bin) {
			t.Errorf("应判孤儿但未判: %q", cl)
		}
	}
	for _, cl := range misses {
		if isOrphanPenelopeCmdline(cl, bin) {
			t.Errorf("误杀风险(判成孤儿): %q", cl)
		}
	}
	// binPath 为空时一律不判(无特征可核对,宁可漏)。
	if isOrphanPenelopeCmdline(hits[0], "") {
		t.Error("binPath 为空时不应判定")
	}
}
