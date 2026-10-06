package db

import (
	"regexp"
	"testing"
)

// 纯单测(不需要 PG):守护化底线规则(V9)的正则必须命中常见变体、不误伤正常命令。
// 说明:诊断类命令(如 `ps aux | grep setsid`)按设计会命中——action 是 ask 而非
// deny,人工一键放行,误报成本远低于漏放一个真守护化(港 VPS 孤儿监听器事故)。
func TestBuiltinDaemonizeRulePatterns(t *testing.T) {
	hits := []string{
		"setsid python3 -m http.server 8000",
		"setsid bash -c 'nc -lvp 4444'",
		"nohup python3 -m http.server 8080 &",
		"cd /tmp && nohup ./agent &",
		"sudo setsid ./listener",
		"sleep 1000 & disown",
		"disown -a",
		"./svc &\ndisown",
		"bash -c 'setsid ./x'", // 引号内空格分隔照样命中
		"setsid",               // 裸命令(行首+结尾)
	}
	misses := []string{
		"curl http://10.0.0.2:8787/s/abc/tool.sh -o /tmp/tool.sh", // stage_share 正常拉取
		"python3 exploit.py",  // 普通脚本
		"cat nohup.out",       // 词后跟点号,不是命令调用
		"echo hello",
		"nmap -p 80 10.0.0.2",
		"cat /proc/1234/cmdline",
		"ls /var/log",
	}
	var rules []*regexp.Regexp
	for _, r := range builtinDaemonizeRules {
		re, err := regexp.Compile(r.pattern)
		if err != nil {
			t.Fatalf("规则 %q 正则编译失败: %v", r.name, err)
		}
		rules = append(rules, re)
	}
	matchAny := func(s string) bool {
		for _, re := range rules {
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}
	for _, c := range hits {
		if !matchAny(c) {
			t.Errorf("应命中但未命中: %s", c)
		}
	}
	for _, c := range misses {
		if matchAny(c) {
			t.Errorf("误伤正常命令: %s", c)
		}
	}
}
